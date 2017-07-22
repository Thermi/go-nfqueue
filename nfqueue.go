package nfqueue

/*
#cgo LDFLAGS: -lnetfilter_queue
#cgo CFLAGS: -Wall
#include "nfqueue.h"
*/
import "C"

import (
	"net"
	"fmt"
//	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

/* The code doesn't handle a wrap around of globalQueueCount!
 * If It wraps around, bad things WILL when the destructor is called!
 */

type channelAndPool struct {
	Channel chan *Packet
	Pool 	*sync.Pool
}
var globalMap struct {
	Lock	*sync.RWMutex
	Map		map[uint64] channelAndPool
	globalQueueCount	uint64
}

type nfqueue struct {
	internalQueueNumber 	uint64
	lk 					sync.Mutex
	DefaultVerdict 		Verdict
	Timeout        		time.Duration
	qid            		uint16
	fd 					int
	h              		*C.struct_nfq_handle
	qh 					*C.struct_nfq_q_handle
}

func NewNFQueue(qid uint16) *nfqueue {
	// Check capabilities, not UID (TODO)
	nfq := nfqueue {
		DefaultVerdict : ACCEPT,
		Timeout : time.Microsecond * 5,
		qid : qid,
	}
	

	if globalMap.Lock == nil {
		// First one alive. Let's make sure we have at least two real threads (Because the application
		// will hard lock, if there's only one)
		if runtime.GOMAXPROCS(-1) < 2 {
			if runtime.NumCPU() < 2 {
				runtime.GOMAXPROCS(2)
			} else {
				runtime.GOMAXPROCS(runtime.NumCPU())
			}
		}
		globalMap.Lock = new(sync.RWMutex)
		globalMap.Map = make(map[uint64] channelAndPool, 1)
	}
	fmt.Println("Current GOMAXPROCS: ", runtime.GOMAXPROCS(-1))
	nfq.init()
	
	// nfq = &nfqueue{NfQueue_int : &NfQueue_int}
	return &nfq
}


/*
This returns a channel that will recieve packets,
the user then must call pkt.Accept() or pkt.Drop()
*/
func (this *nfqueue) Process() <-chan *Packet {
	go func() {
		runtime.LockOSThread()
		C.loop_for_packets(this.h)
	}()
	defer globalMap.Lock.RUnlock()
	globalMap.Lock.RLock()
	pktch := globalMap.Map[this.internalQueueNumber].Channel
	fmt.Println("Sending channel: ", pktch)
	return pktch
}

func (this *nfqueue) init() {
	var chap channelAndPool
	var pool = new(sync.Pool)
	var err error

	this.h, err = C.nfq_open()

	if err != nil || this.h == nil {
		panic(err)
	}

	chap.Channel = make(chan *Packet, 1)
	fmt.Println("Channel in chap: ", chap.Channel)
	chap.Pool = pool
	fmt.Println("Write Locking in init ")
	globalMap.Lock.Lock()
	globalMap.globalQueueCount++
	this.internalQueueNumber = globalMap.globalQueueCount
	fmt.Println("internalQueueNumber: ", this.internalQueueNumber)
	fmt.Println("Original map: ", globalMap.Map)
	fmt.Println("Inserting into map")
	fmt.Println("globalQueueCount", globalMap.globalQueueCount)
	fmt.Println("chap: ", chap)
	fmt.Println("Map: ", globalMap.Map)
	globalMap.Map[globalMap.globalQueueCount] = chap
	fmt.Println("Stored chap: ", globalMap.Map[globalMap.globalQueueCount])
	fmt.Println("Ẃrite Unlocking in init")
	globalMap.Lock.Unlock()

	if C.nfq_unbind_pf(this.h, C.AF_INET) < 0 {
		this.Destroy()
		panic("nfq_unbind_pf(AF_INET) failed, are you running root?.")
	}
	if C.nfq_unbind_pf(this.h, C.AF_INET6) < 0 {
		this.Destroy()
		panic("nfq_unbind_pf(AF_INET6) failed.")
	}

	if C.nfq_bind_pf(this.h, C.AF_INET) < 0 {
		this.Destroy()
		panic("nfq_bind_pf(AF_INET) failed.")
	}

	if C.nfq_bind_pf(this.h, C.AF_INET6) < 0 {
		this.Destroy()
		panic("nfq_bind_pf(AF_INET6) failed.")
	}

	this.qh = C.create_queue(this.h, C.uint16_t(this.qid), unsafe.Pointer(this))
	if this.qh == nil {
		C.nfq_close(this.h)
		panic(err)
	}
	
	this.fd = int(C.nfq_fd(this.h))

	if C.nfq_set_mode(this.qh, C.NFQNL_COPY_PACKET, 0xffff) < 0 {
		this.Destroy()
		panic("nfq_set_mode(NFQNL_COPY_PACKET) failed.")
	}
	if C.nfq_set_queue_maxlen(this.qh, 1024*8) < 0 {
		this.Destroy()
		panic("nfq_set_queue_maxlen(1024 * 8) failed.")
	}
}

func (this *nfqueue) Destroy() {
	this.lk.Lock()
	defer this.lk.Unlock()

	if this.fd != 0 && this.Valid() {
		syscall.Close(this.fd)
	}
	if this.qh != nil {
		C.nfq_destroy_queue(this.qh)
		this.qh = nil
	}
	if this.h != nil {
		C.nfq_close(this.h)
		this.h = nil
	}
	fmt.Println("Write Locking in Destroy")
	globalMap.Lock.Lock()
	delete(globalMap.Map, this.internalQueueNumber)
	fmt.Println("Write Unlocking in Destroy")
	globalMap.Lock.Unlock()

}

func (this *nfqueue) Valid() bool {
	return this.h != nil && this.qh != nil
}

//export go_nfq_callback
func go_nfq_callback(id uint32, hwproto uint16, hook uint8, mark *uint32,
	version, protocol, tos, ttl uint8, saddr, daddr unsafe.Pointer,
	sport, dport, checksum uint16, payload_len uint32, payload, nfqptr unsafe.Pointer) (v uint32) {

	var (
		nfq   = (*nfqueue)(nfqptr)
		ipver = IPVersion(version)
		ipsz  = C.int(ipver.Size())
	)
	fmt.Println("nfq: ", nfq)
	bs := C.GoBytes(payload, (C.int)(payload_len))

	verdict := make(chan uint32, 1)
	pkt := Packet{
		QueueId:    nfq.qid,
		Id:         id,
		HWProtocol: hwproto,
		Hook:       hook,
		Mark:       *mark,
		Payload:    bs,
		IPHeader: &IPHeader{
			Version:  ipver,
			Protocol: IPProtocol(protocol),
			Tos:      tos,
			TTL:      ttl,
			Src:      net.IP(C.GoBytes(saddr, ipsz)),
			Dst:      net.IP(C.GoBytes(daddr, ipsz)),
		},
// Fix this. There are more protocols than UDP and TCP on top of IP{v4,v6}.
		TCPUDPHeader: &TCPUDPHeader{
			SrcPort:  sport,
			DstPort:  dport,
			Checksum: checksum,
		},

		verdict: verdict,
	}
	fmt.Println("Read Locking")
	globalMap.Lock.RLock()
	channel := globalMap.Map[nfq.internalQueueNumber].Channel 
	fmt.Println("Writing packet")
	fmt.Println ("Sending to channel: ", channel)
	channel <- &pkt

	fmt.Println("Read Unlocking")
	globalMap.Lock.RUnlock()

	// This totally shouldn't be here! Needs to be cleaned up, soon!

	select {
	case v = <-pkt.verdict:
		*mark = pkt.Mark
	case <-time.After(nfq.Timeout):
		v = uint32(nfq.DefaultVerdict)
	}

	return v
}
