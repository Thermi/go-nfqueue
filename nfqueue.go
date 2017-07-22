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
type NfQueue_ext struct {
	NfQueue_int 	*NfQueue_int
	pktch 			chan *Packet
	lk 				sync.Mutex
}

type NfQueue_int struct {
	DefaultVerdict 	Verdict
	Timeout        	time.Duration
	qid            	uint16
	fd 				int
	h              	*C.struct_nfq_handle
	qh 				*C.struct_nfq_q_handle
}

func NewNFQueue(qid uint16) (nfq *NfQueue_ext) {
	// Check capabilities, not UID (TODO)
	var NfQueue_int = NfQueue_int {
		DefaultVerdict : ACCEPT,
		Timeout : time.Microsecond * 5,
		qid : qid,
	}
	newQueue := new(NfQueue_ext)
	
	newQueue.NfQueue_int = &NfQueue_int
	// nfq = &NfQueue_ext{NfQueue_int : &NfQueue_int}
	return newQueue
}

/*
This returns a channel that will recieve packets,
the user then must call pkt.Accept() or pkt.Drop()
*/
func (this *NfQueue_ext) Process() <-chan *Packet {
	// nfQueue_handle := this.NfQueue_int.h
	// if nfQueue_handle != nil {
	// 	return this.pktch
	// }
	this.init()

	go func() {
		runtime.LockOSThread()
		C.loop_for_packets(this.NfQueue_int.h)
	}()
	return this.pktch
}

func (this *NfQueue_ext) init() {
	var err error

	if this.NfQueue_int.h, err = C.nfq_open(); err != nil || this.NfQueue_int.h == nil {
		panic(err)
	}
	//if this.qh, err = C.nfq_create_queue(this.h, qid, C.get_cb(), unsafe.Pointer(nfq)); err != nil || this.qh == nil {

	this.pktch = make(chan *Packet, 1)

	if C.nfq_unbind_pf(this.NfQueue_int.h, C.AF_INET) < 0 {
		this.Destroy()
		panic("nfq_unbind_pf(AF_INET) failed, are you running root?.")
	}
	if C.nfq_unbind_pf(this.NfQueue_int.h, C.AF_INET6) < 0 {
		this.Destroy()
		panic("nfq_unbind_pf(AF_INET6) failed.")
	}

	if C.nfq_bind_pf(this.NfQueue_int.h, C.AF_INET) < 0 {
		this.Destroy()
		panic("nfq_bind_pf(AF_INET) failed.")
	}

	if C.nfq_bind_pf(this.NfQueue_int.h, C.AF_INET6) < 0 {
		this.Destroy()
		panic("nfq_bind_pf(AF_INET6) failed.")
	}

	this.NfQueue_int.qh = C.create_queue(this.NfQueue_int.h, C.uint16_t(this.NfQueue_int.qid), unsafe.Pointer(this.NfQueue_int))
	if this.NfQueue_int.qh == nil {
		C.nfq_close(this.NfQueue_int.h)
		panic(err)
	}
	
	this.NfQueue_int.fd = int(C.nfq_fd(this.NfQueue_int.h))

	if C.nfq_set_mode(this.NfQueue_int.qh, C.NFQNL_COPY_PACKET, 0xffff) < 0 {
		this.Destroy()
		panic("nfq_set_mode(NFQNL_COPY_PACKET) failed.")
	}
	if C.nfq_set_queue_maxlen(this.NfQueue_int.qh, 1024*8) < 0 {
		this.Destroy()
		panic("nfq_set_queue_maxlen(1024 * 8) failed.")
	}
}

func (this *NfQueue_ext) Destroy() {
	this.lk.Lock()
	defer this.lk.Unlock()

	if this.NfQueue_int.fd != 0 && this.Valid() {
		syscall.Close(this.NfQueue_int.fd)
	}
	if this.NfQueue_int.qh != nil {
		C.nfq_destroy_queue(this.NfQueue_int.qh)
		this.NfQueue_int.qh = nil
	}
	if this.NfQueue_int.h != nil {
		C.nfq_close(this.NfQueue_int.h)
		this.NfQueue_int.h = nil
	}

	if this.pktch != nil {
		close(this.pktch)
	}
}

func (this *NfQueue_ext) Valid() bool {
	return this.NfQueue_int.h != nil && this.NfQueue_int.qh != nil
}

//export go_nfq_callback
func go_nfq_callback(id uint32, hwproto uint16, hook uint8, mark *uint32,
	version, protocol, tos, ttl uint8, saddr, daddr unsafe.Pointer,
	sport, dport, checksum uint16, payload_len uint32, payload, nfqptr unsafe.Pointer) (v uint32) {

	var (
		nfq   = (*NfQueue_ext)(nfqptr)
		ipver = IPVersion(version)
		ipsz  = C.int(ipver.Size())
	)
	fmt.Println("nfq: ", nfq)
	bs := C.GoBytes(payload, (C.int)(payload_len))

	verdict := make(chan uint32, 1)
	fmt.Println("NfQueue_int: ", nfq.NfQueue_int)
	pkt := Packet{
		QueueId:    nfq.NfQueue_int.qid,
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
	nfq.pktch <- &pkt

	select {
	case v = <-pkt.verdict:
		*mark = pkt.Mark
	case <-time.After(nfq.NfQueue_int.Timeout):
		v = uint32(nfq.NfQueue_int.DefaultVerdict)
	}

	return v
}
