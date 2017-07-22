**This is in Development**
**Use the dev branch**

Go-NFQueue
==========
Go Wrapper For Creating IPTables' NFQueue clients in Go

Usage
------
Check the `examples/test.go` file

```bash
	cd $GOPATH/github.com/OneOfOne/go-nfqueue/examples
	go build -race && sudo ./examples
```
* Open another terminal :
```bash
sudo iptables -I INPUT 1 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
#or
sudo iptables -I INPUT -i eth0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
curl --head localhost
ping localhost
sudo iptables -D INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
```
Then you can `ctrl+c` the program to exit.

* If you have recent enough iptables/nfqueue you could also use a balanced (multithreaded queue).
* check the example in `examples/mq/multiqueue.go`

```bash
iptables -I INPUT 1  -m conntrack --ctstate NEW -j NFQUEUE --queue-balance 0:5 --queue-cpu-fanout
```
Notes
-----

You must run the executable as root or with the capabilitiy CAP_NET_ADMIN
This is *WIP*, but all patches are welcome.

libnetfilter_queue project page: https://www.netfilter.org/projects/libnetfilter_queue/
libnetfilter_queue documentation: https://www.netfilter.org/projects/libnetfilter_queue/doxygen/

License
-------
go-nfqueue is under the Apache v2 license, check the included license file.
Copyright © [Ahmed W.](http://www.limitlessfx.com/)
See the included `LICENSE` file.

> Copyright (c) 2014 Ahmed W.