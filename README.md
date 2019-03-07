# DC Ping RTT test

## Build:
```sh
$ make clean
$ make
```

## Run Server:
```sh
$ ./dcping -s -a 192.192.20.13
server
created cm_id 0xbddf10
rdma_bind_addr successful <192.192.20.13, 7174>
rdma_listen
created pd 0xbddb30
created channel 0xbddb60
created cq 0xbe13d0
created srq 0xbe15f8
created qp 0xbe50a8 (qpn=4359)
allocated & registered buffers...
waiting for client events ...


got cm event: RDMA_CM_EVENT_CONNECT_REQUEST(4) cm_id 0xbe54f0
accepting client connection request (cm_id 0xbe54f0)
waiting for client events ...
got cm event: RDMA_CM_EVENT_ESTABLISHED(9) cm_id 0xbe54f0
client connection established (cm_id 0xbe54f0)
waiting for client events ...
got cm event: RDMA_CM_EVENT_DISCONNECTED(10) cm_id 0xbe54f0
server DISCONNECT EVENT (cm_id 0xbe54f0)
waiting for client events ...
^C
```

## Run Client:
```sh
$ ./dcping -c -a 192.192.20.13 -C 10
client
count 10
size 1000
created cm_id 0x6ecef0
got cm event: RDMA_CM_EVENT_ADDR_RESOLVED(0) cm_id 0x6ecef0
got cm event: RDMA_CM_EVENT_ROUTE_RESOLVED(2) cm_id 0x6ecef0
rdma_resolve_addr/rdma_resolve_route successful
created pd 0x6ec370
created channel 0x6ec330
created cq 0x6f0570
hw_clocks_kHz = 78125
created qp 0x6f0798 (qpn=205)
allocated & registered buffers...
rdma_connecting...
got cm event: RDMA_CM_EVENT_CONNECT_RESPONSE(5) cm_id 0x6ecef0
GOT dctn=4452, buf=0x1c543c0, size=1020, rkey=307835
created ah (0x6f0ec0)
rdma_connect successful
start RDMA Write testing
[iter =   0] rtt =      870 nsec (rtt_hw =  68)
[iter =   1] rtt =       12 nsec (rtt_hw =   1)
[iter =   2] rtt =       25 nsec (rtt_hw =   2)
[iter =   3] rtt =       12 nsec (rtt_hw =   1)
[iter =   4] rtt =       64 nsec (rtt_hw =   5)
[iter =   5] rtt =       25 nsec (rtt_hw =   2)
[iter =   6] rtt =       64 nsec (rtt_hw =   5)
[iter =   7] rtt =       12 nsec (rtt_hw =   1)
[iter =   8] rtt =      320 nsec (rtt_hw =  25)
[iter =   9] rtt =      320 nsec (rtt_hw =  25)
done RDMA Write testing
dcping_free_buffers called on cb 0x6ec3c0
dcping_free_qp/srq/cq/pd called on cb 0x6ec3c0
destroy cm_id 0x6ecef0
```
