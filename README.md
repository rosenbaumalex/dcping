# DC Ping RTT test

## Build:
```sh
$ make clean
$ make
```

## Run Server:
```sh
$ ./dcping -s -a 192.192.20.13 -v
verbose
created cm_id 0x18aaef0
rdma_bind_addr successful <192.192.20.13, 7174>
rdma_listen
created pd 0x18aa5c0
created channel 0x18aab30
created cq 0x18ae3b0
hw_clocks_kHz = 78125
created srq 0x18ae5d8
created qp 0x18b2018 (qpn=4556)
allocated & registered buffers...
server ready, waiting for client connection requests...
waiting for client events ...

got cm event: RDMA_CM_EVENT_CONNECT_REQUEST(4) cm_id 0x18b2560
accepting client connection request (cm_id 0x18b2560)
waiting for client events ...
got cm event: RDMA_CM_EVENT_ESTABLISHED(9) cm_id 0x18b2560
client connection established (cm_id 0x18b2560)
waiting for client events ...
got cm event: RDMA_CM_EVENT_DISCONNECTED(10) cm_id 0x18b2560
server DISCONNECT EVENT (cm_id 0x18b2560)
waiting for client events ...
^C
```

## Run Client:
```sh
$ ./dcping -c -a 192.192.20.13 -C 10 -v
verbose
created cm_id 0x1473ef0
got cm event: RDMA_CM_EVENT_ADDR_RESOLVED(0) cm_id 0x1473ef0
got cm event: RDMA_CM_EVENT_ROUTE_RESOLVED(2) cm_id 0x1473ef0
rdma_resolve_addr/rdma_resolve_route successful
created pd 0x1476170
created channel 0x1473560
created cq 0x1477520
hw_clocks_kHz = 78125
created qp 0x1477748 (qpn=288)
allocated & registered buffers...
rdma_connecting...
got cm event: RDMA_CM_EVENT_CONNECT_RESPONSE(5) cm_id 0x1473ef0
GOT dctn=4556, buf=0x18b2330, size=64, rkey=600712
created ah (0x1476260)
rdma_connect successful
connected to server, starting RTT test
[total = 10] rtt = 0.012 / 0.044 / 0.281 usec <min/avg/max>
done DC RTT test
dcping_free_buffers called on cb 0x14733c0
dcping_free_qp/srq/cq/pd called on cb 0x14733c0
destroy cm_id 0x1473ef0
```
