# DC Ping RTT test

## Build:
```sh
$ make clean
$ make
```

## Run Server:
```sh
$ ./dcping -s -a 192.192.20.13 -d
created cm_id 0x158aef0
rdma_bind_addr successful on address: <192.192.20.13:7174>
rdma_listen
created pd 0x158a5c0
created channel 0x158ab30
created cq 0x158e3b0
created srq 0x158e5d8
created qp 0x1592018 (qpn=4700)
hw_clocks_kHz = 78125
allocated & registered buffers...
server ready, waiting for client connection requests...
waiting for client events ...
got cm event: RDMA_CM_EVENT_CONNECT_REQUEST(4) status=0, cm_id 0x1592560
accepting client connection request from <192.192.20.13:57929> (cm_id 0x1592560)
waiting for client events ...
got cm event: RDMA_CM_EVENT_ESTABLISHED(9) status=0, cm_id 0x1592560
client connection established (cm_id 0x1592560)
waiting for client events ...
got cm event: RDMA_CM_EVENT_DISCONNECTED(10) status=0, cm_id 0x1592560
client connection disconnected (cm_id 0x1592560)
waiting for client events ...
^C
```

## Run Client:
```sh
$ ./dcping -c -a 192.192.20.13 -C 100 -D 100 -d
created cm_id 0x719ef0
got cm event: RDMA_CM_EVENT_ADDR_RESOLVED(0) status=0, cm_id 0x719ef0
got cm event: RDMA_CM_EVENT_ROUTE_RESOLVED(2) status=0, cm_id 0x719ef0
rdma_resolve_addr/rdma_resolve_route successful to server: <192.192.20.13:57929>
created pd 0x71c170
created channel 0x719560
created cq 0x71d520
created qp 0x71d748 (qpn=365)
hw_clocks_kHz = 78125
allocated & registered buffers...
rdma_connecting...
got cm event: RDMA_CM_EVENT_CONNECT_RESPONSE(5) status=0, cm_id 0x719ef0
got server param's: dctn=4700, buf=0x1592330, size=64, rkey=950316
created ah (0x71c260)
rdma_connect successful
connected to server, starting DC RTT test
[total = 100] rtt = 0.012 / 0.070 / 0.281 usec <min/avg/max>
done DC RTT test
dcping_free_buffers called on cb 0x7193c0
dcping_free_qp/srq/cq/pd called on cb 0x7193c0
destroy cm_id 0x719ef0
```
