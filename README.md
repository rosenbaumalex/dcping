# Build:
```sh
$ gcc -o pingmesh pingmesh.c -libverbs -lrdmacm -lmlx5
```

# Run Server:
```sh
$ ./pingmesh -s -a 192.192.20.13
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

# Run Client:
```sh
$  ./pingmesh -c -a 192.192.20.13
client
created cm_id 0x13c4f10
got cm event: RDMA_CM_EVENT_ADDR_RESOLVED(0) cm_id 0x13c4f10
got cm event: RDMA_CM_EVENT_ROUTE_RESOLVED(2) cm_id 0x13c4f10
rdma_resolve_addr/rdma_resolve_route successful
created pd 0x13c4370
created channel 0x13c4330
created cq 0x13c8590
created qp 0x13c87b8 (qpn=136)
allocated & registered buffers...
rdma_connecting...
got cm event: RDMA_CM_EVENT_CONNECT_RESPONSE(5) cm_id 0x13c4f10
GOT SIZE=64, RKEY=41386
rdma_connect successful
rping client failed: -1
pingmesh_free_buffers called on cb 0x13c43c0
destroy cm_id 0x13c4f10
```
