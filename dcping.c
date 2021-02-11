/*
 * Copyright (c) 2019 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#define _GNU_SOURCE
#include <endian.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <rdma/rdma_cma.h>
#include <infiniband/mlx5dv.h>
#include "my_ibv_helper.h"

static int debug = 0;
static int debug_fast_path = 0;
#define DEBUG_LOG if (debug) printf
#define DEBUG_LOG_FAST_PATH if (debug_fast_path) printf

/*
 * dcping "RTT" loop:
 * 	server listens for incoming connection requests
 * 	client connects to server
 * 	server accepts and replies with RDMA buffer: addr/rkey/len
 *	client receives remote addr/rkey/len
 *	client loop:
 *		posts rdma read/write "ping start" sz=1, and cqe will hold start_ts
 *		posts rdma read/write "ping end" sz=SIZE, and cqe will hold end_ts
 *		polls cq for 2 cqes, then RTT = (cqe[1]->ts - cqe[0]->ts)
 *		wait for next latency polling loop
 * 		<repeat loop>
 */

struct dcping_rdma_info {
	__be64 addr;
	__be32 rkey;
	__be32 size;
	__be32 dctn;
};

/*
 * Default max buffer size for IO...
 */
#define PING_BUFSIZE 1024
#define PING_SQ_DEPTH 64
#define DC_KEY 0xffeeddcc

/* Default string for print data and
 * minimum buffer size
 */
#define _stringify( _x ) # _x
#define stringify( _x ) _stringify( _x )

#define PING_MSG_FMT           "dcping-%d: "
#define PING_MIN_BUFSIZE       sizeof(stringify(INT_MAX)) + sizeof(PING_MSG_FMT)

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MAX_INET_ADDRSTRLEN    MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)

#define USEC_PER_SEC    1000000L

/*
 * Control block struct.
 */
struct dcping_cb {
	int is_server;
	uint32_t count;			/* ping count */
	uint32_t size;			/* ping data size */
	uint32_t delay_usec;

	/* verbs stuff */
	struct ibv_comp_channel *channel;
	struct ibv_cq_ex *cq;
	struct ibv_pd *pd;
	struct ibv_srq *srq;		/* server only (for DCT) */
	struct ibv_qp *qp;		/* DCI (client) or DCT (server) */
        struct ibv_qp_ex *qpex;		/* client only */
        struct mlx5dv_qp_ex *mqpex;	/* client only */
	struct ibv_ah *ah;		/* client only */
	enum ibv_mtu mtu;
	uint8_t is_global:1;
	uint8_t is_reserved_qpn_supp:1;
	uint8_t is_ece_supp:1;
	uint8_t sgid_index;
	uint32_t reserved_qpn;
	struct ibv_ece ece;

	/* CM stuff */
	struct rdma_event_channel *cm_channel;
	struct rdma_cm_id *cm_id;	/* connection on client side,*/
					/* listener on service side. */

	uint64_t hw_clocks_kHz;
	char          *local_buf_addr;
	struct ibv_mr *local_buf_mr;
	struct dcping_rdma_info remote_buf_info;

	struct sockaddr_storage sin;
	struct sockaddr_storage ssource;
	__be16 port;			/* dst port in NBO */
};

struct rdma_event_channel *create_first_event_channel(void)
{
        struct rdma_event_channel *channel;

        channel = rdma_create_event_channel();
        if (!channel) {
                if (errno == ENODEV)
                        fprintf(stderr, "No RDMA devices were detected\n");
                else
                        perror("failed to create RDMA CM event channel");
        }
        return channel;
}

static void dcping_init_conn_param(struct dcping_cb *cb,
				   struct rdma_cm_id *cm_id,
				   struct rdma_conn_param *conn_param)
{
	uint32_t qp_num = 0;

	if (cb->is_reserved_qpn_supp) {
		int ret = my_mlx5dv_reserved_qpn_alloc(cb->cm_id->verbs, &qp_num);
		if (ret) {
			cb->is_reserved_qpn_supp = 0;
			DEBUG_LOG("reserved_qpn...NOT SUPPORTED\n");
		}
		cb->reserved_qpn = qp_num;
	}

	if (qp_num == 0) {
		// Fall back to some software base qp_num allocation

		if (cb->is_server) {
			// fake a unique qp_num based on peer's IP addr + UDP port as we're
			// using the same DCT as an external QPN from all RDMA_CM connection
			qp_num = (((struct sockaddr_in *)rdma_get_peer_addr(cm_id))->sin_addr.s_addr) << 16;
			qp_num |=  be16toh(rdma_get_dst_port(cm_id));
		} else {
			qp_num = cb->qp->qp_num;
		}
	}

	memset(conn_param, 0, sizeof(*conn_param));
	conn_param->responder_resources = 1;
	conn_param->initiator_depth = 1;
	conn_param->retry_count = 7;
	conn_param->rnr_retry_count = 7;
	conn_param->qp_num = qp_num;

	conn_param->private_data = &cb->remote_buf_info; // server's reports it's RDMA buffer details
	conn_param->private_data_len = sizeof(cb->remote_buf_info);
}

static int dcping_setup_buffers(struct dcping_cb *cb)
{
	int ret;

	cb->local_buf_addr = malloc(cb->size);
	if (!cb->local_buf_addr) {
		fprintf(stderr, "local_buf_addr malloc failed\n");
		ret = -ENOMEM;
		goto err1;
	}

	cb->local_buf_mr = ibv_reg_mr(cb->pd, cb->local_buf_addr, cb->size,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_WRITE);
	if (!cb->local_buf_mr) {
		fprintf(stderr, "local_buf_addr reg_mr failed\n");
		ret = errno;
		goto err2;
	}

	DEBUG_LOG("allocated & registered buffers...\n");
	return 0;

err2:
	free(cb->local_buf_addr);
err1:
	return ret;
}

static void dcping_free_buffers(struct dcping_cb *cb)
{
	DEBUG_LOG("dcping_free_buffers called on cb %p\n", cb);
	ibv_dereg_mr(cb->local_buf_mr);
	free(cb->local_buf_addr);
}

static void dcping_ece_get_locally_set_remote(struct dcping_cb *cb, struct rdma_cm_id *cm_id)
{
	int ret = 0;
	if (!cb->is_ece_supp)
		return;

	DEBUG_LOG("update ECE from QP to CM...");

	ret = ibv_query_ece(cb->qp, &cb->ece);
	if (ret) {
		cb->is_ece_supp = 0;
		DEBUG_LOG("NOT SUPPORTED\n");
		return;
	}
	DEBUG_LOG("(%#x, %#x)\n", cb->ece.vendor_id, cb->ece.options);
	ret = rdma_set_local_ece(cm_id, &cb->ece);
	if (ret) {
		perror("rdma_set_local_ece");
		return;
	}
}

static void dcping_ece_get_remote_set_locally(struct dcping_cb *cb, struct rdma_cm_id *cm_id)
{
	int ret = 0;
	struct ibv_ece ece;
	if (!cb->is_ece_supp)
		return;

	DEBUG_LOG("update ECE from CM responce to QP...");

	ret = rdma_get_remote_ece(cm_id, &ece);
	if (ret) {
		cb->is_ece_supp = 0;
		DEBUG_LOG("NOT SUPPORTED\n");
		return;
	}
	DEBUG_LOG("(%#x, %#x)\n", ece.vendor_id, ece.options);
	ibv_set_ece(cb->qp, &ece);
	if (ret) {
		perror("ibv_set_ece");
		return;
	}
}

static int dcping_create_qp(struct dcping_cb *cb)
{
        struct ibv_qp_init_attr_ex attr_ex;
        struct mlx5dv_qp_init_attr attr_dv;
	int ret = 0;

	/* create DC QP */
	memset(&attr_ex, 0, sizeof(attr_ex));
	memset(&attr_dv, 0, sizeof(attr_dv));

	attr_ex.qp_type = IBV_QPT_DRIVER;
	attr_ex.send_cq = ibv_cq_ex_to_cq(cb->cq);
	attr_ex.recv_cq = ibv_cq_ex_to_cq(cb->cq);

	attr_ex.comp_mask |= IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = cb->pd;
	attr_ex.srq = cb->srq; /* will be NULL for client (DCI) */

	if (cb->is_server) {
		/* create DCT */
		attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;
		attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCT;
		attr_dv.dc_init_attr.dct_access_key = DC_KEY;

		cb->qp = mlx5dv_create_qp(cb->cm_id->verbs, &attr_ex, &attr_dv);
	}
	else {
		/* create DCI */
		attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;
		attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCI;

		attr_ex.cap.max_send_wr = PING_SQ_DEPTH;
		attr_ex.cap.max_send_sge = 1;

		attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
		attr_ex.send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE;

		attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
		attr_dv.create_flags |= MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE; /*driver doesnt support scatter2cqe data-path on DCI yet*/

		cb->qp = mlx5dv_create_qp(cb->cm_id->verbs, &attr_ex, &attr_dv);
	}

	if (!cb->qp) {
		perror("mlx5dv_create_qp(DC)");
		ret = errno;
		return ret;
	}
	if (!cb->is_server) {
		cb->qpex = ibv_qp_to_qp_ex(cb->qp);
		if (!cb->qpex) {
			perror("ibv_qp_to_qp_ex(DC)");
			ret = errno;
		}
		cb->mqpex = mlx5dv_qp_ex_from_ibv_qp_ex(cb->qpex);
		if (!cb->mqpex) {
			perror("mlx5dv_qp_ex_from_ibv_qp_ex(DC)");
			ret = errno;
		}
		return ret;
	}

	return ret;
}

static int dcping_modify_qp(struct dcping_cb *cb)
{
	int attr_mask = 0;
	int ret = 0;

	/* modify QP to INIT */
	{
		attr_mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT;

		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = cb->cm_id->port_num,
		};

		if (cb->is_server) {
			attr_mask |= IBV_QP_ACCESS_FLAGS;
			attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE;
		}


		if (ibv_modify_qp(cb->qp, &attr, attr_mask)) {
			perror("failed to modify QP to IBV_QPS_INIT");
			ret = errno;
			return ret;
		}
	}

	/* modify QP to RTR */
	{
		attr_mask = IBV_QP_STATE | IBV_QP_PATH_MTU | IBV_QP_AV;

		struct ibv_qp_attr attr = {
			.qp_state               = IBV_QPS_RTR,
			.path_mtu               = cb->mtu,
			.min_rnr_timer          = 0x10,
			.rq_psn                 = 0,
			.ah_attr                = {
				.is_global      = cb->is_global,
				.sl             = 0,
				.src_path_bits  = 0,
				.port_num       = cb->cm_id->port_num,
				.grh.hop_limit  = 1,
				.grh.sgid_index = cb->sgid_index,
				.grh.traffic_class = 0,

			}
		};

		if (cb->is_server) {
			attr_mask |= IBV_QP_MIN_RNR_TIMER;
		}

		if (ibv_modify_qp(cb->qp, &attr, attr_mask)) {
			perror("failed to modify QP to IBV_QPS_RTR");
			ret = errno;
			return ret;
		}
	}

	if (!cb->is_server) {
		/* modify QP to RTS */
		attr_mask = IBV_QP_STATE | IBV_QP_TIMEOUT |
			IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
			IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
			// Optional: IB_QP_MIN_RNR_TIMER

		struct ibv_qp_attr attr = {
			.qp_state               = IBV_QPS_RTS,
			.timeout                = 0x10,
			.retry_cnt              = 7,
			.rnr_retry              = 7,
			.sq_psn                 = 0,
			.max_rd_atomic          = 1,
		};

		if (ibv_modify_qp(cb->qp, &attr, attr_mask)) {
			perror("failed to modify QP to IBV_QPS_RTS");
			ret = errno;
			return ret;
		}
	}

	return ret;
}

static void dcping_free_qp(struct dcping_cb *cb)
{
	DEBUG_LOG("dcping_free_qp/srq/cq/pd called on cb %p\n", cb);
	if (cb->qp) ibv_destroy_qp(cb->qp);
	if (cb->srq) ibv_destroy_srq(cb->srq);
	ibv_destroy_cq(ibv_cq_ex_to_cq(cb->cq));
	ibv_destroy_comp_channel(cb->channel);
	ibv_dealloc_pd(cb->pd);
}

static int dcping_setup_qp(struct dcping_cb *cb, struct rdma_cm_id *srv_req_cm_id)
{
	int ret;
	struct ibv_cq_init_attr_ex cq_attr_ex;
	struct ibv_device_attr_ex device_attr_ex = {};

	cb->channel = ibv_create_comp_channel(cb->cm_id->verbs);
	if (!cb->channel) {
		fprintf(stderr, "ibv_create_comp_channel failed\n");
		ret = errno;
		goto err1;
	}
	DEBUG_LOG("created channel %p\n", cb->channel);

	memset(&cq_attr_ex, 0, sizeof(cq_attr_ex));
	cq_attr_ex.cqe = PING_SQ_DEPTH * 2;
	cq_attr_ex.cq_context = cb;
	cq_attr_ex.channel = cb->channel;
	cq_attr_ex.comp_vector = 0;
	cq_attr_ex.wc_flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;

	cb->cq = ibv_create_cq_ex(cb->cm_id->verbs, &cq_attr_ex);
	if (!cb->cq) {
		fprintf(stderr, "ibv_create_cq failed\n");
		ret = errno;
		goto err2;
	}
	DEBUG_LOG("created cq %p\n", cb->cq);

	if (cb->is_server) 
	{
		struct ibv_srq_init_attr srq_attr;
		memset(&srq_attr, 0, sizeof(srq_attr));
		srq_attr.attr.max_wr = 2;
		srq_attr.attr.max_sge = 1;
		cb->srq = ibv_create_srq(cb->pd, &srq_attr);
		if (!cb->srq) {
			fprintf(stderr, "ibv_create_srq failed\n");
			ret = errno;
			goto err3;
		}

		DEBUG_LOG("created srq %p\n", cb->srq);
	}

	ret = dcping_create_qp(cb);
	if (ret) {
		goto err4;
	}

	if (cb->is_server) {
		dcping_ece_get_remote_set_locally(cb, srv_req_cm_id);
	}

	ret = dcping_modify_qp(cb);
	if (ret) {
		goto err5;
	}
	DEBUG_LOG("created qp %p (qpn=%d)\n", cb->qp, (cb->qp ? cb->qp->qp_num : (uint32_t)-1));

	ret = ibv_query_device_ex(cb->cm_id->verbs, NULL, &device_attr_ex);
	if (ret) {
		fprintf(stderr, "ibv_query_device_ex failed\n");
		ret = errno;
		goto err3;
	}
	if (!device_attr_ex.hca_core_clock) {
		fprintf(stderr, "hca_core_clock = 0\n");
		ret = errno;
		goto err3;
	}
	cb->hw_clocks_kHz = device_attr_ex.hca_core_clock;
	DEBUG_LOG("hw_clocks_kHz = %ld\n", cb->hw_clocks_kHz);

	return 0;

err5:
	ibv_destroy_qp(cb->qp);
err4:
	if (cb->srq)
		ibv_destroy_srq(cb->srq);
err3:
	ibv_destroy_cq(ibv_cq_ex_to_cq(cb->cq));
err2:
	ibv_destroy_comp_channel(cb->channel);
err1:
	ibv_dealloc_pd(cb->pd);
	return ret;
}

static int dcping_handle_cm_event(struct dcping_cb *cb, enum rdma_cm_event_type *cm_event, struct rdma_cm_id **cm_id)
{
        int ret;
        struct rdma_cm_event *event;

	*cm_id = NULL;
	*cm_event = -1;

        ret = rdma_get_cm_event(cb->cm_channel, &event);
        if (ret) {
                perror("rdma_get_cm_event");
                exit(ret);
        }
        DEBUG_LOG("got cm event: %s(%d) status=%d, cm_id %p\n", rdma_event_str(event->event), event->event, event->status, event->id);

	*cm_id = event->id;
	*cm_event = event->event;

        switch (event->event) {

                case RDMA_CM_EVENT_ADDR_RESOLVED:
		case RDMA_CM_EVENT_ADDR_ERROR:
                case RDMA_CM_EVENT_ROUTE_RESOLVED:
		case RDMA_CM_EVENT_ROUTE_ERROR:
		case RDMA_CM_EVENT_CONNECT_REQUEST:
		case RDMA_CM_EVENT_CONNECT_ERROR:
		case RDMA_CM_EVENT_UNREACHABLE:
		case RDMA_CM_EVENT_REJECTED:
		case RDMA_CM_EVENT_ESTABLISHED:
		case RDMA_CM_EVENT_DISCONNECTED:
			break;

                case RDMA_CM_EVENT_CONNECT_RESPONSE:
			if (event->param.conn.private_data_len >= sizeof(struct dcping_rdma_info)) {
				struct rdma_conn_param *conn_param = &event->param.conn;
				struct dcping_rdma_info *remote_buf_info = (struct dcping_rdma_info *)conn_param->private_data;

				cb->remote_buf_info.addr = be64toh(remote_buf_info->addr);
				cb->remote_buf_info.size = be32toh(remote_buf_info->size);
				cb->remote_buf_info.rkey = be32toh(remote_buf_info->rkey);
				cb->remote_buf_info.dctn = be32toh(remote_buf_info->dctn); 

				DEBUG_LOG("got server param's: dctn=%d, buf=%llu, size=%d, rkey=%d\n", cb->remote_buf_info.dctn, cb->remote_buf_info.addr, cb->remote_buf_info.size, cb->remote_buf_info.rkey);
			}
			break;

		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			fprintf(stderr, "cma detected device removal!!!!\n");
			ret = -1;
			break;

		default:
                        fprintf(stderr, "unhandled event: %s, ignoring\n",
                                        rdma_event_str(event->event));
                        ret = -1;
                        break;
        }
        rdma_ack_cm_event(event);
	return ret;
}

static int dcping_bind_server(struct dcping_cb *cb)
{
	int ret;
	char str[MAX_INET_ADDRSTRLEN];
	struct ibv_port_attr port_attr;

	if (cb->sin.ss_family == AF_INET) {
		((struct sockaddr_in *) &cb->sin)->sin_port = cb->port;
		inet_ntop(AF_INET, &(((struct sockaddr_in *)&cb->sin)->sin_addr), str, sizeof(str));
	}
	else {
		((struct sockaddr_in6 *) &cb->sin)->sin6_port = cb->port;
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&cb->sin)->sin6_addr), str, sizeof(str));
	}

	ret = rdma_bind_addr(cb->cm_id, (struct sockaddr *) &cb->sin);
	if (ret) {
		perror("rdma_bind_addr");
		return ret;
	}
	if (cb->cm_id->verbs == NULL) {
		DEBUG_LOG("Failed to bind to an RDMA device, exiting... <%s, %d>\n", str, be16toh(cb->port));
		exit(1);
	}

	if (ibv_query_port(cb->cm_id->verbs, cb->cm_id->port_num, &port_attr)) {
                perror("ibv_query_port");
		exit(1);
        }
	cb->mtu = port_attr.active_mtu;
	if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
		cb->is_global = 1;
		cb->sgid_index = my_ibv_find_sgid_type(cb->cm_id->verbs, cb->cm_id->port_num, MY_IBV_GID_TYPE_ROCE_V2, cb->sin.ss_family);
	}

	DEBUG_LOG("rdma_bind_addr successful on address: <%s:%d>\n", str, be16toh(cb->port));

	DEBUG_LOG("rdma_listen\n");
	ret = rdma_listen(cb->cm_id, 3);
	if (ret) {
		perror("rdma_listen");
		return ret;
	}

	cb->pd = ibv_alloc_pd(cb->cm_id->verbs);
	if (!cb->pd) {
		fprintf(stderr, "ibv_alloc_pd failed\n");
		return errno;
	}
	DEBUG_LOG("created pd %p\n", cb->pd);

	return 0;
}

static void free_cb(struct dcping_cb *cb)
{
	free(cb);
}

static int dcping_run_server(struct dcping_cb *cb)
{
	int ret;
        char str[MAX_INET_ADDRSTRLEN];

	ret = dcping_bind_server(cb);
	if (ret)
		return ret;

	ret = dcping_setup_buffers(cb);
	if (ret) {
		fprintf(stderr, "setup_buffers failed: %d\n", ret);
		goto err1;
	}

	printf("server ready, waiting for client connection requests...\n");

	// main loop:
	// 	wait for CONN REQ
	// 	accept with dctn and MKey
	while (1)
	{
		struct rdma_cm_id *req_cm_id;
		enum rdma_cm_event_type cm_event;

		DEBUG_LOG("waiting for client events ...\n");
		ret = dcping_handle_cm_event(cb, &cm_event, &req_cm_id);
		switch (cm_event) {

			case RDMA_CM_EVENT_CONNECT_REQUEST:
				if (cb->sin.ss_family == AF_INET) {
					inet_ntop(AF_INET, &(((struct sockaddr_in *)rdma_get_peer_addr(req_cm_id))->sin_addr), str, sizeof(str));
				}
				else {
					inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)rdma_get_peer_addr(req_cm_id))->sin6_addr), str, sizeof(str));
				}

				DEBUG_LOG("accepting client connection request from <%s:%d> (cm_id %p)\n", str, be16toh(rdma_get_dst_port(req_cm_id)), req_cm_id);

				if (!cb->qp) {
					ret = dcping_setup_qp(cb, req_cm_id);
					if (ret) {
						fprintf(stderr, "setup_qp failed: %d\n", ret);
						return ret;
					}

					if (cb->is_server) {
						cb->remote_buf_info.addr = htobe64((uint64_t) (unsigned long) cb->local_buf_addr);
						cb->remote_buf_info.size = htobe32(cb->size);
						cb->remote_buf_info.rkey = htobe32(cb->local_buf_mr->rkey);
						cb->remote_buf_info.dctn = htobe32(cb->qp->qp_num);
					}
				}

				dcping_ece_get_locally_set_remote(cb, req_cm_id);

				struct rdma_conn_param conn_param;
				dcping_init_conn_param(cb, req_cm_id, &conn_param);
				ret = rdma_accept(req_cm_id, &conn_param);
				if (ret) {
					perror("rdma_accept");
					goto err2;
				}
				break;

			case RDMA_CM_EVENT_ESTABLISHED:
				printf("client connection established (cm_id %p)\n", req_cm_id);
				break;

			case RDMA_CM_EVENT_DISCONNECTED:
				rdma_disconnect(req_cm_id);
				rdma_destroy_id(req_cm_id);
				if (cb->is_reserved_qpn_supp) {
					my_mlx5dv_reserved_qpn_dealloc(cb->cm_id->verbs, cb->reserved_qpn);
					cb->reserved_qpn = 0;
				}
				if (cb->is_server) printf("client connection disconnected (cm_id %p)\n", req_cm_id);
				break;

			default:
				fprintf(stderr, "server unexpected event: %s (%d)\n", rdma_event_str(cm_event), cm_event);
				exit(1);
				break;
		}
	}


	ret = 0;
err2:
	dcping_free_buffers(cb);
err1:
	dcping_free_qp(cb);

	return ret;
}

static int dcping_client_dc_send_wr(struct dcping_cb *cb, uint64_t wr_id)
{
	/* 1st small RDMA Write for DCI connect, this will create cqe->ts_start */
	ibv_wr_start(cb->qpex);
	cb->qpex->wr_id = wr_id;
	cb->qpex->wr_flags = IBV_SEND_SIGNALED;
	ibv_wr_rdma_write(cb->qpex, cb->remote_buf_info.rkey, cb->remote_buf_info.addr);
	mlx5dv_wr_set_dc_addr(cb->mqpex, cb->ah, cb->remote_buf_info.dctn, DC_KEY);
	ibv_wr_set_sge(cb->qpex, cb->local_buf_mr->lkey,
			(uintptr_t)cb->local_buf_addr, 1);

	/* 2nd SIZE x RDMA Write, this will create cqe->ts_end */
	cb->qpex->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_FENCE;
        ibv_wr_rdma_write(cb->qpex, cb->remote_buf_info.rkey, cb->remote_buf_info.addr);
        mlx5dv_wr_set_dc_addr(cb->mqpex, cb->ah, cb->remote_buf_info.dctn, DC_KEY);
        ibv_wr_set_sge(cb->qpex, cb->local_buf_mr->lkey,
                        (uintptr_t)cb->local_buf_addr,
                        (uint32_t)cb->size);

	/* ring DB */
	return ibv_wr_complete(cb->qpex);
}

static int dcping_client_wait_cq_event(struct dcping_cb *cb)
{
	int ret;
	void *ev_ctx;
	struct ibv_cq *ev_cq;

	ret = ibv_req_notify_cq(ibv_cq_ex_to_cq(cb->cq), 0);
	if (ret) {
		perror("ibv_req_notify_cq");
		ret = errno;
		return ret;
	}
	DEBUG_LOG_FAST_PATH("waiting for cq event...\n");
	if (ibv_get_cq_event(cb->channel, &ev_cq, &ev_ctx)) {
		perror("ibv_get_cq_event");
		ret = errno;
		return ret;
	}
	ibv_ack_cq_events(ibv_cq_ex_to_cq(cb->cq), 1);
	DEBUG_LOG_FAST_PATH("got someting.. checking\n");

	if ((ev_ctx != cb) || (ev_cq != ibv_cq_ex_to_cq(cb->cq))) {
		fprintf(stderr, "ibv_get_cq_event return with wrong cq_ctx (%p) or wrong ibv_cq_ctx (%p)\n", ev_ctx, ev_cq);
		ret = errno;
		return ret;
	}
	return ret;
}

static int dcping_client_process_cqe(struct dcping_cb *cb, uint64_t wr_id, uint64_t *ts_out)
{
	*ts_out = 0;

	if (cb->cq->status !=  IBV_WC_SUCCESS) {
		fprintf(stderr, "CQ failed with status '%s' (%d) for wr_id %d\n",
				ibv_wc_status_str(cb->cq->status),
				cb->cq->status, (int)cb->cq->wr_id);
		return -1;
	}

	if (cb->cq->wr_id != wr_id) {
		fprintf(stderr, "CQ failed wr_id compare '%s' (%d) for cqe->wr_id(%ld) vs wr_id(%ld)\n",
				ibv_wc_status_str(cb->cq->status), cb->cq->status,
				cb->cq->wr_id, wr_id);
		return -1;
	}

	*ts_out = ibv_wc_read_completion_ts(cb->cq);
	return 0;
}

static int dcping_client_get_cqe_tiemstmp(struct dcping_cb *cb, uint64_t wr_id, uint64_t *ts_hw_start, uint64_t *ts_hw_end)
{
	/* we expect 2 cqe matching wr_id's to input */

	int ret, step=0;
	uint64_t ts_hw;
	struct ibv_poll_cq_attr cq_attr = {};

	*ts_hw_start = *ts_hw_end = 0;

	do {
		ret = ibv_start_poll(cb->cq, &cq_attr);
		if (ret) {
			if (ret == ENOENT) {
				ret = dcping_client_wait_cq_event(cb);
				if (ret) {
					return ret;
				}
				/* check cq again, return to main loop */
				continue;
			}
			perror("ibv_start_poll");
			ret = errno;
			return ret;
		}

		ret = dcping_client_process_cqe(cb, wr_id, &ts_hw);
		ibv_end_poll(cb->cq);

		DEBUG_LOG_FAST_PATH("processing cqe (step %d) ts_hw = %lu\n", step, ts_hw);

		if (ret)
			return ret;

		if (step == 0)
			*ts_hw_start = ts_hw;
		else
			*ts_hw_end = ts_hw;

		step++;

	} while (step < 2);

	return 0;
}

static int dcping_test_client(struct dcping_cb *cb)
{
	int ret = 0;
	uint32_t ping;
	uint64_t ts_hw_start, ts_hw_end;
	uint64_t rtt_nsec, rtt_hw;

	uint64_t rtt_nsec_min = ULLONG_MAX;
	uint64_t rtt_nsec_max = 0;
	uint64_t rtt_nsec_total = 0;

	printf("connected to server, starting DC RTT test\n");

	for (ping = 0; !cb->count || ping < cb->count; ping++) {
		/* initiate RDMA Write x2 ops to create tiemstamp CQE's */
		DEBUG_LOG_FAST_PATH("before post send \n");
		ret = dcping_client_dc_send_wr(cb, ping);
		if (ret) {
			DEBUG_LOG("dc send error :(\n");
		}

		/* wait for CQE's with timestamp */
		DEBUG_LOG_FAST_PATH("before cqe check\n");
		ret = dcping_client_get_cqe_tiemstmp(cb, ping, &ts_hw_start, &ts_hw_end);
		if (ret) {
			DEBUG_LOG("cqe processing failed :(\n");
			return ret;
		}

		/* clac RTT */
		rtt_hw = ts_hw_end - ts_hw_start;
		rtt_nsec = rtt_hw * USEC_PER_SEC / cb->hw_clocks_kHz;
		printf("\r[iter =%4d] rtt = %ld.%3.3ld usec", ping, rtt_nsec/1000, rtt_nsec%1000); fflush(stdout);

		rtt_nsec_total += rtt_nsec;
		if (rtt_nsec_min > rtt_nsec) rtt_nsec_min = rtt_nsec;
		if (rtt_nsec_max < rtt_nsec) rtt_nsec_max = rtt_nsec;

		usleep(cb->delay_usec);
	}

	printf("\r[total = %d] rtt = %ld.%3.3ld / %ld.%3.3ld / %ld.%3.3ld usec <min/avg/max>\n", ping, 
		(rtt_nsec_min)/1000, (rtt_nsec_min)%1000, 
		(rtt_nsec_total/ping)/1000, (rtt_nsec_total/ping)%1000,
		(rtt_nsec_max)/1000, (rtt_nsec_max)%1000);
	printf("done DC RTT test\n");

	return 0;
}

static int dcping_connect_client(struct dcping_cb *cb)
{
	int ret;
	int qp_attr_mask;
	struct ibv_qp_attr qp_attr;
	struct rdma_cm_id *cm_id;
	enum rdma_cm_event_type cm_event;
	struct rdma_conn_param conn_param;

	dcping_ece_get_locally_set_remote(cb, cb->cm_id);

	DEBUG_LOG("rdma_connecting...\n");
	dcping_init_conn_param(cb, cb->cm_id, &conn_param);
	ret = rdma_connect(cb->cm_id, &conn_param);
	if (ret) {
		perror("rdma_connect");
		return ret;
	}

	ret = dcping_handle_cm_event(cb, &cm_event, &cm_id);
	if (ret || cm_event != RDMA_CM_EVENT_CONNECT_RESPONSE) {
		perror("rdma_connect wrong responce");
		return -1;
	}

	dcping_ece_get_remote_set_locally(cb, cb->cm_id);

	DEBUG_LOG("modify QP...\n");
	qp_attr.qp_state = IBV_QPS_RTR;
	ret = rdma_init_qp_attr(cb->cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		perror("rdma_init_qp_attr");
		return ret;
	}

	cb->ah = ibv_create_ah(cb->pd, &qp_attr.ah_attr);
	if (!cb->ah) {
		perror("ibv_create_ah");
		return -1;
	}
	DEBUG_LOG("created ah (%p)\n", cb->ah);

	ret = rdma_establish(cb->cm_id);
	if (ret) {
		perror("rdma_establish");
		return ret;
	}

	DEBUG_LOG("rdma_connect successful\n");
	return 0;
}

static int dcping_bind_client(struct dcping_cb *cb)
{
	int ret;
	char str[MAX_INET_ADDRSTRLEN];
	struct ibv_port_attr port_attr;
	struct rdma_cm_id *cm_id;
	enum rdma_cm_event_type cm_event;       

	if (cb->sin.ss_family == AF_INET) {
		((struct sockaddr_in *) &cb->sin)->sin_port = cb->port;
		inet_ntop(AF_INET, &(((struct sockaddr_in *)&cb->sin)->sin_addr), str, sizeof(str));
	}
	else {
		((struct sockaddr_in6 *) &cb->sin)->sin6_port = cb->port;
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&cb->sin)->sin6_addr), str, sizeof(str));
	}

	if (cb->ssource.ss_family) 
		ret = rdma_resolve_addr(cb->cm_id, (struct sockaddr *) &cb->ssource,
				(struct sockaddr *) &cb->sin, 2000);
	else
		ret = rdma_resolve_addr(cb->cm_id, NULL, (struct sockaddr *) &cb->sin, 2000);

	if (ret) {
		perror("rdma_resolve_addr");
		return ret;
	}

	ret = dcping_handle_cm_event(cb, &cm_event, &cm_id);
	if (cm_event != RDMA_CM_EVENT_ADDR_RESOLVED) {
		return -1;
	}

	ret = rdma_resolve_route(cb->cm_id, 2000);
	if (ret) {
		perror("rdma_resolve_route");
	}

	ret = dcping_handle_cm_event(cb, &cm_event, &cm_id);
	if (cm_event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
		return -1;
	}

        if (ibv_query_port(cb->cm_id->verbs, cb->cm_id->port_num, &port_attr)) {
                perror("ibv_query_port");
                exit(1);
        }
        cb->mtu = port_attr.active_mtu;
        if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
		cb->is_global = 1;
                cb->sgid_index = my_ibv_find_sgid_type(cb->cm_id->verbs, cb->cm_id->port_num, MY_IBV_GID_TYPE_ROCE_V2, cb->sin.ss_family);
        }

	DEBUG_LOG("rdma_resolve_addr/rdma_resolve_route successful to server: <%s:%d>\n", str, be16toh(rdma_get_src_port(cb->cm_id)));

	cb->pd = ibv_alloc_pd(cb->cm_id->verbs);
	if (!cb->pd) {
		fprintf(stderr, "ibv_alloc_pd failed\n");
		return errno;
	}
	DEBUG_LOG("created pd %p\n", cb->pd);

	return 0;
}

static int dcping_run_client(struct dcping_cb *cb)
{
	int ret;

	ret = dcping_bind_client(cb);
	if (ret)
		return ret;

	ret = dcping_setup_qp(cb, NULL);
	if (ret) {
		fprintf(stderr, "setup_qp failed: %d\n", ret);
		return ret;
	}

	ret = dcping_setup_buffers(cb);
	if (ret) {
		fprintf(stderr, "rping_setup_buffers failed: %d\n", ret);
		goto err1;
	}

	ret = dcping_connect_client(cb);
	if (ret) {
		fprintf(stderr, "connect error %d\n", ret);
		goto err2;
	}

	ret = dcping_test_client(cb);
	if (ret) {
		fprintf(stderr, "rping client failed: %d\n", ret);
		goto err3;
	}

	ret = 0;
err3:
	rdma_disconnect(cb->cm_id);
err2:
	dcping_free_buffers(cb);
err1:
	dcping_free_qp(cb);

	return ret;
}

static int get_addr(char *dst, struct sockaddr *addr)
{
	struct addrinfo *res;
	int ret;

	ret = getaddrinfo(dst, NULL, NULL, &res);
	if (ret) {
		printf("getaddrinfo failed (%s) - invalid hostname or IP address\n", gai_strerror(ret));
		return ret;
	}

	if (res->ai_family == PF_INET)
		memcpy(addr, res->ai_addr, sizeof(struct sockaddr_in));
	else if (res->ai_family == PF_INET6)
		memcpy(addr, res->ai_addr, sizeof(struct sockaddr_in6));
	else
		ret = -1;

	freeaddrinfo(res);
	return ret;
}

static void usage(const char *name, int op)
{
	if (op) {
		printf("%s: op '%c' not avilable\n", 
			basename(name), op);
	}
	printf("%s -s -a addr [-d] [-S size] [-C count] [-p port]\n", 
	       basename(name));
	printf("%s -c -a addr [-d] [-S size] [-C count] [-D delay] [-I addr] [-p port]\n", 
	       basename(name));
	printf("\t-c\t\tclient side\n");
	printf("\t-s\t\tserver side. To bind to any address with IPv6 use -a ::0\n");
	printf("\t-a addr\t\taddress\n");
	printf("\t-p port\t\tserver port\n");
	printf("\t-I\t\tSource address to bind to for client.\n");
	printf("\t-S size \tping data size (default: 64B)\n");
	printf("\t-C count\tping count times (default: 1)\n");
	printf("\t-D delay\tinter-rtt delay [milli-sec] (default: 1 sec)\n");
	printf("\t-d\t\tdebug printfs\n");
}

int main(int argc, char *argv[])
{
	struct dcping_cb *cb;
	int op;
	int ret = 0;

	cb = malloc(sizeof(*cb));
	if (!cb)
		return -ENOMEM;

	memset(cb, 0, sizeof(*cb));
	cb->is_server = -1;
	cb->count = 1;
	cb->size = 64;
	cb->sin.ss_family = PF_INET;
	cb->port = htobe16(7174);
	cb->is_reserved_qpn_supp = 1;
	cb->is_ece_supp = 1;

	opterr = 0;
	while ((op = getopt(argc, argv, "a:I:p:C:S:D:t:scvd")) != -1) {
		switch (op) {
		case 'a':
			ret = get_addr(optarg, (struct sockaddr *) &cb->sin);
			break;
		case 'I':
			ret = get_addr(optarg, (struct sockaddr *) &cb->ssource);
			break;
		case 'p':
			cb->port = htobe16(atoi(optarg));
			DEBUG_LOG("port %d\n", (int) atoi(optarg));
			break;
		case 's':
			cb->is_server = 1;
			DEBUG_LOG("server\n");
			break;
		case 'c':
			cb->is_server = 0;
			DEBUG_LOG("client\n");
			break;
		case 'S':
			cb->size = atoi(optarg);
			if ((cb->size < PING_MIN_BUFSIZE) ||
			    (cb->size > (PING_BUFSIZE - 1))) {
				fprintf(stderr, "Invalid size %d "
				       "(valid range is %zd to %d)\n",
				       cb->size, PING_MIN_BUFSIZE, PING_BUFSIZE);
				ret = EINVAL;
			} else
				DEBUG_LOG("size %d\n", (int) atoi(optarg));
			break;
		case 'C':
			cb->count = atoi(optarg);
			DEBUG_LOG("count %d\n", (int) cb->count);
			break;
		case 'D':
			cb->delay_usec = atoi(optarg) * 1000;
			DEBUG_LOG("delay %d [msec]\n", cb->delay_usec / 1000);
			break;
		case 'd':
			debug++;
			break;
		default:
			usage("rping", op);
			ret = EINVAL;
			goto out;
		}
	}
	if (ret)
		goto out;

	if (cb->is_server == -1) {
		usage("dcping", 0);
		ret = EINVAL;
		goto out;
	}

	cb->cm_channel = create_first_event_channel();
	if (!cb->cm_channel) {
		ret = errno;
		goto out;
	}

	ret = rdma_create_id(cb->cm_channel, &cb->cm_id, cb, RDMA_PS_TCP);
	if (ret) {
		perror("rdma_create_id");
		goto out2;
	}
	DEBUG_LOG("created cm_id %p\n", cb->cm_id);

	if (cb->is_server) {
		ret = dcping_run_server(cb);
	} else {
		ret = dcping_run_client(cb);
	}

	DEBUG_LOG("destroy cm_id %p\n", cb->cm_id);
	rdma_destroy_id(cb->cm_id);
out2:
	rdma_destroy_event_channel(cb->cm_channel);
out:
	free_cb(cb);
	return ret;
}
