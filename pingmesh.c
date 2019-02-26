/*
 * Copyright (c) 2005 Ammasso, Inc. All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <inttypes.h>
#include <rdma/rdma_cma.h>
#include <infiniband/mlx5dv.h>

static int debug = 1;
#define DEBUG_LOG if (debug) printf

/*
 * pingmesh "RTT" loop:
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

struct pingmesh_rdma_info {
	__be64 addr;
	__be32 rkey;
	__be32 size;
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

#define PING_MSG_FMT           "pingmesh-%d: "
#define PING_MIN_BUFSIZE       sizeof(stringify(INT_MAX)) + sizeof(PING_MSG_FMT)

/*
 * Control block struct.
 */
struct pingmesh_cb {
	int server;			/* 0 iff client */
	struct ibv_comp_channel *channel;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_srq *srq;
	struct ibv_qp *qp;

	struct ibv_send_wr rdma_sq_wr;	/* rdma work request record */
	struct ibv_sge rdma_sgl;	/* rdma single SGE */
	char *rdma_buf;			/* used as rdma sink */
	struct ibv_mr *rdma_mr;

	struct pingmesh_rdma_info rdma_info_for_remote;

	struct sockaddr_storage sin;
	struct sockaddr_storage ssource;
	__be16 port;			/* dst port in NBO */
	int verbose;			/* verbose logging */
	int count;			/* ping count */
	int size;			/* ping data size */

	/* CM stuff */
	struct rdma_event_channel *cm_channel;
	struct rdma_cm_id *cm_id;	/* connection on client side,*/
					/* listener on service side. */
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

#if 0
static int server_recv(struct pingmesh_cb *cb, struct ibv_wc *wc)
{
	if (wc->byte_len != sizeof(cb->recv_buf)) {
		fprintf(stderr, "Received bogus data, size %d\n", wc->byte_len);
		return -1;
	}

	cb->remote_rkey = be32toh(cb->recv_buf.rkey);
	cb->remote_addr = be64toh(cb->recv_buf.buf);
	cb->remote_len  = be32toh(cb->recv_buf.size);
	DEBUG_LOG("Received rkey %x addr %" PRIx64 " len %d from peer\n",
		  cb->remote_rkey, cb->remote_addr, cb->remote_len);

	if (cb->state <= CONNECTED || cb->state == RDMA_WRITE_COMPLETE)
		cb->state = RDMA_READ_ADV;
	else
		cb->state = RDMA_WRITE_ADV;

	return 0;
}

static int client_recv(struct pingmesh_cb *cb, struct ibv_wc *wc)
{
	if (wc->byte_len != sizeof(cb->recv_buf)) {
		fprintf(stderr, "Received bogus data, size %d\n", wc->byte_len);
		return -1;
	}

	if (cb->state == RDMA_READ_ADV)
		cb->state = RDMA_WRITE_ADV;
	else
		cb->state = RDMA_WRITE_COMPLETE;

	return 0;
}

static int rping_cq_event_handler(struct pingmesh_cb *cb)
{
	struct ibv_wc wc;
	struct ibv_recv_wr *bad_wr;
	int ret;
	int flushed = 0;

	while ((ret = ibv_poll_cq(cb->cq, 1, &wc)) == 1) {
		ret = 0;

		if (wc.status) {
			if (wc.status == IBV_WC_WR_FLUSH_ERR) {
				flushed = 1;
				continue;

			}
			fprintf(stderr,
				"cq completion failed status %d\n",
				wc.status);
			ret = -1;
			goto error;
		}

		switch (wc.opcode) {
		case IBV_WC_SEND:
			DEBUG_LOG("send completion\n");
			break;

		case IBV_WC_RDMA_WRITE:
			DEBUG_LOG("rdma write completion\n");
			cb->state = RDMA_WRITE_COMPLETE;
//			sem_post(&cb->sem);
			break;

		case IBV_WC_RDMA_READ:
			DEBUG_LOG("rdma read completion\n");
			cb->state = RDMA_READ_COMPLETE;
//			sem_post(&cb->sem);
			break;

		case IBV_WC_RECV:
			DEBUG_LOG("recv completion\n");
			ret = cb->server ? server_recv(cb, &wc) :
					   client_recv(cb, &wc);
			if (ret) {
				fprintf(stderr, "recv wc error: %d\n", ret);
				goto error;
			}

			ret = ibv_post_recv(cb->qp, &cb->rq_wr, &bad_wr);
			if (ret) {
				fprintf(stderr, "post recv error: %d\n", ret);
				goto error;
			}
//			sem_post(&cb->sem);
			break;

		default:
			DEBUG_LOG("unknown!!!!! completion\n");
			ret = -1;
			goto error;
		}
	}
	if (ret) {
		fprintf(stderr, "poll error %d\n", ret);
		goto error;
	}
	return flushed;

error:
	cb->state = ERROR;
//	sem_post(&cb->sem);
	return ret;
}
#endif

static void rping_init_conn_param(struct pingmesh_cb *cb,
				  struct rdma_conn_param *conn_param)
{
	memset(conn_param, 0, sizeof(*conn_param));
	conn_param->responder_resources = 1;
	conn_param->initiator_depth = 1;
	conn_param->retry_count = 7;
	conn_param->rnr_retry_count = 7;
	conn_param->qp_num = cb->qp->qp_num;

	conn_param->private_data = &cb->rdma_info_for_remote; // server's reports it's RDMA buffer details
	conn_param->private_data_len = sizeof(struct pingmesh_rdma_info);
}

static int pingmesh_setup_buffers(struct pingmesh_cb *cb)
{
	int ret;

	cb->rdma_buf = malloc(cb->size);
	if (!cb->rdma_buf) {
		fprintf(stderr, "rdma_buf malloc failed\n");
		ret = -ENOMEM;
		goto err1;
	}

	cb->rdma_mr = ibv_reg_mr(cb->pd, cb->rdma_buf, cb->size,
				 IBV_ACCESS_LOCAL_WRITE |
				 IBV_ACCESS_REMOTE_READ |
				 IBV_ACCESS_REMOTE_WRITE);
	if (!cb->rdma_mr) {
		fprintf(stderr, "rdma_buf reg_mr failed\n");
		ret = errno;
		goto err2;
	}

	cb->rdma_sgl.addr = (uint64_t) (unsigned long) cb->rdma_buf;
	cb->rdma_sgl.lkey = cb->rdma_mr->lkey;
	cb->rdma_sq_wr.send_flags = IBV_SEND_SIGNALED;
	cb->rdma_sq_wr.sg_list = &cb->rdma_sgl;
	cb->rdma_sq_wr.num_sge = 1;

	cb->rdma_info_for_remote.addr = htobe64((uint64_t) (unsigned long) cb->rdma_buf);
	cb->rdma_info_for_remote.size = htobe32(cb->size);
	cb->rdma_info_for_remote.rkey = htobe32(cb->rdma_mr->rkey);

	DEBUG_LOG("allocated & registered buffers...\n");
	return 0;

err2:
	free(cb->rdma_buf);
err1:
	return ret;
}

static void pingmesh_free_buffers(struct pingmesh_cb *cb)
{
	DEBUG_LOG("pingmesh_free_buffers called on cb %p\n", cb);
	ibv_dereg_mr(cb->rdma_mr);
	free(cb->rdma_buf);
}

static int pingmesh_create_qp(struct pingmesh_cb *cb)
{
        struct ibv_qp_init_attr_ex attr_ex;
        struct mlx5dv_qp_init_attr attr_dv;
	int ret = 0;

	/* create DC QP */
	memset(&attr_ex, 0, sizeof(attr_ex));
	memset(&attr_dv, 0, sizeof(attr_dv));

	attr_ex.qp_type = IBV_QPT_DRIVER;
	attr_ex.send_cq = cb->cq;
	attr_ex.recv_cq = cb->cq;

	attr_ex.comp_mask |= IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = cb->pd;

	if (cb->server) {
		/* create DCT */
		attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;
		attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCT;
		attr_dv.dc_init_attr.dct_access_key = DC_KEY;

		attr_ex.srq = cb->srq;

		cb->qp = mlx5dv_create_qp(cb->cm_id->verbs, &attr_ex, &attr_dv);
	}
	else {
		/* create DCI */
		attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;
		attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCI;

		attr_ex.cap.max_send_wr = PING_SQ_DEPTH;
		attr_ex.cap.max_send_sge = 1;

//		attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
//		attr_ex.send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_RDMA_READ;

		attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
		attr_dv.create_flags |= MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE; /*driver doesnt support scatter2cqe data-path on DCI yet*/

		cb->qp = mlx5dv_create_qp(cb->cm_id->verbs, &attr_ex, &attr_dv);
	}

	if (!cb->qp) {
		perror("mlx5dv_create_qp(DC)");
		ret = errno;
		return ret;
	}

	return ret;
}

static int pingmesh_modify_qp(struct pingmesh_cb *cb)
{
	int attr_mask = 0;
	int ret = 0;

	/* modify QP to INIT */
	{
		attr_mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT;

		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = 1
		};

		if (cb->server) {
			attr_mask |= IBV_QP_ACCESS_FLAGS;
			attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | 
					       IBV_ACCESS_REMOTE_READ | 
					       IBV_ACCESS_REMOTE_ATOMIC;
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
			.path_mtu               = IBV_MTU_1024,
			.min_rnr_timer          = 0x10,
			.rq_psn                 = 0,
			.ah_attr                = {
				.is_global      = 1,
				.sl             = 0,
				.src_path_bits  = 0,
				.port_num       = 1,
			}
		};

		if (cb->server) {
			attr_mask |= IBV_QP_MIN_RNR_TIMER;
		}

		if (ibv_modify_qp(cb->qp, &attr, attr_mask)) {
			perror("failed to modify QP to IBV_QPS_RTR");
			ret = errno;
			return ret;
		}
	}

	if (!cb->server) {
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

static void pingmesh_free_qp(struct pingmesh_cb *cb)
{
	if (cb->qp) ibv_destroy_qp(cb->qp);
	if (cb->srq) ibv_destroy_srq(cb->srq);
	ibv_destroy_cq(cb->cq);
	ibv_destroy_comp_channel(cb->channel);
	ibv_dealloc_pd(cb->pd);
}

static int pingmesh_setup_qp(struct pingmesh_cb *cb)
{
        struct ibv_srq_init_attr attr;
        uint32_t srqn;
	int ret;

	cb->pd = ibv_alloc_pd(cb->cm_id->verbs);
	if (!cb->pd) {
		fprintf(stderr, "ibv_alloc_pd failed\n");
		return errno;
	}
	DEBUG_LOG("created pd %p\n", cb->pd);
	
	cb->channel = ibv_create_comp_channel(cb->cm_id->verbs);
	if (!cb->channel) {
		fprintf(stderr, "ibv_create_comp_channel failed\n");
		ret = errno;
		goto err1;
	}
	DEBUG_LOG("created channel %p\n", cb->channel);

	cb->cq = ibv_create_cq(cb->cm_id->verbs, PING_SQ_DEPTH * 2, cb,
				cb->channel, 0);
	if (!cb->cq) {
		fprintf(stderr, "ibv_create_cq failed\n");
		ret = errno;
		goto err2;
	}
	DEBUG_LOG("created cq %p\n", cb->cq);

	ret = ibv_req_notify_cq(cb->cq, 0);
	if (ret) {
		fprintf(stderr, "ibv_create_cq failed\n");
		ret = errno;
		goto err3;
	}

	if (cb->server) 
	{
		memset(&attr, 0, sizeof(attr));
		attr.attr.max_wr = 2;
		attr.attr.max_sge = 1;
		cb->srq = ibv_create_srq(cb->pd, &attr);
		if (!cb->srq) {
			fprintf(stderr, "ibv_create_srq failed\n");
			ret = errno;
			goto err3;
		}

		// ibv_get_srq_num(cb->srq, &srqn);
		DEBUG_LOG("created srq %p\n", cb->srq);
	}

	ret = pingmesh_create_qp(cb);
	if (ret) {
		goto err4;
	}

	ret = pingmesh_modify_qp(cb);
	if (ret) {
		goto err5;
	}

	DEBUG_LOG("created qp %p (qpn=%d)\n", cb->qp, (cb->qp ? cb->qp->qp_num : -1));
	return 0;

err5:
	ibv_destroy_qp(cb->qp);
err4:
	if (cb->srq)
		ibv_destroy_srq(cb->srq);
err3:
	ibv_destroy_cq(cb->cq);
err2:
	ibv_destroy_comp_channel(cb->channel);
err1:
	ibv_dealloc_pd(cb->pd);
	return ret;
}

#if 0
static void *cq_thread(void *arg)
{
	struct pingmesh_cb *cb = arg;
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	int ret;
	
	DEBUG_LOG("cq_thread started.\n");

	while (1) {	
		pthread_testcancel();

		ret = ibv_get_cq_event(cb->channel, &ev_cq, &ev_ctx);
		if (ret) {
			fprintf(stderr, "Failed to get cq event!\n");
			pthread_exit(NULL);
		}
		if (ev_cq != cb->cq) {
			fprintf(stderr, "Unknown CQ!\n");
			pthread_exit(NULL);
		}
		ret = ibv_req_notify_cq(cb->cq, 0);
		if (ret) {
			fprintf(stderr, "Failed to set notify!\n");
			pthread_exit(NULL);
		}
		ret = rping_cq_event_handler(cb);
		ibv_ack_cq_events(cb->cq, 1);
		if (ret)
			pthread_exit(NULL);
	}
}

static void rping_format_send(struct pingmesh_cb *cb, char *buf, struct ibv_mr *mr)
{
	struct rping_rdma_info *info = &cb->send_buf;

	info->buf = htobe64((uint64_t) (unsigned long) buf);
	info->rkey = htobe32(mr->rkey);
	info->size = htobe32(cb->size);

	DEBUG_LOG("RDMA addr %" PRIx64" rkey %x len %d\n",
		  be64toh(info->buf), be32toh(info->rkey), be32toh(info->size));
}
#endif

static int pingmesh_handle_cm_event(struct pingmesh_cb *cb, enum rdma_cm_event_type *cm_event, struct rdma_cm_id **cm_id)
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
        DEBUG_LOG("got cm event: %s(%d) cm_id %p\n", rdma_event_str(event->event), event->event, event->id);

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
			if (event->param.conn.private_data_len >= sizeof(struct pingmesh_rdma_info)) {
				struct pingmesh_rdma_info *rdma_info_from_remote = (struct pingmesh_rdma_info *)event->param.conn.private_data;
//				   cb->rdma_info_for_remote.addr = be64toh((uint64_t) (unsigned long) cb->rdma_buf);
				cb->size = be32toh(rdma_info_from_remote->size);
				cb->rdma_mr->rkey = be32toh(rdma_info_from_remote->rkey);

			DEBUG_LOG("GOT SIZE=%d, RKEY=%d\n", cb->size, cb->rdma_mr->rkey);

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
        if (ret)
                exit(ret);
	return ret;
}

static int pingmesh_bind_server(struct pingmesh_cb *cb)
{
	int ret;
	char str[INET_ADDRSTRLEN];

	if (cb->sin.ss_family == AF_INET) {
		((struct sockaddr_in *) &cb->sin)->sin_port = cb->port;
		inet_ntop(AF_INET, &(((struct sockaddr_in *)&cb->sin)->sin_addr), str, INET_ADDRSTRLEN);
	}
	else {
		((struct sockaddr_in6 *) &cb->sin)->sin6_port = cb->port;
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&cb->sin)->sin6_addr), str, INET_ADDRSTRLEN);
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

	DEBUG_LOG("rdma_bind_addr successful <%s, %d>\n", str, be16toh(cb->port));

	DEBUG_LOG("rdma_listen\n");
	ret = rdma_listen(cb->cm_id, 3);
	if (ret) {
		perror("rdma_listen");
		return ret;
	}

	return 0;
}

static void free_cb(struct pingmesh_cb *cb)
{
	free(cb);
}

static int pingmesh_run_server(struct pingmesh_cb *cb)
{
	int ret;

	ret = pingmesh_bind_server(cb);
	if (ret)
		return ret;

	ret = pingmesh_setup_qp(cb);
	if (ret) {
		fprintf(stderr, "setup_qp failed: %d\n", ret);
		return ret;
	}

	ret = pingmesh_setup_buffers(cb);
	if (ret) {
		fprintf(stderr, "setup_buffers failed: %d\n", ret);
		goto err1;
	}

	// main loop:
	// 	wait for CONN REQ
	// 	accept with dctn and MKey
	while (1)
	{
		struct rdma_cm_id *cm_id;
		struct rdma_cm_event event;
		enum rdma_cm_event_type cm_event;

		DEBUG_LOG("waiting for client events ...\n");
		ret = pingmesh_handle_cm_event(cb, &cm_event, &cm_id);
		switch (cm_event) {

			case RDMA_CM_EVENT_CONNECT_REQUEST:
				DEBUG_LOG("accepting client connection request (cm_id %p)\n", cm_id);
				// ALEXR: reply with dctn and MKey

				struct rdma_conn_param conn_param;
				rping_init_conn_param(cb, &conn_param);
				ret = rdma_accept(cm_id, &conn_param);
				if (ret) {
					perror("rdma_accept");
					return ret;
				}
				break;

			case RDMA_CM_EVENT_ESTABLISHED:
				DEBUG_LOG("client connection established (cm_id %p)\n", cm_id);
				break;

			case RDMA_CM_EVENT_DISCONNECTED:
				DEBUG_LOG("%s DISCONNECT EVENT (cm_id %p)\n", cb->server ? "server" : "client", cm_id);
				rdma_disconnect(cm_id);
				rdma_destroy_id(cm_id);
				break;

			default:
				fprintf(stderr, "server unexpected event: %s (%d)\n", rdma_event_str(cm_event), cm_event);
				exit(1);
				break;
		}
	}


	ret = 0;
err2:
	pingmesh_free_buffers(cb);
err1:
	pingmesh_free_qp(cb);

	return ret;
}

static int pingmesh_test_client(struct pingmesh_cb *cb)
{
	int ping, start, cc, i, ret = 0;
	struct ibv_send_wr *bad_wr;
	unsigned char c;

//ALEXR Handle cq: code from cq_thread
#if 0
	start = 65;
	for (ping = 0; !cb->count || ping < cb->count; ping++) {
		cb->state = RDMA_READ_ADV;

		/* Put some ascii text in the buffer. */
		cc = snprintf(cb->start_buf, cb->size, PING_MSG_FMT, ping);
		for (i = cc, c = start; i < cb->size; i++) {
			cb->start_buf[i] = c;
			c++;
			if (c > 122)
				c = 65;
		}
		start++;
		if (start > 122)
			start = 65;
		cb->start_buf[cb->size - 1] = 0;

		rping_format_send(cb, cb->start_buf, cb->start_mr);
		ret = ibv_post_send(cb->qp, &cb->sq_wr, &bad_wr);
		if (ret) {
			fprintf(stderr, "post send error %d\n", ret);
			break;
		}

		/* Wait for server to ACK */
		sem_wait(&cb->sem);
		if (cb->state != RDMA_WRITE_ADV) {
			fprintf(stderr, "wait for RDMA_WRITE_ADV state %d\n",
				cb->state);
			ret = -1;
			break;
		}

		rping_format_send(cb, cb->rdma_buf, cb->rdma_mr);
		ret = ibv_post_send(cb->qp, &cb->sq_wr, &bad_wr);
		if (ret) {
			fprintf(stderr, "post send error %d\n", ret);
			break;
		}

		/* Wait for the server to say the RDMA Write is complete. */
		sem_wait(&cb->sem);
		if (cb->state != RDMA_WRITE_COMPLETE) {
			fprintf(stderr, "wait for RDMA_WRITE_COMPLETE state %d\n",
				cb->state);
			ret = -1;
			break;
		}

		if (cb->verbose)
			printf("ping data: %s\n", cb->rdma_buf);
	}

	return (cb->state == DISCONNECTED) ? 0 : ret;
#endif
	return -1;
}

static int pingmesh_connect_client(struct pingmesh_cb *cb)
{
	int ret;
	struct rdma_cm_id *cm_id;
	enum rdma_cm_event_type cm_event;
	struct rdma_conn_param conn_param;

	DEBUG_LOG("rdma_connecting...\n");
	rping_init_conn_param(cb, &conn_param);
	ret = rdma_connect(cb->cm_id, &conn_param);
	if (ret) {
		perror("rdma_connect");
		return ret;
	}

	ret = pingmesh_handle_cm_event(cb, &cm_event, &cm_id);
	if (cm_event != RDMA_CM_EVENT_CONNECT_RESPONSE) {
		return -1;
	}

	ret = rdma_establish(cb->cm_id);
	if (ret) {
		perror("rdma_establish");
		return ret;
	}

	DEBUG_LOG("rdma_connect successful\n");
	return 0;
}

static int pingmesh_bind_client(struct pingmesh_cb *cb)
{
	int ret;
	struct rdma_cm_id *cm_id;
	enum rdma_cm_event_type cm_event;       

	if (cb->sin.ss_family == AF_INET)
		((struct sockaddr_in *) &cb->sin)->sin_port = cb->port;
	else
		((struct sockaddr_in6 *) &cb->sin)->sin6_port = cb->port;

	if (cb->ssource.ss_family) 
		ret = rdma_resolve_addr(cb->cm_id, (struct sockaddr *) &cb->ssource,
				(struct sockaddr *) &cb->sin, 2000);
	else
		ret = rdma_resolve_addr(cb->cm_id, NULL, (struct sockaddr *) &cb->sin, 2000);

	if (ret) {
		perror("rdma_resolve_addr");
		return ret;
	}

	ret = pingmesh_handle_cm_event(cb, &cm_event, &cm_id);
	if (cm_event != RDMA_CM_EVENT_ADDR_RESOLVED) {
		return -1;
	}

	ret = rdma_resolve_route(cb->cm_id, 2000);
	if (ret) {
		perror("rdma_resolve_route");
	}

	ret = pingmesh_handle_cm_event(cb, &cm_event, &cm_id);
	if (cm_event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
		return -1;
	}

	DEBUG_LOG("rdma_resolve_addr/rdma_resolve_route successful\n");
	return 0;
}

static int pingmesh_run_client(struct pingmesh_cb *cb)
{
	int ret;

	ret = pingmesh_bind_client(cb);
	if (ret)
		return ret;

	ret = pingmesh_setup_qp(cb);
	if (ret) {
		fprintf(stderr, "setup_qp failed: %d\n", ret);
		return ret;
	}

	ret = pingmesh_setup_buffers(cb);
	if (ret) {
		fprintf(stderr, "rping_setup_buffers failed: %d\n", ret);
		goto err1;
	}

	ret = pingmesh_connect_client(cb);
	if (ret) {
		fprintf(stderr, "connect error %d\n", ret);
		goto err2;
	}

	ret = pingmesh_test_client(cb);
	if (ret) {
		fprintf(stderr, "rping client failed: %d\n", ret);
		goto err3;
	}

	ret = 0;
err3:
	rdma_disconnect(cb->cm_id);
err2:
	pingmesh_free_buffers(cb);
err1:
	pingmesh_free_qp(cb);

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

static void usage(const char *name)
{
	printf("%s -s [-vVd] [-S size] [-C count] [-a addr] [-p port]\n", 
	       basename(name));
	printf("%s -c [-vVd] [-S size] [-C count] [-I addr] -a addr [-p port]\n", 
	       basename(name));
	printf("\t-c\t\tclient side\n");
	printf("\t-I\t\tSource address to bind to for client.\n");
	printf("\t-s\t\tserver side.  To bind to any address with IPv6 use -a ::0\n");
	printf("\t-v\t\tdisplay ping data to stdout\n");
	printf("\t-d\t\tdebug printfs\n");
	printf("\t-S size \tping data size\n");
	printf("\t-C count\tping count times\n");
	printf("\t-a addr\t\taddress\n");
	printf("\t-p port\t\tport\n");
}

int main(int argc, char *argv[])
{
	struct pingmesh_cb *cb;
	int op;
	int ret = 0;

	cb = malloc(sizeof(*cb));
	if (!cb)
		return -ENOMEM;

	memset(cb, 0, sizeof(*cb));
	cb->server = -1;
	cb->size = 64;
	cb->sin.ss_family = PF_INET;
	cb->port = htobe16(7174);

	opterr = 0;
	while ((op = getopt(argc, argv, "a:I:p:C:S:t:scvd")) != -1) {
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
			cb->server = 1;
			DEBUG_LOG("server\n");
			break;
		case 'c':
			cb->server = 0;
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
			if (cb->count < 0) {
				fprintf(stderr, "Invalid count %d\n",
					cb->count);
				ret = EINVAL;
			} else
				DEBUG_LOG("count %d\n", (int) cb->count);
			break;
		case 'v':
			cb->verbose++;
			DEBUG_LOG("verbose\n");
			break;
		case 'd':
			debug++;
			break;
		default:
			usage("rping");
			ret = EINVAL;
			goto out;
		}
	}
	if (ret)
		goto out;

	if (cb->server == -1) {
		usage("rping");
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

	if (cb->server) {
		ret = pingmesh_run_server(cb);
	} else {
		ret = pingmesh_run_client(cb);
	}

	DEBUG_LOG("destroy cm_id %p\n", cb->cm_id);
	rdma_destroy_id(cb->cm_id);
out2:
	rdma_destroy_event_channel(cb->cm_channel);
out:
	free(cb);
	return ret;
}
