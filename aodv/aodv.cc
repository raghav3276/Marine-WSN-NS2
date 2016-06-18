/*
 Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
 Reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote products
 derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

 */

//#include <ip.h>

#include <aodv/aodv.h>
#include <aodv/aodv_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <energy-model.h>

#define max(a,b)        ( (a) > (b) ? (a) : (b) )
#define CURRENT_TIME    Scheduler::instance().clock()

//#define DEBUG
//#define ERROR

//#define EXOR_DBG


#ifdef DEBUG
static int extra_route_reply = 0;
static int limit_route_request = 0;
static int route_request = 0;
#endif

/*
 TCL Hooks
 */

//--------- exor -- 
//should be changed according to tcl file
#define BANDWIDTH 1000000
#define MAC_HDR  80	// 52
#define IP_HDR   20
#define PAY_LOAD 512    //1024 yanhua modified cbr size to 512 too, and totally pkt size is 612 now
#define MAX_WAIT 1000
//the time it takes the device to transmit a pkt (in sec)
#define ONE_PKT_TIME ((double)(PAY_LOAD+IP_HDR+MAC_HDR)/(double) (BANDWIDTH/8))
//the measured time from ns-2 is around 0.003 sec / packet
//--------- exor


int hdr_aodv::offset_;
static class AODVHeaderClass: public PacketHeaderClass {
public:
	AODVHeaderClass() :
		PacketHeaderClass("PacketHeader/AODV", sizeof(hdr_all_aodv)) {
		bind_offset(&hdr_aodv::offset_);
	}
} class_rtProtoAODV_hdr;

static class AODVclass: public TclClass {
public:
	AODVclass() :
		TclClass("Agent/AODV") {
	}
	TclObject* create(int argc, const char* const * argv) {
		assert(argc == 5);
		//return (new AODV((nsaddr_t) atoi(argv[4])));
		return (new AODV((nsaddr_t) Address::instance().str2addr(argv[4])));
	}
} class_rtProtoAODV;

int AODV::command(int argc, const char* const * argv) {
	if (argc == 2) {
		Tcl& tcl = Tcl::instance();

		if (strncasecmp(argv[1], "id", 2) == 0) {
			tcl.resultf("%d", index);
			return TCL_OK;
		}

		if (strncasecmp(argv[1], "start", 2) == 0) {
			btimer.handle((Event*) 0);

#ifndef AODV_LINK_LAYER_DETECTION
			htimer.handle((Event*) 0);
			ntimer.handle((Event*) 0);
#endif // LINK LAYER DETECTION
			rtimer.handle((Event*) 0);
			return TCL_OK;
		}
	} else if (argc == 3) {
		if (strcmp(argv[1], "index") == 0) {
			index = atoi(argv[2]);
			return TCL_OK;
		}

		else if (strcmp(argv[1], "log-target") == 0 || strcmp(argv[1],
				"tracetarget") == 0) {
			logtarget = (Trace*) TclObject::lookup(argv[2]);
			if (logtarget == 0)
				return TCL_ERROR;
			return TCL_OK;
		} else if (strcmp(argv[1], "drop-target") == 0) {
			int stat = rqueue.command(argc, argv);
			if (stat != TCL_OK)
				return stat;
			return Agent::command(argc, argv);
		} else if (strcmp(argv[1], "if-queue") == 0) {
			ifqueue = (PriQueue*) TclObject::lookup(argv[2]);

			if (ifqueue == 0)
				return TCL_ERROR;
			return TCL_OK;
		} else if (strcmp(argv[1], "port-dmux") == 0) {
			dmux_ = (PortClassifier *) TclObject::lookup(argv[2]);
			if (dmux_ == 0) {
				fprintf(stdout, "%s: %s lookup of %s failed\n", __FILE__,
						argv[1], argv[2]);
				return TCL_ERROR;
			}
			return TCL_OK;
		}
	}
	return Agent::command(argc, argv);
}

/* 
 Constructor
 */

AODV::AODV(nsaddr_t id) :
	Agent(PT_AODV), fTimer(this), btimer(this), htimer(this), ntimer(this),
			rtimer(this), lrtimer(this), rqueue() {

	index = id;
	seqno = 2;
	bid = 1;

	LIST_INIT(&nbhead);
	LIST_INIT(&bihead);

	logtarget = 0;
	ifqueue = 0;

	//--exor
	lastReceivedFragNum = -1; //meaning no pkt received yet
	lastReceivedTime = -1.;
	curRate = -1.;
	localBatchMap[0] = -1; //indicating it is not init-ed yet for the new batch
	BatchId = -1;// indicating ready for new batch and 

	nextBatchId = -1;
	pktNum = -1;

	curNode = -1; //no cur Sending node initially
	//resetForwardingTimer(MAX_WAIT*ONE_PKT_TIME);


	//init local packet buffer
	for (int i = 0; i < BATCH_SIZE; i++)
		packetBuffer[i] = false;
	ackReady = false;
	//---------------yanhua-0304--------------------
	// readRM();
	read_orderRM();
	//---------------yanhua-0304--------------------
	//--exor
}

int AODV::getNextBatchId() {
	nextBatchId++;
	return nextBatchId;
}

int AODV::getNextPktNum() {
	pktNum++;
	return pktNum;
}

/*
 Timers
 */

void BroadcastTimer::handle(Event*) {
	/*agent->id_purge();
	 Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);
	 */
}

void HelloTimer::handle(Event*) {
	/*agent->sendHello();
	 double interval = MinHelloInterval +
	 ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
	 assert(interval >= 0);
	 Scheduler::instance().schedule(this, &intr, interval);*/
}

void NeighborTimer::handle(Event*) {
	/*
	 agent->nb_purge();
	 Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);
	 */
}

void RouteCacheTimer::handle(Event*) {
	/*
	 agent->rt_purge();
	 #define FREQUENCY 0.5 // sec
	 Scheduler::instance().schedule(this, &intr, FREQUENCY);
	 */
}

//---exor
void ForwardingTimer::expire(Event* e) {
	//first send all fragments
	//fprintf(stdout,"Node %d  ------ Timer fires at %f ---- \n",agent->index, CURRENT_TIME);
	agent->transmitAllFragments();
	//reschedule the timer
	//Scheduler::instance().schedule(this, &intr, MAX_WAIT*ONE_PKT_TIME);
	resched((double) (MAX_WAIT * ONE_PKT_TIME));
	//listen for a while, can be shortened, how long to wait for next round if no pkt recevied anymore
}
//--- exor

void LocalRepairTimer::handle(Event* p) { // SRD: 5/4/99
	aodv_rt_entry *rt;
	struct hdr_ip *ih = HDR_IP( (Packet *)p);

	/* you get here after the timeout in a local repair attempt */
	/*	fprintf(stdout, "%s\n", __FUNCTION__); */

	rt = agent->rtable.rt_lookup(ih->daddr());

	if (rt && rt->rt_flags != RTF_UP) {
		// route is yet to be repaired
		// I will be conservative and bring down the route
		// and send route errors upstream.
		/* The following assert fails, not sure why */
		/* assert (rt->rt_flags == RTF_IN_REPAIR); */

		//rt->rt_seqno++;
		agent->rt_down(rt);
		// send RERR
#ifdef DEBUG
		fprintf(stdout,"Node %d: Dst - %d, failed local repair\n",index, rt->rt_dst);
#endif      
	}
	Packet::free((Packet *) p);
}

/*
 Broadcast ID Management  Functions
 */

void AODV::id_insert(nsaddr_t id, u_int32_t bid) {
	BroadcastID *b = new BroadcastID(id, bid);

	assert(b);
	b->expire = CURRENT_TIME + BCAST_ID_SAVE;
	LIST_INSERT_HEAD(&bihead, b, link);
}

/* SRD */
bool AODV::id_lookup(nsaddr_t id, u_int32_t bid) {
	BroadcastID *b = bihead.lh_first;

	// Search the list for a match of source and bid
	for (; b; b = b->link.le_next) {
		if ((b->src == id) && (b->id == bid))
			return true;
	}
	return false;
}

void AODV::id_purge() {
	BroadcastID *b = bihead.lh_first;
	BroadcastID *bn;
	double now = CURRENT_TIME;

	for (; b; b = bn) {
		bn = b->link.le_next;
		if (b->expire <= now) {
			LIST_REMOVE(b,link);
			delete b;
		}
	}
}

/*
 Helper Functions
 */

double AODV::PerHopTime(aodv_rt_entry *rt) {
	int num_non_zero = 0, i;
	double total_latency = 0.0;

	if (!rt)
		return ((double) NODE_TRAVERSAL_TIME);

	for (i = 0; i < MAX_HISTORY; i++) {
		if (rt->rt_disc_latency[i] > 0.0) {
			num_non_zero++;
			total_latency += rt->rt_disc_latency[i];
		}
	}
	if (num_non_zero > 0)
		return (total_latency / (double) num_non_zero);
	else
		return ((double) NODE_TRAVERSAL_TIME);

}

/*
 Link Failure Management Functions
 */

static void aodv_rt_failed_callback(Packet *p, void *arg) {
	((AODV*) arg)->rt_ll_failed(p);
}

/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void AODV::rt_ll_failed(Packet *p) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	aodv_rt_entry *rt;
	nsaddr_t broken_nbr = ch->next_hop_;

#ifndef AODV_LINK_LAYER_DETECTION
	drop(p, DROP_RTR_MAC_CALLBACK);
#else 

	/*
	 * Non-data packets and Broadcast Packets can be dropped.
	 */
	if (!DATA_PACKET(ch->ptype()) || (u_int32_t) ih->daddr() == IP_BROADCAST) {
		drop(p, DROP_RTR_MAC_CALLBACK);
		return;
	}
	log_link_broke(p);
	if ((rt = rtable.rt_lookup(ih->daddr())) == 0) {
		drop(p, DROP_RTR_MAC_CALLBACK);
		return;
	}
	log_link_del(ch->next_hop_);

#ifdef AODV_LOCAL_REPAIR
	/* if the broken link is closer to the dest than source,
	 attempt a local repair. Otherwise, bring down the route. */

	if (ch->num_forwards() > rt->rt_hops) {
		local_rt_repair(rt, p); // local repair
		// retrieve all the packets in the ifq using this link,
		// queue the packets for which local repair is done,
		return;
	} else
#endif // LOCAL REPAIR	
	{
		drop(p, DROP_RTR_MAC_CALLBACK);
		// Do the same thing for other packets in the interface queue using the
		// broken link -Mahesh
		while ((p = ifqueue->filter(broken_nbr))) {
			drop(p, DROP_RTR_MAC_CALLBACK);
		}
		nb_delete(broken_nbr);
	}

#endif // LINK LAYER DETECTION
}

void AODV::handle_link_failure(nsaddr_t id) {
	aodv_rt_entry *rt, *rtn;
	Packet *rerr = Packet::alloc();
	struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);

	re->DestCount = 0;
	for (rt = rtable.head(); rt; rt = rtn) { // for each rt entry
		rtn = rt->rt_link.le_next;
		if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id)) {
			assert (rt->rt_flags == RTF_UP);
			assert((rt->rt_seqno%2) == 0);
			rt->rt_seqno++;
			re->unreachable_dst[re->DestCount] = rt->rt_dst;
			re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
			fprintf(stdout, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
					index, re->unreachable_dst[re->DestCount],
					re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
			re->DestCount += 1;
			rt_down(rt);
		}
		// remove the lost neighbor from all the precursor lists
		rt->pc_delete(id);
	}

	if (re->DestCount > 0) {
#ifdef DEBUG
		fprintf(stdout, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
		sendError(rerr, false);
	} else {
		Packet::free(rerr);
	}
}

void AODV::local_rt_repair(aodv_rt_entry *rt, Packet *p) {
#ifdef DEBUG
	fprintf(stdout,"%s: Dst - %d\n", __FUNCTION__, rt->rt_dst);
#endif  
	// Buffer the packet
	rqueue.enque(p);

	// mark the route as under repair
	rt->rt_flags = RTF_IN_REPAIR;

	sendRequest(rt->rt_dst);

	// set up a timer interrupt
	Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);
}

void AODV::rt_update(aodv_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
		nsaddr_t nexthop, double expire_time) {

	rt->rt_seqno = seqnum;
	rt->rt_hops = metric;
	rt->rt_flags = RTF_UP;
	rt->rt_nexthop = nexthop;
	rt->rt_expire = expire_time;
}

void AODV::rt_down(aodv_rt_entry *rt) {
	/*
	 *  Make sure that you don't "down" a route more than once.
	 */

	if (rt->rt_flags == RTF_DOWN) {
		return;
	}

	// assert (rt->rt_seqno%2); // is the seqno odd?
	rt->rt_last_hop_count = rt->rt_hops;
	rt->rt_hops = INFINITY2;
	rt->rt_flags = RTF_DOWN;
	rt->rt_nexthop = 0;
	rt->rt_expire = 0;

} /* rt_down function */

/*
 Route Handling Functions
 */

void AODV::rt_resolve(Packet *p) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	aodv_rt_entry *rt;

	/*
	 *  Set the transmit failure callback.  That
	 *  won't change.
	 */
	ch->xmit_failure_ = aodv_rt_failed_callback;
	ch->xmit_failure_data_ = (void*) this;
	rt = rtable.rt_lookup(ih->daddr());
	if (rt == 0) {
		rt = rtable.rt_add(ih->daddr());
	}

	/*
	 * If the route is up, forward the packet
	 */

	if (rt->rt_flags == RTF_UP) {
		assert(rt->rt_hops != INFINITY2);
		forward(rt, p, NO_DELAY);
	}
	/*
	 *  if I am the source of the packet, then do a Route Request.
	 */
	else if (ih->saddr() == index) {
		rqueue.enque(p);
		sendRequest(rt->rt_dst);
	}
	/*
	 *	A local repair is in progress. Buffer the packet.
	 */
	else if (rt->rt_flags == RTF_IN_REPAIR) {
		rqueue.enque(p);
	}

	/*
	 * I am trying to forward a packet for someone else to which
	 * I don't have a route.
	 */
	else {
		Packet *rerr = Packet::alloc();
		struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);
		/*
		 * For now, drop the packet and send error upstream.
		 * Now the route errors are broadcast to upstream
		 * neighbors - Mahesh 09/11/99
		 */

		assert (rt->rt_flags == RTF_DOWN);
		re->DestCount = 0;
		re->unreachable_dst[re->DestCount] = rt->rt_dst;
		re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
		re->DestCount += 1;
#ifdef DEBUG
		fprintf(stdout, "%s: sending RERR...\n", __FUNCTION__);
#endif
		sendError(rerr, false);

		drop(p, DROP_RTR_NO_ROUTE);
	}

}

void AODV::rt_purge() {
	aodv_rt_entry *rt, *rtn;
	double now = CURRENT_TIME;
	double delay = 0.0;
	Packet *p;

	for (rt = rtable.head(); rt; rt = rtn) { // for each rt entry
		rtn = rt->rt_link.le_next;
		if ((rt->rt_flags == RTF_UP) && (rt->rt_expire < now)) {
			// if a valid route has expired, purge all packets from
			// send buffer and invalidate the route.
			assert(rt->rt_hops != INFINITY2);
			while ((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
				fprintf(stdout, "%s: calling drop()\n",
						__FUNCTION__);
#endif // DEBUG
				drop(p, DROP_RTR_NO_ROUTE);
			}
			rt->rt_seqno++;
			assert (rt->rt_seqno%2);
			rt_down(rt);
		} else if (rt->rt_flags == RTF_UP) {
			// If the route is not expired,
			// and there are packets in the sendbuffer waiting,
			// forward them. This should not be needed, but this extra
			// check does no harm.
			assert(rt->rt_hops != INFINITY2);
			while ((p = rqueue.deque(rt->rt_dst))) {
				forward(rt, p, delay);
				delay += ARP_DELAY;
			}
		} else if (rqueue.find(rt->rt_dst))
			// If the route is down and
			// if there is a packet for this destination waiting in
			// the sendbuffer, then send out route request. sendRequest
			// will check whether it is time to really send out request
			// or not.
			// This may not be crucial to do it here, as each generated
			// packet will do a sendRequest anyway.

			sendRequest(rt->rt_dst);
	}

}

//---------------exor
/*
 Forward Timer
 Estimate the data transmission rate of a node (of higher priority)
 this function should be called only if this node is within the forwarderlist
 */
double AODV::estimateDataRate(Packet * p) {

#define alpha 0.9
	//cur imp not efficient but easy to debug

	double curTime = CURRENT_TIME;

#ifdef EXOR_DBG
	//fprintf(stdout, "%s: cur time = %f\n", __FUNCTION__, curTime);
#endif 

	struct hdr_cmn *ch = HDR_CMN(p);
	if (curNode != ch->sender_addr) //new sending node, restart estimation process
	{
		curNode = ch->sender_addr;
		lastReceivedTime = curTime;
		lastReceivedFragNum = ch->FragNum;
		curRate = -1.0; //not ready to give estimate
		return curRate;
	}

	//now it must be at least the 2nd pkt from the same sender
	//we are ready to estimate
	if ((lastReceivedFragNum >= 0) && (lastReceivedTime >= 0))//for safety
	{
		int numPktLeft = ch->FragNum - lastReceivedFragNum;
		if (numPktLeft < 0)
			numPktLeft = 0;
		//double curTime = CURRENT_TIME;
		//assert((curTime - lastReceivedTime) > 0.000001);
		if ((curTime - lastReceivedTime) < 0.000001)
			return curRate; //no need to process this pkt (caused by ns-2)
		double rate = (double) numPktLeft / (double) (curTime
				- lastReceivedTime);

		//fprintf(stdout, "%s:  numPktLeft, curTime-lastReceivedTime = %d:%f !!!\n", 
		// __FUNCTION__, numPktLeft, curTime-lastReceivedTime);


		//EWMA
		if (curRate > 0.)
			curRate = alpha * rate + (1. - alpha) * curRate;
		else
			curRate = rate; //first rate estimation

	}

	lastReceivedTime = curTime;
	lastReceivedFragNum = ch->FragNum;

#ifdef EXOR_DBG
	fprintf(stdout, "%s: cur rate = %f\n",
			__FUNCTION__, curRate);
#endif

	if (ch->FragNum == (ch->FragSz - 1)) //already last pkt
		curNode = -1;//mark for next estimation, needed to distinguish two sending sessions of the same node

	return curRate;//negative number means not sufficient info to compute rate

}

bool AODV::shouldParticipate(Packet *p) {
	bool should = false;
	struct hdr_cmn *ch = HDR_CMN(p);
	VecAddr::iterator it;

	for (int i = 0; i < ch->FwdListSize; i++) {
		if (ch->F_List[i] == index) {
			should = true;
			break;
		}
	}

	return should;
}

int AODV::getPriority(nsaddr_t nid) //lower numer --> higher priority
{
	MapInt::iterator it = localForwarderMap.find(nid);
	return it->second;
}

bool AODV::updateLocalBatchMap(Packet *p) {
	bool changed = false;
	struct hdr_cmn *ch = HDR_CMN(p);
	int i;
	//receivedBatchMap = ch->BatchMap;
	//int curPriority, rP;

	if (localBatchMap[0] < 0) //indicating the map is not inited yet
	{
		for (i = 0; i < BATCH_SIZE; i++) {
			localBatchMap[i] = ch->BatchMap[i];
		}
		changed = true;
	} else {
		for (i = 0; i < BATCH_SIZE; i++) {
			if (getPriority(ch->BatchMap[i]) < getPriority(localBatchMap[i])) {
				localBatchMap[i] = ch->BatchMap[i];
				changed = true;
			}
		}
	}
	/*
	 #ifdef EXOR_DBG
	 //fprintf(stdout, "%s:  ------- done !!! ---------\n", __FUNCTION__);
	 for(int j=0;j<BATCH_SIZE;j++)
	 fprintf(stdout, "%s:  batchmap for pktNums %d  = %d !!!\n", __FUNCTION__, j, localBatchMap[j]);
	 #endif // DEBUG
	 */
	return changed;
}

Packet *
AODV::createAck(Packet *op, int fragNum) {
	struct hdr_cmn *cho = HDR_CMN(op);
	//struct hdr_ip *iho = HDR_IP(op);

	Packet * p = allocpkt();
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);

	//copy/set general fields
	ch->ptype_ = cho->ptype_;
	ch->direction() = hdr_cmn::DOWN;//important
	ch->size() = cho->size();
	ch->error() = 0;
	ch->next_hop() = IP_BROADCAST;//important
	ch->addr_type() = NS_AF_INET;

	ih->saddr() = index; //key
	ih->daddr() = IP_BROADCAST; //key
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl() = IP_DEF_TTL;

	//set fields specfic for exor, complete copy
	//ch->Ver = cho->Ver;
	//ch->HdrLen = cho->HdrLen;
	ch->BatchId = cho->BatchId;
	ch->PktNum = cho->PktNum;
	ch->BatchSz = cho->BatchSz;
	ch->FragNum = fragNum;
	ch->FragSz = ACK_SIZE;
	ch->FwdListSize = cho->FwdListSize;
	ch->ForwardernNum = cho->ForwardernNum;
	for (int i = 0; i < MAX_FWDER; i++)
		ch->F_List[i] = cho->F_List[i];
	for (int i = 0; i < BATCH_SIZE; i++)
		ch->BatchMap[i] = cho->BatchMap[i];
	//ch->checksum = cho->checksum;
	ch->sender_addr = index;
	ch->PayloadLen = 0;

	return p;
}

void AODV::updateLocalPacketBuffer(Packet *p) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);

	if (BatchId < 0) {
		BatchId = ch->BatchId;
		//first time, the local ForwarderList needs to be updated
		if (localForwarderList.size() <= 0) {
			for (int i = 0; i < ch->FwdListSize; i++)
				localForwarderList.push_back(ch->F_List[i]);
		}

		//for dest node only, the first time receiving a pkt, populate the ack array
		if (ih->daddr() == index) {
			for (int i = 0; i < ACK_SIZE; i++) {
				acks[i] = createAck(p, i);
			}
			ackReady = true;
		}
	}

	if ((ch->PayloadLen != 0) && (packetBuffer[ch->PktNum] == false)) {
		packetBuffer[ch->PktNum] = true;
		pBuffer[ch->PktNum] = copyPacket(p); //create a new one and drop the old one, only the first time
	}

	//set local batch map for this particular pkt
	int thisP = getPriority(index); //this node's priority
	if (getPriority(localBatchMap[ch->PktNum]) > thisP)
		localBatchMap[ch->PktNum] = index; //save the cur node id

	/*
	 #ifdef EXOR_DBG
	 fprintf(stdout, "%s:  done !!!\n", __FUNCTION__);
	 for(int j=0;j<BATCH_SIZE;j++)
	 if(packetBuffer[j])
	 fprintf(stdout, "%s:  recevied pktNums include %d  !!!\n", __FUNCTION__, j);

	 #endif // DEBUG
	 */

}

bool AODV::curBatchCompleted() {
#ifdef EXOR_DBG
	// fprintf(stdout, "%s:  done !!!\n", __FUNCTION__);
#endif // DEBUG  
	int count = 0;
	int thisP = getPriority(index); //this node's priority
	for (int i = 0; i < BATCH_SIZE; i++) {
		if (getPriority(localBatchMap[i]) < thisP) //already received by higher priority nodes
			count++;
	}

#ifdef EXOR_DBG
	//fprintf(stdout, "%s:  done !!!\n", __FUNCTION__);
#endif // DEBUG  
	return ((count / BATCH_SIZE) >= COMPLETION_RATIO);
}

bool AODV::needTransmit(int pNum) {
	if (packetBuffer[pNum] == false)
		return false;
	int thisP = getPriority(index); //this node's priority
	if (getPriority(localBatchMap[pNum]) >= thisP)
		return true;
	return false;
}

int AODV::getFragmentSize() //it sets up  the first one already
{
	fragSize = 0;
	nextFragNum = -1;
	for (int i = 0; i < BATCH_SIZE; i++) {
		if (needTransmit(i)) {
			if (nextFragNum < 0) {
				nextFragNum = 0;
				nextPktNum = i;
			}

			fragSize++;
		}
	}

	return fragSize;
}

int AODV::getNextFragment() {

	int tmp = nextPktNum;

	if (nextPktNum == (BATCH_SIZE - 1)) //already last one
	{
		nextPktNum = -1;
		return nextPktNum;
	}

	for (int i = nextPktNum + 1; i < BATCH_SIZE; i++) {
		if (needTransmit(i)) {
			nextFragNum++;
			nextPktNum = i;
			break;
		}
	}

	if (nextPktNum == tmp) //indicating no more pkt to be send for this batch
	{
		nextPktNum = -1;
	}

	return nextPktNum;

}

int AODV::getForwarderNum() {
	//make sure local f list was inited...

	int i = 0;
	int s = localForwarderList.size();
	for (i = 0; i < s; i++) {
		if (localForwarderList[i] == index)
			return i;
	}
	return -1;//If the sending node is not in the forwarder list
	//It should forward the packet, so it should not happend. comments by yanhua.
}

Packet *
AODV::preparePacket(int pNum, int fragNum, int fSz) {

	if (ackReady) { //the ack packet to be sent by dest
		struct hdr_cmn *ch = HDR_CMN(acks[fragNum]);
		//struct hdr_ip* ih = HDR_IP(acks[fragNum]);

		//set fields specfic for exor
		ch->FragNum = fragNum;
		ch->FragSz = fSz;
		ch->ForwardernNum = getForwarderNum();
		for (int i = 0; i < BATCH_SIZE; i++)
			ch->BatchMap[i] = localBatchMap[i];
		ch->sender_addr = index; //important for rate estimation


		//set general fields
		ch->direction() = hdr_cmn::DOWN; //important
		ch->size() = IP_HDR + MAC_HDR;
		ch->error() = 0;
		ch->next_hop() = IP_BROADCAST; //important
		ch->addr_type() = NS_AF_INET;

		return acks[fragNum];
	} else {
		struct hdr_cmn *ch = HDR_CMN(pBuffer[pNum]);
		struct hdr_ip* ih = HDR_IP(pBuffer[pNum]);

		//set fields specfic for exor
		ch->FragNum = fragNum;
		ch->FragSz = fSz;
		ch->ForwardernNum = getForwarderNum();
		for (int i = 0; i < BATCH_SIZE; i++)
			ch->BatchMap[i] = localBatchMap[i];
		ch->sender_addr = index; //important for rate estimation


		if (ih->daddr() == here_.addr_) {
			ih->daddr() = IP_BROADCAST;
			ch->PayloadLen = 0; //if it dest node, only broadcast batch map
		} else
			ch->PayloadLen = PAY_LOAD;

		//set general fields
		ch->direction() = hdr_cmn::DOWN; //important
		ch->size() = IP_HDR + MAC_HDR + PAY_LOAD;
		ch->error() = 0;
		ch->next_hop() = IP_BROADCAST; //important
		ch->addr_type() = NS_AF_INET;

		return pBuffer[pNum];
	}
}

#define RATE_TH 0.000001
double AODV::computeBackOffTime(Packet *pkt) {
	//check the forwarder list and find the position of the curNode
	//compute the expected needed time for curNode
	// for each other node 5 pkt durations


	struct hdr_cmn *ch = HDR_CMN(pkt);
	VecAddr::iterator it;
	if (localForwarderList.size() == 0) //non-inited yet, localforwarderlist should be cleared when a new batch is in effect
	{//save a local copy	

		for (int i = 0; i < ch->FwdListSize; i++) //it is acutally an array
		{
			localForwarderList.push_back(ch->F_List[i]);
			localForwarderMap.insert(std::make_pair(ch->F_List[i], i));

		}

	}

	assert(localForwarderList.size()>0);

	double backoffTime = 0;
	double defaultBackoffTime = 5 * ONE_PKT_TIME; //
	bool shouldCount = true; //check all higher priorty nodes
	for (it = localForwarderList.begin(); it < localForwarderList.end(); ++it) {

		//fprintf(stdout, "%s:  inside loop (*it) = %d!!!\n", __FUNCTION__, (*it));

		if (shouldCount)//handles all nodes w/ higher priorty
		{
			if ((*it) == index) //skip myself
			{
				shouldCount = false;
				continue; //in case the sender is a lower priority one, should let it finish anyway
			}

			if ((*it) == curNode) {
				if (curRate < RATE_TH) //too slow or not valid at all
					backoffTime += defaultBackoffTime;
				else
					backoffTime += (double) (ch->FragSz - ch->FragNum - 1)
							/ (double) curRate;
			} else
				backoffTime += defaultBackoffTime; //for all nodes w/ higher priorty
			//fprintf(stdout, "%s:  inside loop backoffTime %f!!!\n", __FUNCTION__, defaultBackoffTime);
		} else {

			if ((*it) == curNode) {
				if (curRate < RATE_TH)
					backoffTime += defaultBackoffTime;
				else {
					backoffTime += (double) (ch->FragSz - ch->FragNum - 1)
							/ (double) curRate;
				}
			}
		}
	}

	//fprintf(stdout, "%s:  end  %f!!!\n", __FUNCTION__, backoffTime);
	return backoffTime; //sec

}

void AODV::constructForwarderList(Packet *p) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	int i, j, dst_i;
	float Cur_order, tmp_order;
	float dstEtx[MAX_FWDER];
	int fwList[MAX_FWDER];
	int dst, src;

	dst = (int) ih->daddr();
	//MAX_FWDER
	ch->FwdListSize = MAX_FWDER; //4;
	ch->ForwardernNum = MAX_FWDER - 1; //3;//last one = source
	//--------------------------yanhua--0304---
	src = index;
	dst_i = 0;
	for (i = 1; i < MAX_FWDER; i++) {
		dstEtx[i] = -1;
		fwList[i] = -1;
	}
	// sort all nodes according to the etx values for the destination
	for (i = 0; i < MAX_FWDER; i++) {
		Cur_order = etx[src][dst];
		tmp_order = Cur_order - 4 + i;
		if (tmp_order < 0) {
			continue;
		}
		dst_i++;
		for (j = 1; j < nNodes; j++) {
			if (tmp_order == etx[j][dst]) {
				dstEtx[dst_i] = etx[j][dst];
				fwList[dst_i] = j;
				break;
			}
		}
#ifdef EXOR_DBG
		if (j==nNodes) {
			printf("yanhua : no suiable forwarder to the destination!!");
		}
#endif
	}

	//  printf("before sort... \n");
	//  prDstEtx(dstEtx);
	//  prFwList(fwList);

	//  quickSort(dstEtx, MAX_FWDER, fwList);

	//  printf("after sort... \n");
	//  prDstEtx(dstEtx);
	//  prFwList(fwList);

	//--------------------------yanhua--0304---
	for (i = 0; i < MAX_FWDER; i++) {
		ch->F_List[i] = fwList[i];
		//ch->F_List[i] = MAX_FWDER-1-i;
	}

	//ch->F_List[(int)ih->daddr()] = ch->F_List[0];
	//ch->F_List[0] = ih->daddr();//highest priority
	//ch->F_List[(int)index] = ch->F_List[37];
	//ch->F_List[37] = index;//lowest priority

	//ch->F_List[0] = 3;//highest priority
	//ch->F_List[1] = 2;
	//ch->F_List[2] = 1;
	//ch->F_List[3] = 0; //lowest

#ifdef EXOR_DBG
	//    fprintf(stdout, "%s:  done !!!\n", __FUNCTION__);
#endif // DEBUG
}

//this function should called only by source node when receiving a pkt from upper layer
void AODV::constructBatchMap(Packet *p) {
	struct hdr_cmn *ch = HDR_CMN(p);
	for (int i = 0; i < ch->BatchSz; i++) {
		ch->BatchMap[i] = index; //only source node got it
	}
#ifdef EXOR_DBG
	//fprintf(stdout, "%s:  done !!!\n", __FUNCTION__);
#endif // DEBUG
}

//for source only
bool AODV::isBatchReady() {
	return (pktNum == (BATCH_SIZE - 1));
}

void AODV::transmitAllFragments() {
	double backoff = 0.;
	Packet *p, *ghost;

	if (ackReady) {//i must be dest node
		for (int i = 0; i < ACK_SIZE; i++) {
#ifdef EXOR_DBG
			fprintf(stdout, "%s:  sending ack %d  !!!\n", __FUNCTION__, i);
#endif // DEBUG   
			p = preparePacket(0, i, ACK_SIZE);
			// ghost = copyPacket(p); //make a copy for scheduler to destroy
			ghost = p->copy();
			Scheduler::instance().schedule(target_, ghost, 0);
			backoff += ONE_PKT_TIME;
		}

	} else {//non-dest node
		int idx_pk_num;
		int fSize = getFragmentSize();

		for (int i = 0; i < fSize; i++) {

			idx_pk_num = nextPktNum;
#ifdef EXOR_DBG
			fprintf(stdout, "%s:  sending data Pkt %d  (frag num = %d) !!!\n", __FUNCTION__, idx_pk_num, i);
#endif // DEBUG  
			if (idx_pk_num < 0) {
				fprintf(
						stdout,
						"%s:  ERROR !!!sending data Pkt %d  (frag num = %d) !!!\n",
						__FUNCTION__, idx_pk_num, i);
				exit(1);
			}
			p = preparePacket(idx_pk_num, i, fSize);
			//ghost = copyPacket(p);
			ghost = p->copy();
			Scheduler::instance().schedule(target_, ghost, 0);
			idx_pk_num = getNextFragment();
			backoff += ONE_PKT_TIME;
		}
	}

#ifdef EXOR_DBG
	fprintf(stdout, "%s:  done !!!\n", __FUNCTION__);
#endif // DEBUG                                                                               
}

/*
 // add a function to transmit all pkt in the buffer imediately
 // it should be called from the forwarder timer
 // the waiting time is handled by the forwarder timer setting/resetting

 void
 AODV::transmitAllFragments()
 {
 double backoff = 0.;
 Packet *p;

 if(ackReady){//i must be dest node
 for(int i = 0; i<ACK_SIZE;i++){
 #ifdef EXOR_DBG
 fprintf(stdout, "%s:  sending ack %d  !!!\n", __FUNCTION__, i);
 #endif // DEBUG
 p = preparePacket(0, i, ACK_SIZE);
 Scheduler::instance().schedule(target_, p,
 backoff);
 backoff += ONE_PKT_TIME;
 }

 }
 else{//non-dest node
 int idx_pk_num;
 int fSize = getFragmentSize();
 
 for(int i = 0; i<fSize;i++){

 idx_pk_num = nextPktNum;
 #ifdef EXOR_DBG
 fprintf(stdout, "%s:  sending data Pkt %d  (frag num = %d) !!!\n", __FUNCTION__, idx_pk_num, i);
 #endif // DEBUG

 if(idx_pk_num < 0){
 fprintf(stdout, "%s:  ERROR !!!sending data Pkt %d  (frag num = %d) !!!\n", __FUNCTION__, idx_pk_num, i);
 exit(1);
 }
 p = preparePacket(idx_pk_num, i, fSize);
 Scheduler::instance().schedule(target_, p,
 backoff);
 idx_pk_num = getNextFragment();
 backoff += ONE_PKT_TIME;
 }
 }


 #ifdef EXOR_DBG
 fprintf(stdout, "%s:  done !!!\n", __FUNCTION__);
 #endif // DEBUG

 }

 */

void AODV::resetForwardingTimer(double waitTime) {

	if (waitTime < 0) {
		fprintf(stdout, "node %d:  neg waitTime = %f !!!\n", index, waitTime);
		waitTime = 0;
	}
	fTimer.resched(waitTime);
}

//create a new packet (allocate new memory)
//with same source and dest
//and complete copy of  exor fields
Packet *
AODV::copyPacket(Packet* op) {

	struct hdr_cmn *cho = HDR_CMN(op);
	struct hdr_ip *iho = HDR_IP(op);

	Packet * p = allocpkt();
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);

	//copy/set general fields
	ch->ptype_ = cho->ptype_;
	ch->direction() = hdr_cmn::DOWN;//important
	ch->size() = cho->size();
	ch->error() = 0;
	ch->next_hop() = IP_BROADCAST;//important
	ch->addr_type() = NS_AF_INET;

	ih->saddr() = iho->saddr(); //key
	ih->daddr() = iho->daddr(); //key
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl() = IP_DEF_TTL;

	//set fields specfic for exor, complete copy
	//ch->Ver = cho->Ver;
	//ch->HdrLen = cho->HdrLen;
	ch->BatchId = cho->BatchId;
	ch->PktNum = cho->PktNum;
	ch->BatchSz = cho->BatchSz;
	ch->FragNum = cho->FragNum;
	ch->FragSz = cho->FragSz;
	ch->FwdListSize = cho->FwdListSize;
	ch->ForwardernNum = cho->ForwardernNum;
	for (int i = 0; i < MAX_FWDER; i++)
		ch->F_List[i] = cho->F_List[i];
	for (int i = 0; i < BATCH_SIZE; i++)
		ch->BatchMap[i] = cho->BatchMap[i];
	//ch->checksum = cho->checksum;
	ch->sender_addr = cho->sender_addr;
	ch->PayloadLen = cho->PayloadLen;

	//Packet::free(op);//release the old packet
	return p;
}

//--------------exor

/*
 Packet Reception Routines
 */

void AODV::recv(Packet *p, Handler*) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);

	assert(initialized());

	//if(ch->sender_addr == index)//received from itself
	//   return;


	//control pkts, of no interest to exor
	if (ch->ptype() == PT_AODV) {
		//ih->ttl_ -= 1;
		//recvAODV(p);
		drop(p, DROP_RTR_TTL);
		return;
	}

#ifdef EXOR_DBG
	fprintf(stdout, "----------------- %s:  start recv of pkt in node %d  from node %d at time %f!!! ----------------------------\n",
			__FUNCTION__, index, ch->sender_addr, CURRENT_TIME);
	fprintf(stdout, "----------------- %s:  ch->FragNum, ch->FragSz, ch->PktNum = %d:%d:%d\n", __FUNCTION__,ch->FragNum, ch->FragSz, ch->PktNum );
#endif // DEBUG   

	//---exor---------------------------------------------

	//a data pkt originated from upper layer (only at source node)
	if ((ih->saddr() == index) && (ch->num_forwards() == 0)) {
		//fprintf(stdout, "%s: should e here only once !!!!!!!!!!!!!!! %d \n", __FUNCTION__,ch->BatchId );
		//Add the IP Header
		ch->size() += IP_HDR_LEN;
		//we don't need to use ttl anymore ???
		ih->ttl_ = NETWORK_DIAMETER;

		//set up all the header fields by GOD
		//we should set batch Id if the current batch id is not set yet
		if (BatchId < 0)
			ch->BatchId = getNextBatchId();

#ifdef EXOR_DBG
		fprintf(stdout, "%s: new BatchId = %d \n", __FUNCTION__,ch->BatchId );
#endif // DEBUG

		ch->PktNum = getNextPktNum();

		// choi
		// send only one batch
		if (ch->PktNum >= BATCH_SIZE) {
			drop(p, DROP_RTR_QFULL);//Modified by yanhua
			//   	Packet::free (p);      //Modified by yanhua
			return;
		}

#ifdef EXOR_DBG
		fprintf(stdout, "%s: new PktNum = %d \n", __FUNCTION__,ch->PktNum );
#endif // DEBUG
		//ch->Ver = 1;
		//ch->HdrLen=10; //not useful anyway
		//ch->PayloadLen = 512; //not used anyway
		ch->BatchSz = BATCH_SIZE;
		ch->FragNum = ch->PktNum;// in process of building up batch, pkt buffer = frag buffer
		ch->FragSz = BATCH_SIZE;
		constructForwarderList(p); //For pkt class- comments by yanhua
		constructBatchMap(p); //For pkt class- comments by yanhua
		ch->ForwardernNum = getForwarderNum();
		ch->PayloadLen = PAY_LOAD;
		//no need to set checksum

		//handle general initialization
		if (localForwarderList.size() == 0) //non-inited yet, localforwarderlist should be cleared when a new batch is in effect
		{//save a local copy
			for (int i = 0; i < ch->FwdListSize; i++) //it is acutally an array
			{
				localForwarderList.push_back(ch->F_List[i]);
				localForwarderMap.insert(std::make_pair(ch->F_List[i], i));
			}
		}
		//now update the local pkt buffer and batch map
		updateLocalBatchMap(p);
		updateLocalPacketBuffer(p);
		Packet::free(p);

		//printf("after free at the source...\n");

		//estimate data rate (for init) and compute backoff time, no need for source
		//estimateDataRate(p);
		//computeBackOffTime(p);
		if (isBatchReady()) {
			//schedule transmission immediately
			//transmitAllFragments();
#ifdef EXOR_DBG
			fprintf(stdout, "%s:Hi, yanhua. i am ready to send this batch!!! \n", __FUNCTION__);//DBG by yanhua.
#endif // DEBUG
			resetForwardingTimer(0.);
		}

#ifdef EXOR_DBG
		//fprintf(stdout, "%s: iam here before return  \n", __FUNCTION__);
#endif // DEBUG

		return; // no need for anything else
	}

	//forwarder receives this packet- comments by yanhua
	//handle general initialization
	if (localForwarderList.size() == 0) //non-inited yet, localforwarderlist should be cleared when a new batch is in effect
	{//save a local copy	
		//int j=0;
		for (int i = 0; i < ch->FwdListSize; i++) //it is acutally an array
		{
			localForwarderList.push_back(ch->F_List[i]);
			localForwarderMap.insert(std::make_pair(ch->F_List[i], i));
			//j++;
		}

	}

#ifdef EXOR_DBG
	fprintf(stdout, "%s:  before geneic handling!!!\n", __FUNCTION__);
#endif // DEBUG

	//--- now a generic data pkt (received from neighbors (already inited)) for all nodes, including source and dest
	//always update the local pkt buffer and batch map
	updateLocalBatchMap(p);

	updateLocalPacketBuffer(p);

	/*
	 #ifdef EXOR_DBG
	 fprintf(stdout, "  --- current local batch map on node %d ----\n", index);
	 for(int j=0;j<BATCH_SIZE;j++)
	 fprintf(stdout, "%s:  batchmap for pktNums %d  = %d !!!\n", __FUNCTION__, j,localBatchMap[j]);
	 //for(int ii= 0;ii<ch->FwdListSize;ii++)
	 //fprintf(stdout, "%s:  priority for node %d  = %d !!!\n", __FUNCTION__, ii, getPriority(ii));
	 #endif // DEBUG
	 */

	//estimate data rate (for init) and compute backoff time, no need for source
	estimateDataRate(p);
	double waitTime = computeBackOffTime(p);

#ifdef EXOR_DBG
	// yanhua DBG
	fprintf(stdout, "%s:Hi, yanhua.Node %d ,  new waiting time = %f !!!\n", __FUNCTION__,index,waitTime);//DBG by yanhua.
#endif // DEBUG
	//reset the Forwarder Timer
	resetForwardingTimer(waitTime);//the right one
	//resetForwardingTimer(0.01 * Random::uniform());
	//resetForwardingTimer(0.);

	//------------------------------------------------------------

	//if it is a data pkt destined for this node, deliver to upper layer
	/* if (ch->PayloadLen > 0 && ch->ptype() != PT_AODV && ch->direction() == hdr_cmn::UP &&
	 ((u_int32_t)ih->daddr() == IP_BROADCAST)
	 || (ih->daddr() == here_.addr_)) {
	 */

	//if it is a data pkt destined for this node, deliver to upper layer
	FILE *OUTDATA;
	if ((OUTDATA = fopen("deliPkt.dat", "a")) == NULL) {
		printf("deliPkt.dat file open error\n");
	}

	//   if (ch->PayloadLen > 0 && ih->daddr() == here_.addr_){

	//dmux_->recv(p,0);
	//fprintf(stdout, "%s:  pkt %d delivered to dest %d !!!\n", __FUNCTION__, ch->PktNum, index);
	fprintf(OUTDATA,
			"%.9f pkt seq %d from %d received -> by dst node %d !!!\n",
			CURRENT_TIME, ch->PktNum, ch->sender_addr, index);

	fclose(OUTDATA);
	Packet::free(p); //print and free this pkt- comments by yanhua.
	return;
	//}
	//---exor-------------------------------------------------------------------------------------------------------

	fclose(OUTDATA);
#ifdef EXOR_DBG
	// yanhua DBG
	fprintf(stdout, "%s:Hi, yanhua. I should not be here, i am not a regular pkt !!!\n", __FUNCTION__);//DBG by yanhua.
#endif // DEBUG
	Packet::free(p);
}

void AODV::printPkt(Packet *p) {
	struct hdr_cmn *ch = HDR_CMN(p);
	fprintf(stdout, "----- pkt printout start---- \n");
	fprintf(stdout, "ch->PktNum %d,  ch->FragNum %d,ch->FragSz %d \n",
			ch->PktNum, ch->FragNum, ch->FragSz);

	//ch->ForwardernNum = cho->ForwardernNum;
	fprintf(stdout, " F_LIST[1]= %d, BatchMap[1] = %d  ", ch->F_List[1],
			ch->BatchMap[1]);
	fprintf(stdout, "----- pkt printout end ---- \n");
}

void AODV::recvAODV(Packet *p) {
	struct hdr_aodv *ah = HDR_AODV(p);

	assert(HDR_IP (p)->sport() == RT_PORT);
	assert(HDR_IP (p)->dport() == RT_PORT);

	/*
	 * Incoming Packets.
	 */
	switch (ah->ah_type) {

	case AODVTYPE_RREQ:
		recvRequest(p);
		break;

	case AODVTYPE_RREP:
		recvReply(p);
		break;

	case AODVTYPE_RERR:
		recvError(p);
		break;

	case AODVTYPE_HELLO:
		recvHello(p);
		break;

	default:
		fprintf(stdout, "Invalid AODV type (%x)\n", ah->ah_type);
		exit(1);
	}

}

void AODV::recvRequest(Packet *p) {
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
	aodv_rt_entry *rt;

	/*
	 * Drop if:
	 *      - I'm the source
	 *      - I recently heard this request.
	 */

	if (rq->rq_src == index) {
#ifdef DEBUG
		fprintf(stdout, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
		Packet::free(p);
		return;
	}

	if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
		fprintf(stdout, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG
		Packet::free(p);
		return;
	}

	/*
	 * Cache the broadcast ID
	 */
	id_insert(rq->rq_src, rq->rq_bcast_id);

	/*
	 * We are either going to forward the REQUEST or generate a
	 * REPLY. Before we do anything, we make sure that the REVERSE
	 * route is in the route table.
	 */
	aodv_rt_entry *rt0; // rt0 is the reverse route

	rt0 = rtable.rt_lookup(rq->rq_src);
	if (rt0 == 0) { /* if not in the route table */
		// create an entry for the reverse route.
		rt0 = rtable.rt_add(rq->rq_src);
	}

	rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));

	if ((rq->rq_src_seqno > rt0->rt_seqno) || ((rq->rq_src_seqno
			== rt0->rt_seqno) && (rq->rq_hop_count < rt0->rt_hops))) {
		// If we have a fresher seq no. or lesser #hops for the
		// same seq no., update the rt entry. Else don't bother.
		rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
				max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)));
		if (rt0->rt_req_timeout > 0.0) {
			// Reset the soft state and
			// Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
			// This is because route is used in the forward direction,
			// but only sources get benefited by this change
			rt0->rt_req_cnt = 0;
			rt0->rt_req_timeout = 0.0;
			rt0->rt_req_last_ttl = rq->rq_hop_count;
			rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
		}

		/* Find out whether any buffered packet can benefit from the
		 * reverse route.
		 * May need some change in the following code - Mahesh 09/11/99
		 */assert (rt0->rt_flags == RTF_UP);
		Packet *buffered_pkt;
		while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
			if (rt0 && (rt0->rt_flags == RTF_UP)) {
				assert(rt0->rt_hops != INFINITY2);
				forward(rt0, buffered_pkt, NO_DELAY);
			}
		}
	}
	// End for putting reverse route in rt table


	/*
	 * We have taken care of the reverse route stuff.
	 * Now see whether we can send a route reply.
	 */

	rt = rtable.rt_lookup(rq->rq_dst);

	// First check if I am the destination ..

	if (rq->rq_dst == index) {

#ifdef DEBUG
		fprintf(stdout, "%d - %s: destination sending reply\n",
				index, __FUNCTION__);
#endif // DEBUG

		// Just to be safe, I use the max. Somebody may have
		// incremented the dst seqno.
		seqno = max(seqno, rq->rq_dst_seqno) + 1;
		if (seqno % 2)
			seqno++;

		sendReply(rq->rq_src, // IP Destination
				1, // Hop Count
				index, // Dest IP Address
				seqno, // Dest Sequence Num
				MY_ROUTE_TIMEOUT, // Lifetime
				rq->rq_timestamp); // timestamp

		Packet::free(p);
	}

	// I am not the destination, but I may have a fresh enough route.

	else if (rt && (rt->rt_hops != INFINITY2) && (rt->rt_seqno
			>= rq->rq_dst_seqno)) {

		//assert (rt->rt_flags == RTF_UP);
		assert(rq->rq_dst == rt->rt_dst);
		//assert ((rt->rt_seqno%2) == 0);	// is the seqno even?
		sendReply(rq->rq_src, rt->rt_hops + 1, rq->rq_dst, rt->rt_seqno,
				(u_int32_t) (rt->rt_expire - CURRENT_TIME),
				//             rt->rt_expire - CURRENT_TIME,
				rq->rq_timestamp);
		// Insert nexthops to RREQ source and RREQ destination in the
		// precursor lists of destination and source respectively
		rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
		rt0->pc_insert(rt->rt_nexthop); // nexthop to RREQ destination

#ifdef RREQ_GRAT_RREP  

		sendReply(rq->rq_dst,
				rq->rq_hop_count,
				rq->rq_src,
				rq->rq_src_seqno,
				(u_int32_t) (rt->rt_expire - CURRENT_TIME),
				//             rt->rt_expire - CURRENT_TIME,
				rq->rq_timestamp);
#endif

		// TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT

		// DONE: Included gratuitous replies to be sent as per IETF aodv draft specification. As of now, G flag has not been dynamically used and is always set or reset in aodv-packet.h --- Anant Utgikar, 09/16/02.

		Packet::free(p);
	}
	/*
	 * Can't reply. So forward the  Route Request
	 */
	else {
		ih->saddr() = index;
		ih->daddr() = IP_BROADCAST;
		rq->rq_hop_count += 1;
		// Maximum sequence number seen en route
		if (rt)
			rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
		forward((aodv_rt_entry*) 0, p, DELAY);
	}

}

void AODV::recvReply(Packet *p) {
	//struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
	aodv_rt_entry *rt;
	char suppress_reply = 0;
	double delay = 0.0;

#ifdef DEBUG
	fprintf(stdout, "%d - %s: received a REPLY\n", index, __FUNCTION__);
#endif // DEBUG

	/*
	 *  Got a reply. So reset the "soft state" maintained for
	 *  route requests in the request table. We don't really have
	 *  have a separate request table. It is just a part of the
	 *  routing table itself.
	 */
	// Note that rp_dst is the dest of the data packets, not the
	// the dest of the reply, which is the src of the data packets.

	rt = rtable.rt_lookup(rp->rp_dst);

	/*
	 *  If I don't have a rt entry to this host... adding
	 */
	if (rt == 0) {
		rt = rtable.rt_add(rp->rp_dst);
	}

	/*
	 * Add a forward route table entry... here I am following
	 * Perkins-Royer AODV paper almost literally - SRD 5/99
	 */

	if ((rt->rt_seqno < rp->rp_dst_seqno) || // newer route
			((rt->rt_seqno == rp->rp_dst_seqno) && (rt->rt_hops
					> rp->rp_hop_count))) { // shorter or better route

		// Update the rt entry
		rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count, rp->rp_src,
				CURRENT_TIME + rp->rp_lifetime);

		// reset the soft state
		rt->rt_req_cnt = 0;
		rt->rt_req_timeout = 0.0;
		rt->rt_req_last_ttl = rp->rp_hop_count;

		if (ih->daddr() == index) { // If I am the original source
			// Update the route discovery latency statistics
			// rp->rp_timestamp is the time of request origination

			rt->rt_disc_latency[(unsigned char) rt->hist_indx] = (CURRENT_TIME
					- rp->rp_timestamp) / (double) rp->rp_hop_count;
			// increment indx for next time
			rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
		}

		/*
		 * Send all packets queued in the sendbuffer destined for
		 * this destination.
		 * XXX - observe the "second" use of p.
		 */
		Packet *buf_pkt;
		while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
			if (rt->rt_hops != INFINITY2) {
				assert (rt->rt_flags == RTF_UP);
				// Delay them a little to help ARP. Otherwise ARP
				// may drop packets. -SRD 5/23/99
				forward(rt, buf_pkt, delay);
				delay += ARP_DELAY;
			}
		}
	} else {
		suppress_reply = 1;
	}

	/*
	 * If reply is for me, discard it.
	 */

	if (ih->daddr() == index || suppress_reply) {
		Packet::free(p);
	}
	/*
	 * Otherwise, forward the Route Reply.
	 */
	else {
		// Find the rt entry
		aodv_rt_entry *rt0 = rtable.rt_lookup(ih->daddr());
		// If the rt is up, forward
		if (rt0 && (rt0->rt_hops != INFINITY2)) {
			assert (rt0->rt_flags == RTF_UP);
			rp->rp_hop_count += 1;
			rp->rp_src = index;
			forward(rt0, p, NO_DELAY);
			// Insert the nexthop towards the RREQ source to
			// the precursor list of the RREQ destination
			rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source

		} else {
			// I don't know how to forward .. drop the reply.
#ifdef DEBUG
			fprintf(stdout, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
			drop(p, DROP_RTR_NO_ROUTE);
		}
	}
}

void AODV::recvError(Packet *p) {
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
	aodv_rt_entry *rt;
	u_int8_t i;
	Packet *rerr = Packet::alloc();
	struct hdr_aodv_error *nre = HDR_AODV_ERROR(rerr);

	nre->DestCount = 0;

	for (i = 0; i < re->DestCount; i++) {
		// For each unreachable destination
		rt = rtable.rt_lookup(re->unreachable_dst[i]);
		if (rt && (rt->rt_hops != INFINITY2) && (rt->rt_nexthop == ih->saddr())
				&& (rt->rt_seqno <= re->unreachable_dst_seqno[i])) {
			assert(rt->rt_flags == RTF_UP);
			assert((rt->rt_seqno%2) == 0); // is the seqno even?
#ifdef DEBUG
			fprintf(stdout, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__,CURRENT_TIME,
					index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
					re->unreachable_dst[i],re->unreachable_dst_seqno[i],
					ih->saddr());
#endif // DEBUG
			rt->rt_seqno = re->unreachable_dst_seqno[i];
			rt_down(rt);

			// Not sure whether this is the right thing to do
			Packet *pkt;
			while ((pkt = ifqueue->filter(ih->saddr()))) {
				drop(pkt, DROP_RTR_MAC_CALLBACK);
			}

			// if precursor list non-empty add to RERR and delete the precursor list
			if (!rt->pc_empty()) {
				nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
				nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
				nre->DestCount += 1;
				rt->pc_delete();
			}
		}
	}

	if (nre->DestCount > 0) {
#ifdef DEBUG
		fprintf(stdout, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
		sendError(rerr);
	} else {
		Packet::free(rerr);
	}

	Packet::free(p);
}

/*
 Packet Transmission Routines
 */

void AODV::forward(aodv_rt_entry *rt, Packet *p, double delay) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);

	if (ih->ttl_ == 0) {

#ifdef DEBUG
		fprintf(stdout, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG
		drop(p, DROP_RTR_TTL);
		return;
	}

	if (ch->ptype() != PT_AODV && ch->direction() == hdr_cmn::UP
			&& ((u_int32_t) ih->daddr() == IP_BROADCAST) || (ih->daddr()
			== here_.addr_)) {
		dmux_->recv(p, 0);
		return;
	}

	if (rt) {
		assert(rt->rt_flags == RTF_UP);
		rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
		ch->next_hop_ = rt->rt_nexthop;
		ch->addr_type() = NS_AF_INET;
		ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction
	} else { // if it is a broadcast packet
		// assert(ch->ptype() == PT_AODV); // maybe a diff pkt type like gaf
		assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
		ch->addr_type() = NS_AF_NONE;
		ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction
	}

	if (ih->daddr() == (nsaddr_t) IP_BROADCAST) {
		// If it is a broadcast packet
		assert(rt == 0);
		/*
		 *  Jitter the sending of broadcast packets by 10ms
		 */
		Scheduler::instance().schedule(target_, p, 0.01 * Random::uniform());
	} else { // Not a broadcast packet
		if (delay > 0.0) {
			Scheduler::instance().schedule(target_, p, delay);
		} else {
			// Not a broadcast packet, no delay, send immediately
			Scheduler::instance().schedule(target_, p, 0.);
		}
	}

}

void AODV::sendRequest(nsaddr_t dst) {
	// Allocate a RREQ packet
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
	aodv_rt_entry *rt = rtable.rt_lookup(dst);

	assert(rt);

	/*
	 *  Rate limit sending of Route Requests. We are very conservative
	 *  about sending out route requests.
	 */

	if (rt->rt_flags == RTF_UP) {
		assert(rt->rt_hops != INFINITY2);
		Packet::free((Packet *) p);
		return;
	}

	if (rt->rt_req_timeout > CURRENT_TIME) {
		Packet::free((Packet *) p);
		return;
	}

	// rt_req_cnt is the no. of times we did network-wide broadcast
	// RREQ_RETRIES is the maximum number we will allow before
	// going to a long timeout.

	if (rt->rt_req_cnt > RREQ_RETRIES) {
		rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
		rt->rt_req_cnt = 0;
		Packet *buf_pkt;
		while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
			drop(buf_pkt, DROP_RTR_NO_ROUTE);
		}
		Packet::free((Packet *) p);
		return;
	}

#ifdef DEBUG
	fprintf(stdout, "(%2d) - %2d sending Route Request, dst: %d\n",
			++route_request, index, rt->rt_dst);
#endif // DEBUG
	// Determine the TTL to be used this time.
	// Dynamic TTL evaluation - SRD

	rt->rt_req_last_ttl = max(rt->rt_req_last_ttl,rt->rt_last_hop_count);

	if (0 == rt->rt_req_last_ttl) {
		// first time query broadcast
		ih->ttl_ = TTL_START;
	} else {
		// Expanding ring search.
		if (rt->rt_req_last_ttl < TTL_THRESHOLD)
			ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
		else {
			// network-wide broadcast
			ih->ttl_ = NETWORK_DIAMETER;
			rt->rt_req_cnt += 1;
		}
	}

	// remember the TTL used  for the next time
	rt->rt_req_last_ttl = ih->ttl_;

	// PerHopTime is the roundtrip time per hop for route requests.
	// The factor 2.0 is just to be safe .. SRD 5/22/99
	// Also note that we are making timeouts to be larger if we have
	// done network wide broadcast before.

	rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt);
	if (rt->rt_req_cnt > 0)
		rt->rt_req_timeout *= rt->rt_req_cnt;
	rt->rt_req_timeout += CURRENT_TIME;

	// Don't let the timeout to be too large, however .. SRD 6/8/99
	if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
		rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
	rt->rt_expire = 0;

#ifdef DEBUG
	fprintf(stdout, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
			++route_request,
			index, rt->rt_dst,
			rt->rt_req_timeout - CURRENT_TIME);
#endif	// DEBUG

	// Fill out the RREQ packet
	// ch->uid() = 0;
	ch->ptype() = PT_AODV;
	ch->size() = IP_HDR_LEN + rq->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_NONE;
	ch->prev_hop_ = index; // AODV hack

	ih->saddr() = index;
	ih->daddr() = IP_BROADCAST;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;

	// Fill up some more fields.
	rq->rq_type = AODVTYPE_RREQ;
	rq->rq_hop_count = 1;
	rq->rq_bcast_id = bid++;
	rq->rq_dst = dst;
	rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
	rq->rq_src = index;
	seqno += 2;
	assert ((seqno%2) == 0);
	rq->rq_src_seqno = seqno;
	rq->rq_timestamp = CURRENT_TIME;

	Scheduler::instance().schedule(target_, p, 0.);

}

void AODV::sendReply(nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
		u_int32_t rpseq, u_int32_t lifetime, double timestamp) {
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
	aodv_rt_entry *rt = rtable.rt_lookup(ipdst);

#ifdef DEBUG
	fprintf(stdout, "sending Reply from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
	assert(rt);

	rp->rp_type = AODVTYPE_RREP;
	//rp->rp_flags = 0x00;
	rp->rp_hop_count = hop_count;
	rp->rp_dst = rpdst;
	rp->rp_dst_seqno = rpseq;
	rp->rp_src = index;
	rp->rp_lifetime = lifetime;
	rp->rp_timestamp = timestamp;

	// ch->uid() = 0;
	ch->ptype() = PT_AODV;
	ch->size() = IP_HDR_LEN + rp->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_INET;
	ch->next_hop_ = rt->rt_nexthop;
	ch->prev_hop_ = index; // AODV hack
	ch->direction() = hdr_cmn::DOWN;

	ih->saddr() = index;
	ih->daddr() = ipdst;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl_ = NETWORK_DIAMETER;

	Scheduler::instance().schedule(target_, p, 0.);

}

void AODV::sendError(Packet *p, bool jitter) {
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_error *re = HDR_AODV_ERROR(p);

#ifdef ERROR
	fprintf(stdout, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
	re->re_type = AODVTYPE_RERR;
	//re->reserved[0] = 0x00; re->reserved[1] = 0x00;
	// DestCount and list of unreachable destinations are already filled

	// ch->uid() = 0;
	ch->ptype() = PT_AODV;
	ch->size() = IP_HDR_LEN + re->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_NONE;
	ch->next_hop_ = 0;
	ch->prev_hop_ = index; // AODV hack
	ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction

	ih->saddr() = index;
	ih->daddr() = IP_BROADCAST;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl_ = 1;

	// Do we need any jitter? Yes
	if (jitter)
		Scheduler::instance().schedule(target_, p, 0.01 * Random::uniform());
	else
		Scheduler::instance().schedule(target_, p, 0.0);

}

/*
 Neighbor Management Functions
 */

void AODV::sendHello() {
	Packet *p = Packet::alloc();
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_reply *rh = HDR_AODV_REPLY(p);

#ifdef DEBUG
	fprintf(stdout, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
	rh->rp_type = AODVTYPE_HELLO;
	//rh->rp_flags = 0x00;
	rh->rp_hop_count = 1;
	rh->rp_dst = index;
	rh->rp_dst_seqno = seqno;
	rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;

	// ch->uid() = 0;
	ch->ptype() = PT_AODV;
	ch->size() = IP_HDR_LEN + rh->size();
	ch->iface() = -2;
	ch->error() = 0;
	ch->addr_type() = NS_AF_NONE;
	ch->prev_hop_ = index; // AODV hack

	ih->saddr() = index;
	ih->daddr() = IP_BROADCAST;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl_ = 1;

	Scheduler::instance().schedule(target_, p, 0.0);
}

void AODV::recvHello(Packet *p) {
	//struct hdr_ip *ih = HDR_IP(p);
	struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
	AODV_Neighbor *nb;

	nb = nb_lookup(rp->rp_dst);
	if (nb == 0) {
		nb_insert(rp->rp_dst);
	} else {
		nb->nb_expire = CURRENT_TIME + (1.5 * ALLOWED_HELLO_LOSS
				* HELLO_INTERVAL);
	}

	Packet::free(p);
}

void AODV::nb_insert(nsaddr_t id) {
	AODV_Neighbor *nb = new AODV_Neighbor(id);

	assert(nb);
	nb->nb_expire = CURRENT_TIME + (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
	LIST_INSERT_HEAD(&nbhead, nb, nb_link);
	seqno += 2; // set of neighbors changed
	assert ((seqno%2) == 0);
}

AODV_Neighbor*
AODV::nb_lookup(nsaddr_t id) {
	AODV_Neighbor *nb = nbhead.lh_first;

	for (; nb; nb = nb->nb_link.le_next) {
		if (nb->nb_addr == id)
			break;
	}
	return nb;
}

/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */
void AODV::nb_delete(nsaddr_t id) {
	AODV_Neighbor *nb = nbhead.lh_first;

	log_link_del(id);
	seqno += 2; // Set of neighbors changed
	assert ((seqno%2) == 0);

	for (; nb; nb = nb->nb_link.le_next) {
		if (nb->nb_addr == id) {
			LIST_REMOVE(nb,nb_link);
			delete nb;
			break;
		}
	}

	handle_link_failure(id);

}

/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
void AODV::nb_purge() {
	AODV_Neighbor *nb = nbhead.lh_first;
	AODV_Neighbor *nbn;
	double now = CURRENT_TIME;

	for (; nb; nb = nbn) {
		nbn = nb->nb_link.le_next;
		if (nb->nb_expire <= now) {
			nb_delete(nb->nb_addr);
		}
	}

}
//-----------yanhua-----------------0304--
/*AODV::readRM()
 {}
 */
// read etx values
void AODV::read_orderRM() {
	// read route metric information
	FILE *fin;
	//int nbyte;
	int i;

	// route metric : etx
	//if((fin=fopen("min-etx.txt", "r")) == NULL) {
	if ((fin = fopen("Order_M.txt", "r")) == NULL) {
		printf("route metric file (Order_M.txt) file open error\n");
		exit(0);
	}

	for (i = 0; i < nNodes; i++) {
		fscanf(
				fin,
				"%f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f\n",
				&etx[i][0], &etx[i][1], &etx[i][2], &etx[i][3], &etx[i][4],
				&etx[i][5], &etx[i][6], &etx[i][7], &etx[i][8], &etx[i][9],
				&etx[i][10], &etx[i][11], &etx[i][12], &etx[i][13],
				&etx[i][14], &etx[i][15], &etx[i][16], &etx[i][17],
				&etx[i][18], &etx[i][19], &etx[i][20], &etx[i][21],
				&etx[i][22], &etx[i][23], &etx[i][24], &etx[i][25],
				&etx[i][26], &etx[i][27], &etx[i][28], &etx[i][29],
				&etx[i][30], &etx[i][31], &etx[i][32], &etx[i][33],
				&etx[i][34], &etx[i][35], &etx[i][36], &etx[i][37]);
	}
	fclose(fin);
#ifdef EXOR_DBG
	printf ("yanhua : read over.");
#endif
	//if(i != nNodes)
	//	printf("nodeId is wrong(i=%d, nNodes=%d)\n", i, nNodes);

}

//-----------yanhua-----------------0304--
// quick sort
void AODV::prDstEtx(float num[]) {
	int i;
	for (i = 0; i < MAX_FWDER; i++)
		printf("%.2f \n", num[i]);

	return;
}

void AODV::prFwList(int num[]) {
	int i;
	for (i = 0; i < MAX_FWDER; i++)
		printf("%d\n", num[i]);

	return;
}

// quick sort
void AODV::quickSort(float numbers[], int array_size, int idx[]) {
	q_sort(numbers, 0, array_size - 1, idx);
}

void AODV::q_sort(float numbers[], int left, int right, int idx[]) {
	float pivot;
	int l_hold, r_hold, pivot_idx;

	l_hold = left;
	r_hold = right;
	pivot = numbers[left];
	pivot_idx = idx[left];

	while (left < right) {
		while ((numbers[right] >= pivot) && (left < right))
			right--;
		if (left != right) {
			numbers[left] = numbers[right];
			idx[left] = idx[right];
			left++;
		}
		while ((numbers[left] <= pivot) && (left < right))
			left++;
		if (left != right) {
			numbers[right] = numbers[left];
			idx[right] = idx[left];
			right--;
		}
	}
	numbers[left] = pivot;
	idx[left] = pivot_idx;

	pivot_idx = left;
	left = l_hold;
	right = r_hold;
	if (left < pivot_idx)
		q_sort(numbers, left, pivot_idx - 1, idx);
	if (right > pivot_idx)
		q_sort(numbers, pivot_idx + 1, right, idx);
}
