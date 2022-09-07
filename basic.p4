/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_ADDRESS 32w4194304

const bit<16> TYPE_IPV4 = 0x800;
const bit<6>  ACK       = 0x10;
const bit<6>  FINACK    = 0x11;
const bit<6>  PSHACK    = 0x18;
const bit<6>  FINPSHACK = 0x19;
const bit<6>  RST       = 0x04;
const bit<6>  RSTACK    = 0x14;
const bit<4>  ScoreMAX  = 0x08;
const bit<6>  AbnrmlMAX = 0x08;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

register<bit<4>>(MAX_ADDRESS) IPScores;
register<bit<6>>(1) TCPConnectCount;
register<bit<6>>(1) AbnormalConnectCount;
register<bit<6>>(1) AttackFlag;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checkSum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> index;
    bit<4>  score;
    bit<6>  tcpCount;
    bit<6>  abnormalCount;
    bit<6>  attackScore;
    egressSpec_t  port;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol){
	    8w0x6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
	packet.extract(hdr.tcp);
	transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
	
    /*counter(1, CounterType.packets) AbnormalConnections;*/

    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
	key = {
	    meta.port: exact;
	}
	actions = {
	    ipv4_forward;
	    drop;
	    NoAction;
	}
	size = 1024;
	default_action = drop();
    }

    apply {   
        if(hdr.ipv4.isValid()) {
	    meta.port = standard_metadata.ingress_port;
            ipv4_lpm.apply();
        }
	if(hdr.tcp.isValid()) {
	    if(meta.port == 1){
		hash(meta.index, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr}, MAX_ADDRESS);	
	    }
	    else{
		hash(meta.index, HashAlgorithm.crc32, 32w0, {hdr.ipv4.dstAddr}, MAX_ADDRESS);
	    }

	    IPScores.read(meta.score, meta.index);
	    TCPConnectCount.read(meta.tcpCount, 0);
	    AbnormalConnectCount.read(meta.abnormalCount, 0);
	    AttackFlag.read(meta.attackScore, 0);
	
	    if(meta.attackScore  > 0 && meta.score == ScoreMAX){
		drop();
	    }
	    else {
		if(meta.score == 0){
            	    meta.tcpCount = meta.tcpCount + 1;
                    TCPConnectCount.write(0, meta.tcpCount);
                }

            	if(hdr.tcp.ctrl == ACK || hdr.tcp.ctrl == PSHACK){
                    if(meta.score != 0){
                    	meta.score = meta.score - 1;
                    	IPScores.write(meta.index, meta.score);
                	}	
            	}
		else if(hdr.tcp.ctrl == FINACK || hdr.tcp.ctrl == RST || hdr.tcp.ctrl == RSTACK || hdr.tcp.ctrl == FINPSHACK){
                    IPScores.write(meta.index, 0);
                }
            	else{
                     if(meta.score != ScoreMAX){
                    	meta.score = meta.score + 1;
                    	IPScores.write(meta.index, meta.score);
                        
			if(meta.score == ScoreMAX){
                            meta.abnormalCount = meta.abnormalCount + 1;
                            AbnormalConnectCount.write(0, meta.abnormalCount);
                    }
                }
            	}
	    }
	    if(meta.tcpCount > 50){
		if(meta.abnormalCount > AbnrmlMAX){
		    meta.attackScore = meta.attackScore + 1;
		    AttackFlag.write(0, meta.attackScore);
		}
		else{
		    if(meta.attackScore != 0){
			meta.attackScore = meta.attackScore - 1;
			AttackFlag.write(0, meta.attackScore);
		    }
		}
		TCPConnectCount.write(0, 0);
		AbnormalConnectCount.write(0,0);
	    }	    
    
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
