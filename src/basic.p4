/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

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
    bit<6>  cntl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

}

header payload_t{
	bit<32> data;
	bit<32> encrypt;
	bit<32> type;
	bit<32> index;
}

struct metadata {
    /* empty */
	
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
	tcp_t		 tcp;
	payload_t	 payload;
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
        packet.extract(hdr.tcp);
		packet.extract(hdr.payload);
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
    
	bit<32> secret_key;
	register<bit<32>>((bit<32>) 4) keys;

	action initial_key(){
		keys.write((bit<32>) 0,(bit<32>) 12345);
		keys.write((bit<32>) 1,(bit<32>) 2345);
		keys.write((bit<32>) 2,(bit<32>) 4536);
		keys.write((bit<32>) 3,(bit<32>) 89735);
	}
		

	action drop() {
        mark_to_drop();
    }

	action encrypt_xor(){
		keys.read(secret_key, hdr.payload.index);
		hdr.payload.data = hdr.payload.data ^ secret_key;
	}

	action encrypt_caesar(){
		keys.read(secret_key, hdr.payload.index);
		hdr.payload.data = hdr.payload.data + secret_key;
	}

	action encrypt_feistel(){
		keys.read(secret_key, hdr.payload.index);
		bit<32> left = hdr.payload.data >> 16;
		bit<32> right = hdr.payload.data & (bit<32>) 65535;

		bit<32> new_left = right;
		bit<32> new_right = left ^ secret_key ^ right;
		
		keys.read(secret_key, hdr.payload.index+1);
		right = new_right;
		left = new_right ^ new_left ^ secret_key;

		hdr.payload.data = (left << 16) | right;
		
	}
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
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
		bit<32> key;
		keys.read(key, (bit<32>) 0);
		if (key == 0){
			initial_key();
		}

		if (hdr.payload.encrypt == 1){
			if (hdr.payload.encrypt == 0){
				encrypt_xor();
			}
			else if (hdr.payload.encrypt == 1){
				encrypt_caesar();
			}
			else{
				encrypt_feistel();
			}
			hdr.payload.encrypt = 0;
		}

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
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
		packet.emit(hdr.payload);
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
