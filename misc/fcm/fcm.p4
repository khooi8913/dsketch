/* -*- P4_16 -*- */
/*
	Retrieved and adapted from: https://github.com/fcm-project/fcm_p4
*/

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
#define SKETCH_W1 0x40000 // 8 bits, width at layer 1, 2^18 = 262,144
#define SKETCH_W2 0x8000 // 16 bits, width at layer 2, 2^15 = 32,768
#define SKETCH_W3 0x1000 // 32 bits, width at layer 3, 2^12 = 4096

#define ADD_LEVEL1 0x000000ff // 2^8 - 2 + 1 (property of SALU)
#define ADD_LEVEL2 0x000100fd // (2^8 - 2) + (2^16 - 2) + 1 (property of SALU)

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_DECAY_UPDATE = 16w0x8888;

typedef bit<8> ip_proto_t;
const ip_proto_t IP_PROTO_ICMP = 1;
const ip_proto_t IP_PROTO_TCP = 6;
const ip_proto_t IP_PROTO_UDP = 17;

typedef bit<32> count_t;

const bit<3> HH_DIGEST = 0x03;
struct hh_digest_t {
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
    bit<8>  protocol;
    l4_port_t src_port;
    l4_port_t dst_port;
}

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    ip_proto_t   protocol;
    bit<16>  hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

header tcp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flag;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

     /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h  ipv4;
    tcp_h   tcp;
    udp_h   udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct fcm_metadata_t {
    bit<32> hash_meta_d1;
    bit<32> hash_meta_d2;


    bit<32> result_d1;
    bit<32> result_d2;
    bit<32> increment_occupied;
}

struct my_ingress_metadata_t {
	fcm_metadata_t	fcm_mdata;
    l4_port_t src_port;
    l4_port_t dst_port;
}

   /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);

		// initialize metadata
    	meta.fcm_mdata.result_d1 = 0;
    	meta.fcm_mdata.result_d2 = 0;
    	meta.fcm_mdata.increment_occupied = 0;

        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.src_port = 0;
        meta.dst_port = 0;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP    : parse_tcp;
            IP_PROTO_UDP    : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        transition accept;
    }
}
 
    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror() mirror;
    Digest <hh_digest_t>() hh_digest;

    apply {
        if(ig_dprsr_md.mirror_type == 1) {
            // session 1, where it points to the recirculation port
            mirror.emit(10w1);
        }

        if(ig_dprsr_md.digest_type == HH_DIGEST) {
            hh_digest.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, meta.src_port, meta.dst_port});
        }

        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// FCM logic control block
// ---------------------------------------------------------------------------
control FCMSketch (
	inout my_ingress_headers_t hdr,
	inout my_ingress_metadata_t meta,
	out bit<19> num_occupied_reg, 
	out bit<32> flow_size,
    out bit<32> cardinality) {

	bit<32> index = 0;
	bit<32> index0 = 0;
	bit<32> index1 = 0;

	// +++++++++++++++++++ 
	//	hashings & hash action
	// +++++++++++++++++++

    // CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
    //                        true,          // reversed
    //                        false,         // use msb?
    //                        false,         // extended?
    //                        32w0xFFFFFFFF, // initial shift register value
    //                        32w0xFFFFFFFF  // result xor
    //                        ) CRC32;
    // Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32) hash_d1;

	Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_d1;
	CRCPolynomial<bit<32>>(32w0x04C11DB7, 
                           false, 
                           false, 
                           false, 
                           32w0xFFFFFFFF,
                           32w0x00000000
                           ) CRC32_MPEG;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32_MPEG) hash_d2;

    
	// +++++++++++++++++++ 
	//	registers
	// +++++++++++++++++++

	Register<bit<8>, bit<18>>(SKETCH_W1) sketch_reg_l1_d1;
	Register<bit<16>, bit<15>>(SKETCH_W2) sketch_reg_l2_d1;
	Register<bit<32>, bit<12>>(SKETCH_W3) sketch_reg_l3_d1;

	Register<bit<8>, bit<18>>(SKETCH_W1) sketch_reg_l1_d2;
	Register<bit<16>, bit<15>>(SKETCH_W2) sketch_reg_l2_d2;
	Register<bit<32>, bit<12>>(SKETCH_W3) sketch_reg_l3_d2;

	// total number of empty registers for all trees
	Register<bit<32>, _>(1) reg_num_empty;

	// +++++++++++++++++++ 
	//	register actions
	// +++++++++++++++++++

	// level 1, depth 1
	RegisterAction<bit<8>, bit<18>, bit<32>>(sketch_reg_l1_d1) increment_l1_d1 = {
		void apply(inout bit<8> value, out bit<32> result) {
			value = value |+| 1;
			result = (bit<32>)value; // return level 1 value (255 -> count 254)
		}
	};
	// level 2, depth 1, only when level 1 output is 255
	RegisterAction<bit<16>, bit<15>, bit<32>>(sketch_reg_l2_d1) increment_l2_d1 = {
		void apply(inout bit<16> value, out bit<32> result) {
			result = (bit<32>)value + ADD_LEVEL1; // return level 1 + 2
			value = value |+| 1;
		}
	};
	// level 3, depth 1, only when level 2 output is 65789
	RegisterAction<bit<32>, bit<12>, bit<32>>(sketch_reg_l3_d1) increment_l3_d1 = {
		void apply(inout bit<32> value, out bit<32> result) {
			result = value + ADD_LEVEL2; // return level 1 + 2 + 3
			value = value |+| 1;
			
		}
	};

	// level 1, depth 2
	RegisterAction<bit<8>, bit<18>, bit<32>>(sketch_reg_l1_d2) increment_l1_d2 = {
		void apply(inout bit<8> value, out bit<32> result) {
			value = value |+| 1;
			result = (bit<32>)value; // return level 1 value (255 -> count 254)
		}
	};
	// level 2, depth 2, only when level 1 output is 255
	RegisterAction<bit<16>, bit<15>, bit<32>>(sketch_reg_l2_d2) increment_l2_d2 = {
		void apply(inout bit<16> value, out bit<32> result) {
			result = (bit<32>)value + ADD_LEVEL1; // return level 1 + 2
			value = value |+| 1;
		}
	};
	// level 3, depth 2, only when level 2 output is 65789
	RegisterAction<bit<32>, bit<12>, bit<32>>(sketch_reg_l3_d2) increment_l3_d2 = {
		void apply(inout bit<32> value, out bit<32> result) {
			result = value + ADD_LEVEL2; // return level 1 + 2 + 3
			value = value |+| 1; // increment assuming no 32-bit overflow
			
		}
	};

	// increment number of empty register value for cardinality
	RegisterAction<bit<32>, _, bit<32>>(reg_num_empty) increment_occupied_reg = {
		void apply(inout bit<32> value, out bit<32> result) {
			result = value + meta.fcm_mdata.increment_occupied;
			value = value + meta.fcm_mdata.increment_occupied;
		}
	};


	// +++++++++++++++++++ 
	//	actions
	// +++++++++++++++++++

	// action for level 1, depth 1, you can re-define the flow key identification
	action fcm_action_l1_d1() {
		// meta.fcm_mdata.result_d1 = increment_l1_d1.execute(index0[17:0]);
		meta.fcm_mdata.result_d1 = increment_l1_d1.execute(index[17:0]);
	}
	// action for level 2, depth 1
	action fcm_action_l2_d1() {
		// meta.fcm_mdata.result_d1 = increment_l2_d1.execute(index0[17:3]);
		meta.fcm_mdata.result_d1 = increment_l2_d1.execute(index[17:3]);
	}
	// action for level 3, depth 1
	action fcm_action_l3_d1() {
		// meta.fcm_mdata.result_d1 = increment_l3_d1.execute(index0[17:6]);
		meta.fcm_mdata.result_d1 = increment_l3_d1.execute(index[17:6]);
	}

	// action for level 1, depth 2, you can re-define the flow key identification
	action fcm_action_l1_d2() {
		// meta.fcm_mdata.result_d2 = increment_l1_d2.execute(index1[17:0]);
		meta.fcm_mdata.result_d2 = increment_l1_d2.execute(index[23:6]);
	}
	// action for level 2, depth 2
	action fcm_action_l2_d2() {
		// meta.fcm_mdata.result_d2 = increment_l2_d2.execute(index1[17:3]);
		meta.fcm_mdata.result_d2 = increment_l2_d2.execute(index1[23:9]);
	}
	// action for level 3, depth 2
	action fcm_action_l3_d2() {
		// meta.fcm_mdata.result_d2 = increment_l3_d2.execute(index1[17:6]);
		meta.fcm_mdata.result_d2 = increment_l3_d2.execute(index1[23:12]);
	}


	// increment reg of occupied leaf number
	action fcm_action_increment_cardreg() {
		num_occupied_reg = (increment_occupied_reg.execute(0))[19:1];
	}

	action fcm_action_check_occupied(bit<32> increment_val) {
		meta.fcm_mdata.increment_occupied = increment_val;
	}


	action fcm_action_set_cardinality(bit<32> card_match) {
		cardinality = card_match;
	}

	// +++++++++++++++++++ 
	//	tables
	// +++++++++++++++++++

	// if level 1 is full, move to level 2.
	table tb_fcm_l1_to_l2_d1 {
		key = {
			meta.fcm_mdata.result_d1 : exact;
		}
		actions = {
			fcm_action_l2_d1;
			@defaultonly NoAction;
		}
		const default_action = NoAction();
		const entries = {
			32w255: fcm_action_l2_d1();
		}
		size = 2;
	}

	// if level 2 is full, move to level 3.
	table tb_fcm_l2_to_l3_d1 {
		key = {
			meta.fcm_mdata.result_d1 : exact;
		}
		actions = {
			fcm_action_l3_d1;
			@defaultonly NoAction;
		}
		const default_action = NoAction();
		const entries = {
			32w65789: fcm_action_l3_d1();
		}
		size = 2;
	}

	// if level 1 is full, move to level 2.
	table tb_fcm_l1_to_l2_d2 {
		key = {
			meta.fcm_mdata.result_d2 : exact;
		}
		actions = {
			fcm_action_l2_d2;
			@defaultonly NoAction;
		}
		const default_action = NoAction();
		const entries = {
			32w255: fcm_action_l2_d2();
		}
		size = 2;
	}

	// if level 2 is full, move to level 3.
	table tb_fcm_l2_to_l3_d2 {
		key = {
			meta.fcm_mdata.result_d2 : exact;
		}
		actions = {
			fcm_action_l3_d2;
			@defaultonly NoAction;
		}
		const default_action = NoAction();
		const entries = {
			32w65789: fcm_action_l3_d2();
		}
		size = 2;
	}

	// Update the number of occupied leaf nodes
	table tb_fcm_increment_occupied {
		key = {
			meta.fcm_mdata.result_d1 : ternary;
			meta.fcm_mdata.result_d2 : ternary;
		}
		actions = {
			fcm_action_check_occupied;
		}
		const default_action = fcm_action_check_occupied(0);
		const entries = {
			(32w1, 32w1) : fcm_action_check_occupied(2);
			(32w1, _) : fcm_action_check_occupied(1);
			(_, 32w1) : fcm_action_check_occupied(1);
		}
		size = 4;
	}


	// look up LC cardinality using number of empty counters at level 1
	// [30:12] : divide by 2 ("average" empty_reg number). 
	// Each array size is 2 ** 19, so slice 19 bits
	table tb_fcm_cardinality {
		key = {
			num_occupied_reg : range; // 19 bits
		}
		actions = {
			fcm_action_set_cardinality;
		}
		const default_action = fcm_action_set_cardinality(0);
		size = 4096;
	}


	// +++++++++++++++++++ 
	//	apply
	// +++++++++++++++++++
	apply {
		// index0 = hash_d1.get(
		// 	{ 
		// 		hdr.ipv4.src_addr,
        //         hdr.ipv4.dst_addr,
        //         hdr.ipv4.protocol,
        //         meta.src_port,
        //         meta.dst_port
		//  	}
		// );
		// index1 = hash_d2.get(
		// 	{ 
		// 		hdr.ipv4.src_addr,
        //         hdr.ipv4.dst_addr,
        //         hdr.ipv4.protocol,
        //         meta.src_port,
        //         meta.dst_port
		//  	}
		// );
		index = hash_d2.get(
			{ 
				hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                meta.src_port,
                meta.dst_port
		 	}
		);

		fcm_action_l1_d1();			// increment level 1, depth 1
		fcm_action_l1_d2();			// increment level 1, depth 2
		/* increment the number of occupied leaf nodes */
		// tb_fcm_increment_occupied.apply(); 
		// fcm_action_increment_cardreg(); 
		// tb_fcm_cardinality.apply(); // calculate cardinality estimate
		tb_fcm_l1_to_l2_d1.apply(); // conditional increment level 2, depth 1
		tb_fcm_l1_to_l2_d2.apply(); // conditional increment level 2, depth 2
		tb_fcm_l2_to_l3_d1.apply(); // conditional increment level 3, depth 1
		tb_fcm_l2_to_l3_d2.apply(); // conditional increment level 3, depth 2

		/* Take minimum for final count-query. */
		flow_size = meta.fcm_mdata.result_d1 > meta.fcm_mdata.result_d2 ? meta.fcm_mdata.result_d2 : meta.fcm_mdata.result_d1;
	}
}


    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
		
		bit<19> num_occupied_reg = 0; // local variable for cardinality
		bit<32> flow_size = 0; // local variable for final query
		bit<32> cardinality = 0; // local variable for final query


		/*** temp ***/
		// increment when packet comes in
		Register<bit<32>, _>(1, 0) num_pkt;
		RegisterAction<bit<32>, _, bit<32>>(num_pkt) increment_pkt = {
			void apply(inout bit<32> value, out bit<32> result) {
				value = value |+| 1;
				result = value;
			}
		};

		action count_pkt() { 
			increment_pkt.execute(0); 
		}
		/*** temp ***/

		 action generate_digest() {
        	ig_dprsr_md.digest_type = 0x03;
		}

		action drop() {
			ig_dprsr_md.drop_ctl = 0x0;    // drop packet
			exit;
		}

		action forward(PortId_t port) {
			ig_tm_md.ucast_egress_port = port;
		}

		table ipv4_forward {
			key = {
				ig_intr_md.ingress_port : exact;
			}
			actions = {
				forward;
				NoAction;
			}
			default_action = NoAction();
		}


		table threshold {
			key = {
				// TODO: this needs to be slightly readjusted
				flow_size[19:0] : range;
			}
			actions = {
				generate_digest;
				NoAction;
			}
			default_action = NoAction();
			size = 1;
		}


		FCMSketch() fcmsketch;
		apply {
			// bit<19> num_occupied_reg; // local variable for cardinality
			// bit<32> flow_size; // local variable for final query
		    // bit<32> cardinality; // local variable for final query
			
			// count_pkt(); // temp
			ipv4_forward.apply();
			fcmsketch.apply(hdr, 
							meta, 
							num_occupied_reg, 
							flow_size, 
							cardinality);

			threshold.apply();
		}
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


Pipeline( 
		IngressParser(),
		Ingress(),
		IngressDeparser(),
		EgressParser(),
		Egress(),
		EgressDeparser()
         ) pipe;

Switch(pipe) main;


