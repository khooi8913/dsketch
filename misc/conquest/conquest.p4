// vim: syntax=P4
/*
    ConQuest: Fine-Grained Queue Measurement in the Data Plane
    
    Copyright (C) 2020 Xiaoqi Chen, Princeton University
    xiaoqic [at] cs.princeton.edu / https://doi.org/10.1145/3359989.3365408
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
    Retrieved, and adapted from: https://github.com/Princeton-Cabernet/p4-projects
    
    Note:
    - cleaning is done on the corresponding sketch instance using the control plane whenever the epoch advances.
*/

#define SKETCH_INC ((bit<32>) hdr.ipv4.total_len)

//== Preamble: constants, headers
#include <core.p4>
#include <tna.p4>

const bit<32> SKETCH_SIZE = 16384;
typedef bit<14> hash_index_t;

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

typedef bit<8> ip_proto_t;
const ip_proto_t IP_PROTO_ICMP = 1;
const ip_proto_t IP_PROTO_TCP = 6;
const ip_proto_t IP_PROTO_UDP = 17;


header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> diffserv;
    bit<2> ecn; 
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

struct paired_32bit {
    bit<32> hi;
    bit<32> lo;
}


//== Metadata definition
struct ig_metadata_t {
    bit<16> src_port;
    bit<16> dst_port;

    bit<2> snap_epoch;
     
    hash_index_t hashed_index_row_0;
    hash_index_t hashed_index_row_1;

    hash_index_t snap_0_row_0_index;
    bit<32> snap_0_row_0_read;
    hash_index_t snap_0_row_1_index;
    bit<32> snap_0_row_1_read;
    hash_index_t snap_1_row_0_index;
    bit<32> snap_1_row_0_read;
    hash_index_t snap_1_row_1_index;
    bit<32> snap_1_row_1_read;
    hash_index_t snap_2_row_0_index;
    bit<32> snap_2_row_0_read;
    hash_index_t snap_2_row_1_index;
    bit<32> snap_2_row_1_read;
    hash_index_t snap_3_row_0_index;
    bit<32> snap_3_row_0_read;
    hash_index_t snap_3_row_1_index;
    bit<32> snap_3_row_1_read;

    bit<32> snap_0_read_min_l0;
    bit<32> snap_1_read_min_l0;
    bit<32> snap_2_read_min_l0;
    bit<32> snap_3_read_min_l0;

    bit<32> snap_0_read_min_l1;
    bit<32> snap_2_read_min_l1;
    bit<32> snap_0_read_min_l2;

    bit<14> cyclic_index;
}

struct eg_metadata_t {
    
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
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
        ig_md.src_port = 0;
        ig_md.dst_port = 0;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP    : parse_tcp;
            IP_PROTO_UDP    : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        ig_md.src_port = hdr.tcp.src_port;
        ig_md.dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        ig_md.src_port = hdr.udp.src_port;
        ig_md.dst_port = hdr.udp.dst_port;
        transition accept;
    }    
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {    
    apply {    
        pkt.emit(hdr);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
        pkt.emit(hdr);
    }
}


//== Control logic 
control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_index;
    // Hash<bit<14>>(HashAlgorithm_t.CRC32) hash_0_TCP;  
    // Hash<bit<14>>(HashAlgorithm_t.CRC32) hash_0_UDP;  
    // Hash<bit<14>>(HashAlgorithm_t.CRC32) hash_0_Other;   
    // Hash<bit<14>>(HashAlgorithm_t.CRC32) hash_1_TCP;  
    // Hash<bit<14>>(HashAlgorithm_t.CRC32) hash_1_UDP;  
    // Hash<bit<14>>(HashAlgorithm_t.CRC32) hash_1_Other;   
       
    // action calc_hashed_index_TCP(){
    //     ig_md.hashed_index_row_0 = hash_0_TCP.get({
    //         6w27, hdr.ipv4.src_addr,
    //         5w8, hdr.ipv4.dst_addr,
    //         4w8, hdr.tcp.src_port,
    //         6w6, hdr.tcp.dst_port
    //     });
    //     ig_md.hashed_index_row_1 = hash_1_TCP.get({
    //         4w2, hdr.ipv4.src_addr,
    //         4w13, hdr.ipv4.dst_addr,
    //         3w1, hdr.tcp.src_port,
    //         4w3, hdr.tcp.dst_port
    //     });
    // }
    // action calc_hashed_index_UDP(){
    //     ig_md.hashed_index_row_0 = hash_0_UDP.get({
    //         5w20, hdr.ipv4.src_addr,
    //         4w2, hdr.ipv4.dst_addr,
    //         6w28, hdr.udp.src_port,
    //         5w19, hdr.udp.dst_port
    //     });
    //     ig_md.hashed_index_row_1 = hash_1_UDP.get({
    //         5w11, hdr.ipv4.src_addr,
    //         5w3, hdr.ipv4.dst_addr,
    //         3w2, hdr.udp.src_port,
    //         3w2, hdr.udp.dst_port
    //     });
    // }
    // action calc_hashed_index_Other(){
    //     ig_md.hashed_index_row_0 = hash_0_Other.get({
    //         3w0, hdr.ipv4.src_addr,
    //         3w3, hdr.ipv4.dst_addr,
    //         4w2, hdr.ipv4.protocol
    //     });
    //     ig_md.hashed_index_row_1 = hash_1_Other.get({
    //         4w0, hdr.ipv4.src_addr,
    //         5w6, hdr.ipv4.dst_addr,
    //         3w7, hdr.ipv4.protocol
    //     });
    // }

    action prep_reads(){
        ig_md.snap_0_row_0_read=0;
        ig_md.snap_0_row_1_read=0;
        ig_md.snap_1_row_0_read=0;
        ig_md.snap_1_row_1_read=0;
        ig_md.snap_2_row_0_read=0;
        ig_md.snap_2_row_1_read=0;
        ig_md.snap_3_row_0_read=0;
        ig_md.snap_3_row_1_read=0;
    }
         
    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; 
        exit;
    }

    //== Prepare register access index options
    Register<bit<32>,_>(1) reg_cleaning_index;
    RegisterAction<bit<32>, _, bit<32>>(reg_cleaning_index) reg_cleaning_index_rw = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
            val = val + 1;
        }
    };
    action calc_cyclic_index(){
        ig_md.cyclic_index = (bit<14>) reg_cleaning_index_rw.execute(0);
    }

    // SNAPSHOT 0
    action snap_0_select_index_hash(){
        // READ or WRITE
        ig_md.snap_0_row_0_index=ig_md.hashed_index_row_0;
        ig_md.snap_0_row_1_index=ig_md.hashed_index_row_1;
    }
    action snap_0_select_index_cyclic(){
        // CLEAN
        ig_md.snap_0_row_0_index=ig_md.cyclic_index;
        ig_md.snap_0_row_1_index=ig_md.cyclic_index;
    }
    table tb_snap_0_select_index {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            snap_0_select_index_hash;
            snap_0_select_index_cyclic;
        }
        // size = 2;
        default_action = snap_0_select_index_hash();
        const entries = {
            1 : snap_0_select_index_cyclic();   // CLEAN
        }
    }
    // SNAPSHOT 1
    action snap_1_select_index_hash(){
        // READ or WRITE
        ig_md.snap_1_row_0_index=ig_md.hashed_index_row_0;
        ig_md.snap_1_row_1_index=ig_md.hashed_index_row_1;
    }
    action snap_1_select_index_cyclic(){
        // CLEAN    
    }
    table tb_snap_1_select_index {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            snap_1_select_index_hash;
            snap_1_select_index_cyclic;
        }
        // size = 2;
        default_action = snap_1_select_index_hash();
        const entries = {
            2 : snap_1_select_index_cyclic(); // CLEAN
        }
    }
    // SNAPSHOT 2
    action snap_2_select_index_hash(){
        // READ or WRITE
        ig_md.snap_2_row_0_index=ig_md.hashed_index_row_0;
        ig_md.snap_2_row_1_index=ig_md.hashed_index_row_1;
    }
    action snap_2_select_index_cyclic(){
        // CLEAN
        ig_md.snap_2_row_0_index=ig_md.cyclic_index;
        ig_md.snap_2_row_1_index=ig_md.cyclic_index;
    }
    table tb_snap_2_select_index {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            snap_2_select_index_hash;
            snap_2_select_index_cyclic;
        }
        size = 2;
        default_action = snap_2_select_index_hash();
        const entries = {
            3 : snap_2_select_index_cyclic();   // CLEAN
        }
    }
    // SNAPSHOT 3
    action snap_3_select_index_hash(){
        // READ or WRITE
        ig_md.snap_3_row_0_index=ig_md.hashed_index_row_0;
        ig_md.snap_3_row_1_index=ig_md.hashed_index_row_1;
    }
    action snap_3_select_index_cyclic(){
        // CLEAN    
        ig_md.snap_3_row_0_index=ig_md.cyclic_index;
        ig_md.snap_3_row_1_index=ig_md.cyclic_index;
    }
    table tb_snap_3_select_index {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            snap_3_select_index_hash;
            snap_3_select_index_cyclic;
        }
        // size = 2;
        default_action = snap_3_select_index_hash();
        const entries = {
            0 : snap_3_select_index_cyclic();   // CLEAN
        }
    }
    
    // SNAPSHOT 0
    Register<bit<32>,_>(SKETCH_SIZE) snap_0_row_0;
    RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_0_row_0_read(){
        ig_md.snap_0_row_0_read=snap_0_row_0_read.execute(ig_md.snap_0_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_0_row_0_inc(){
        ig_md.snap_0_row_0_read=snap_0_row_0_inc.execute(ig_md.snap_0_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_0_row_0_clr(){
        snap_0_row_0_clr.execute(ig_md.snap_0_row_0_index);
    }
    table tb_snap_0_row_0_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_0_row_0_read;
            regexec_snap_0_row_0_inc;
            regexec_snap_0_row_0_clr;
            // NoAction;
        }
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_0_row_0_inc();
        //     1 : regexec_snap_0_row_0_clr();
        //     2 : regexec_snap_0_row_0_read();
        //     3 : regexec_snap_0_row_0_read();
        // }
        // size = 4;
    }
    Register<bit<32>,_>(SKETCH_SIZE) snap_0_row_1;
    RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_0_row_1_read(){
        ig_md.snap_0_row_1_read=snap_0_row_1_read.execute(ig_md.snap_0_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_0_row_1_inc(){
        ig_md.snap_0_row_1_read=snap_0_row_1_inc.execute(ig_md.snap_0_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_0_row_1_clr(){
        snap_0_row_1_clr.execute(ig_md.snap_0_row_1_index);
    }
    table tb_snap_0_row_1_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_0_row_1_read;
            regexec_snap_0_row_1_inc;
            regexec_snap_0_row_1_clr;
            // NoAction;
        }
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_0_row_1_inc(); 
        //     1 : regexec_snap_0_row_1_clr();
        //     2 : regexec_snap_0_row_1_read();
        //     3 : regexec_snap_0_row_1_read();
        // }
        // size = 4;
    }

    // SNAPSHOT 1
    Register<bit<32>,_>(SKETCH_SIZE) snap_1_row_0;
    RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_1_row_0_read(){
        ig_md.snap_1_row_0_read=snap_1_row_0_read.execute(ig_md.snap_1_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_1_row_0_inc(){
        ig_md.snap_1_row_0_read=snap_1_row_0_inc.execute(ig_md.snap_1_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_1_row_0_clr(){
        snap_1_row_0_clr.execute(ig_md.snap_1_row_0_index);
    }
    table tb_snap_1_row_0_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_1_row_0_read;
            regexec_snap_1_row_0_inc;
            regexec_snap_1_row_0_clr;
            // NoAction;
        }
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_1_row_0_read();
        //     1 : regexec_snap_1_row_0_inc();
        //     2 : regexec_snap_1_row_0_clr();
        //     3 : regexec_snap_1_row_0_read();
        // }
        // size = 4;
    }
    Register<bit<32>,_>(SKETCH_SIZE) snap_1_row_1;
    RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_1_row_1_read(){
        ig_md.snap_1_row_1_read=snap_1_row_1_read.execute(ig_md.snap_1_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_1_row_1_inc(){
        ig_md.snap_1_row_1_read=snap_1_row_1_inc.execute(ig_md.snap_1_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_1_row_1_clr(){
        snap_1_row_1_clr.execute(ig_md.snap_1_row_1_index);
    }
    table tb_snap_1_row_1_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_1_row_1_read;
            regexec_snap_1_row_1_inc;
            regexec_snap_1_row_1_clr;
            // NoAction;
        }
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_1_row_1_read();
        //     1 : regexec_snap_1_row_1_inc();
        //     2 : regexec_snap_1_row_1_clr();
        //     3 : regexec_snap_1_row_1_read();
        // }
        // size = 4;
    }

    // SNAPSHOT 2
    Register<bit<32>,_>(SKETCH_SIZE) snap_2_row_0;
    RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_2_row_0_read(){
        ig_md.snap_2_row_0_read=snap_2_row_0_read.execute(ig_md.snap_2_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_2_row_0_inc(){
        ig_md.snap_2_row_0_read=snap_2_row_0_inc.execute(ig_md.snap_2_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_2_row_0_clr(){
        snap_2_row_0_clr.execute(ig_md.snap_2_row_0_index);
    }
    table tb_snap_2_row_0_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_2_row_0_read;
            regexec_snap_2_row_0_inc;
            regexec_snap_2_row_0_clr;
            // NoAction;
        }
        
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_2_row_0_read();
        //     1 : regexec_snap_2_row_0_read();
        //     2 : regexec_snap_2_row_0_inc();
        //     3 : regexec_snap_2_row_0_clr();
        // }
        // size = 4;
    }
    Register<bit<32>,_>(SKETCH_SIZE) snap_2_row_1;
    RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_2_row_1_read(){
        ig_md.snap_2_row_1_read=snap_2_row_1_read.execute(ig_md.snap_2_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_2_row_1_inc(){
        ig_md.snap_2_row_1_read=snap_2_row_1_inc.execute(ig_md.snap_2_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_2_row_1_clr(){
        snap_2_row_1_clr.execute(ig_md.snap_2_row_1_index);
    }
    table tb_snap_2_row_1_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_2_row_1_read;
            regexec_snap_2_row_1_inc;
            regexec_snap_2_row_1_clr;
            // NoAction;
        }
        
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_2_row_1_read();
        //     1 : regexec_snap_2_row_1_read();
        //     2 : regexec_snap_2_row_1_inc();
        //     3 : regexec_snap_2_row_1_clr();
        // }
        // size = 4;
    }

    // SNAPSHOT 3
    Register<bit<32>,_>(SKETCH_SIZE) snap_3_row_0;
    RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_3_row_0_read(){
        ig_md.snap_3_row_0_read=snap_3_row_0_read.execute(ig_md.snap_3_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_3_row_0_inc(){
        ig_md.snap_3_row_0_read=snap_3_row_0_inc.execute(ig_md.snap_3_row_0_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_3_row_0_clr(){
        snap_3_row_0_clr.execute(ig_md.snap_3_row_0_index);
    }
    table tb_snap_3_row_0_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_3_row_0_read;
            regexec_snap_3_row_0_inc;
            regexec_snap_3_row_0_clr;
            // NoAction;
        }
        
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_3_row_0_clr();
        //     1 : regexec_snap_3_row_0_read();
        //     2 : regexec_snap_3_row_0_read();
        //     3 : regexec_snap_3_row_0_inc();
        // }
        // size = 4;
    }
    Register<bit<32>,_>(SKETCH_SIZE) snap_3_row_1;
    RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_read = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    action regexec_snap_3_row_1_read(){
        ig_md.snap_3_row_1_read=snap_3_row_1_read.execute(ig_md.snap_3_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_inc = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + SKETCH_INC;
                rv = val;
            }
        };
    action regexec_snap_3_row_1_inc(){
        ig_md.snap_3_row_1_read=snap_3_row_1_inc.execute(ig_md.snap_3_row_1_index);
    }
    RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_clr = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = 0;
                rv = 0;
            }
        };
    action regexec_snap_3_row_1_clr(){
        snap_3_row_1_clr.execute(ig_md.snap_3_row_1_index);
    }
    table tb_snap_3_row_1_rr {
        key = {
            ig_md.snap_epoch: exact;
        }
        actions = {
            regexec_snap_3_row_1_read;
            regexec_snap_3_row_1_inc;
            regexec_snap_3_row_1_clr;
            // NoAction;
        }
        
        // default_action = NoAction();
        //round-robin logic
        // const entries = {
        //     0 : regexec_snap_3_row_1_clr();
        //     1 : regexec_snap_3_row_1_read();
        //     2 : regexec_snap_3_row_1_read();
        //     3 : regexec_snap_3_row_1_inc();
        // }
        // size = 4;
    }

    //== Folding sums, which can't be written inline 
    action calc_sum_0_l0(){
        ig_md.snap_0_read_min_l1 = 
        ig_md.snap_0_read_min_l0 + ig_md.snap_1_read_min_l0;
    }
    action calc_sum_2_l0(){
        ig_md.snap_2_read_min_l1 = 
        ig_md.snap_2_read_min_l0 + ig_md.snap_3_read_min_l0;
    }

    action calc_sum_0_l1(){
        ig_md.snap_0_read_min_l2 = 
        ig_md.snap_0_read_min_l1 + ig_md.snap_2_read_min_l1;
    }

    table threshold {
        key = {
            ig_md.snap_0_read_min_l2[19:0] : range; //scale down to 20 bits
        }
        actions = {
            NoAction;
            drop;
        }
        default_action = NoAction();
        size = 1;
    }

    apply {
        ig_md.snap_epoch = ig_intr_md.ingress_mac_tstamp[33:32];
        prep_reads();

        bit<32> index = hash_index.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                ig_md.src_port,
                ig_md.dst_port
            }
        );

        ig_md.hashed_index_row_0 = index[13:0];
        ig_md.hashed_index_row_1 = index[21:8];

        // if(hdr.ipv4.protocol==IP_PROTOCOLS_TCP){
        //     calc_hashed_index_TCP();
        // }else if(hdr.ipv4.protocol==IP_PROTOCOLS_UDP){
        //     calc_hashed_index_UDP();
        // }else{
        //     calc_hashed_index_Other();
        // }

        // Select index for snapshots. Cyclic for cleaning, hashed for read/inc
        // @stage(1){
        tb_snap_0_select_index.apply();
        tb_snap_1_select_index.apply();
        tb_snap_2_select_index.apply();
        tb_snap_3_select_index.apply();
        // }
        // Run the snapshots! Round-robin clean, inc, read
        tb_snap_0_row_0_rr.apply();
        tb_snap_0_row_1_rr.apply();
        tb_snap_1_row_0_rr.apply();
        tb_snap_1_row_1_rr.apply();
        tb_snap_2_row_0_rr.apply();
        tb_snap_2_row_1_rr.apply();
        tb_snap_3_row_0_rr.apply();
        tb_snap_3_row_1_rr.apply();

        // Calc min across rows (as in count-"min" sketch)
        ig_md.snap_0_read_min_l0=min(ig_md.snap_0_row_0_read,ig_md.snap_0_row_1_read);
        ig_md.snap_1_read_min_l0=min(ig_md.snap_1_row_0_read,ig_md.snap_1_row_1_read);
        ig_md.snap_2_read_min_l0=min(ig_md.snap_2_row_0_read,ig_md.snap_2_row_1_read);
        ig_md.snap_3_read_min_l0=min(ig_md.snap_3_row_0_read,ig_md.snap_3_row_1_read);

        // Sum all reads together, using log(CQ_H) layers.
        calc_sum_0_l0();
        calc_sum_2_l0();

        calc_sum_0_l1();

        // Check whether it exceeds threshold
        threshold.apply();
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    
    apply {
    
    }
}


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;