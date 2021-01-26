typedef bit<32> count_t;
typedef bit<8> window_t;

#define INCREMENT 1
#define SKETCH_CTR_PER_ROW 65536

control DSketch (
    inout switch_header_t hdr,
    in bit<8> ts,
    in bit<32> index,
    inout bit<32> flow_count,
    inout bit<9>  egress_port
    ) 
{    
    count_t     count_r0 = 0;
    window_t    diff_r0 = 0;
    count_t     count_r1 = 0;
    window_t    diff_r1 = 0;

    Register<count_t,_>(SKETCH_CTR_PER_ROW) sketch0;
    Register<window_t,_>(SKETCH_CTR_PER_ROW) window0;

    Register<count_t,_>(SKETCH_CTR_PER_ROW) sketch1;
    Register<window_t,_>(SKETCH_CTR_PER_ROW) window1;

    RegisterAction<count_t, _, count_t> (sketch0) sketch0_count = {
        void apply(inout count_t val, out count_t rv) {
            val = val |+| INCREMENT;
            rv = val;
        }
    };

    RegisterAction<count_t, _, count_t> (sketch0) sketch0_decay = {
        void apply(inout count_t val, out count_t rv) {
            val = hdr.decay_update.count_r0;
            rv = val;
        }
    };

    RegisterAction<window_t, _, window_t> (window0) window0_update = {
        void apply(inout window_t val, out window_t rv) {
            val = ts;
            rv = 0;
        }
    };

    RegisterAction<window_t, _, window_t> (window0) window0_diff = {
        void apply(inout window_t val, out window_t rv) {
            rv = ts - val;
        }
    };

    RegisterAction<count_t, _, count_t> (sketch1) sketch1_count = {
        void apply(inout count_t val, out count_t rv) {
            val = val |+| INCREMENT;
            rv = val;
        }
    };

    RegisterAction<count_t, _, count_t> (sketch1) sketch1_decay = {
        void apply(inout count_t val,  out count_t rv) {
            val = hdr.decay_update.count_r1;
            rv = val;
        }
    };

    RegisterAction<window_t, _, window_t> (window1) window1_update = {
        void apply(inout window_t val, out window_t rv) {
            val = ts;
            rv = 0;
        }
    };

    RegisterAction<window_t, _, window_t> (window1) window1_diff = {
        void apply(inout window_t val, out window_t rv) {
            rv = ts - val;
        }
    };

    action update_sketch0() {
        count_r0 = sketch0_count.execute(index[31:16]);
    }

    action decay_sketch0() {
        hdr.decay_update.setInvalid();
        count_r0 = sketch0_decay.execute(index[31:16]);
    }

     action update_sketch1() {
        count_r1 = sketch1_count.execute(index[15:0]);
    }

    action decay_sketch1() {
        hdr.decay_update.setInvalid();
        count_r1 =  sketch1_decay.execute(index[15:0]);
    }

     action diff_window0() {
        diff_r0 = window0_diff.execute(index[31:16]);
    }

    action update_window0() {
        diff_r0 = window0_update.execute(index[31:16]);
    }

      action diff_window1() {
        diff_r1 = window1_diff.execute(index[15:0]);
    }

    action update_window1() {
        diff_r1 = window1_update.execute(index[15:0]);
    }

    action zero0 (bit<9> recirc_port) {
        hdr.decay_update.setValid();
        egress_port = recirc_port;
        hdr.ethernet.ether_type = ETHERTYPE_DECAY_UPDATE;
        hdr.decay_update.ether_type = ETHERTYPE_IPV4;
        hdr.decay_update.count_r0 = count_r0;
    }

    action shift0(bit<9> recirc_port) {
        hdr.decay_update.setValid();
        egress_port = recirc_port; 
        hdr.ethernet.ether_type = ETHERTYPE_DECAY_UPDATE;
        hdr.decay_update.ether_type = ETHERTYPE_IPV4;
        hdr.decay_update.count_r0 = count_r0 >> 1;
    }

    action zero1 (bit<9> recirc_port) {
        hdr.decay_update.setValid();
        egress_port = recirc_port;  
        hdr.ethernet.ether_type = ETHERTYPE_DECAY_UPDATE;
        hdr.decay_update.ether_type = ETHERTYPE_IPV4;
        hdr.decay_update.count_r1 = count_r1;
    }

    action shift1(bit<9> recirc_port) {
        hdr.decay_update.setValid();
        egress_port = recirc_port; 
        hdr.ethernet.ether_type = ETHERTYPE_DECAY_UPDATE;
        hdr.decay_update.ether_type = ETHERTYPE_IPV4;
        hdr.decay_update.count_r1 = count_r1 >> 1;
    }

    table sketch00 {
        key = {
            hdr.decay_update.isValid() : exact;
        }
        actions = {
            update_sketch0;
            decay_sketch0;
        }
        const entries = {
            false : update_sketch0();
            true : decay_sketch0();
        }
    }

    table sketch11 {
        key = {
            hdr.decay_update.isValid() : exact;
        }
        actions = {
            update_sketch1;
            decay_sketch1;
        }
        const entries = {
            false : update_sketch1();
            true : decay_sketch1();
        }
    }

    table window00 {
        key = {
            hdr.decay_update.isValid() : exact;
        }
        actions = {
            diff_window0;
            update_window0;
        }
        const entries = {
            false : diff_window0();
            true : update_window0();
        }
    }

      table window11 {
        key = {
            hdr.decay_update.isValid() : exact;
        }
        actions = {
            diff_window1;
            update_window1;
        }
        const entries = {
            false : diff_window1();
            true : update_window1();
        }
        size = 2;
    }

     table decay0 {
        key = {
            diff_r0 : exact;
        }
        actions = {
            zero0;
            shift0;
            NoAction;
        }
        // const entries = {
        //     0 : NoAction();
        //     1 : shift0(192);
        // }
        // default_action = zero0(192);
    }

    table decay1 {
        key = {
            diff_r1 : exact;
        }
        actions = {
            zero1;
            shift1;
            NoAction;
        }
        // const entries = {
        //     0 : NoAction();
        //     1 : shift1(192);
        // }
        // default_action = zero1(192);
    }

    apply {
        sketch00.apply();
        sketch11.apply();
        window00.apply();
        window11.apply();
        flow_count = min(count_r1, count_r0);
        decay0.apply();
        decay1.apply();
    }
}