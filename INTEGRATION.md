# Integrating `dSketch`

Here, we discuss the steps to integrate `dSketch` in to existing P4_16 programs for the Intel Tofino-based switches.
We use the commodity programmable switch, `switch.p4` as the example in this case. The same applies for other programs.

## Overview
We provide two functional equivalent variants of the `dSketch` module. One in in-line style while the other in match-action-table style. However, both of them have slight differences in terms of memory consumption with the latter requiring more memory to maintain the table entries.

The `dSketch` module is wrapped in the form of a control block. It requires 5 parameters.
```
control DSketch (
    inout switch_header_t hdr,
    in bit<8> ts,
    in bit<32> index,
    inout bit<32> flow_count,
    inout bit<9>  egress_port
    ) 
{
    ...  
}
```

- `inout switch_header_t hdr` : headers used in the main program.
- `in bit<8> ts` : sliced from the 48-bit timestamp.
- `in bit<32> index` : output from hash functions.
- `inout bit<32> flow_count` : metadata/ variable to store the flow count output from `dSketch`
- `inout bit<9>  egress_port` : egress port field for traffic manager

## Headers & Constants
As we rely on (cloned) recirculated packets to update `dSketch` with the decayed counts, we require a special header to carry the necessary information (i.e., decayed counts). To ease the packet parsing process, we define a header formatted similarly as a VLAN which contains an ethernet type field to store the original ethernet type. 

Recirculated packets carrying the decay update header will be set with ethernet type `0xDECA`.
The decay update header should be declared right after the ethernet header.

```
#define ETHERTYPE_DECAY_UPDATE 0xDECA

header decay_update_h {
    bit<32> count_r0;
    bit<32> count_r1;
    bit<16> ether_type;
}

struct switch_header_t {
    ...
    ethernet_h ethernet;
    decay_update_h decay_update;
    ...
}
```

## Parsers
To parse the (cloned and) recirculated packets, we look for the special ethernet type `0xDECA` when parsing the ethernet frame. This requires modifications to the existing parsers (see below). Then, we extract  the information from the decay update header before continuing to parse the remaining headers as usual using the carried ethernet type in the header.

```
state parse_ethernet {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type, ig_intr_md.ingress_port) {
        ...
        (ETHERTYPE_DECAY_UPDATE, _) : parse_decay_update;
        ...
    }
}

state parse_decay_update {
    pkt.extract(hdr.decay_update);
    transition select(hdr.decay_update.ether_type) {
        ...
    }
}
```

## Integrating `dSketch`
To integrate `dSketch`, we include `dsketch.p4` into the main program. Then, we initialize an instance of `dSketch` in the Ingress control block before applying it in the `apply` block with the necessary parameters.
This completes the integration.

> Note: `dSketch` can only work in the Ingress control block.

```
#include "dsketch.p4"
...

SwitchIngress(...) {
    ...
    DSketch() dsketch;
    ...

    apply {
        ...
        dsketch.apply(
            hdr,                                    // switch headers
            ig_md.timestamp[40:33],                 // timestamp (from metadata)
            ig_md.hash[31:0],                       // hash (from metadata)
            ig_md.flow_count,                       // flow count (to write to metadata)
            ig_intr_md_for_tm.ucast_egress_port     // egress port (for traffic manager)
        );
        ...
    }
} 

```

