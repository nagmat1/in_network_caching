/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/

/* Header Stuff */
enum bit<16> ether_type_t {
    TPID = 0x8100,
    IPV4 = 0x0800,
    ARP  = 0x0806,
    IPV6 = 0x86DD,
    MPLS = 0x8847
}

enum bit<8> ip_protocol_t {
    ICMP = 1,
    IGMP = 2,
    TCP  = 6,
    UDP  = 17
}

enum bit<16> arp_opcode_t {
    REQUEST = 1,
    REPLY   = 2
}

enum bit<8> icmp_type_t {
    ECHO_REPLY   = 0,
    ECHO_REQUEST = 8
}

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

/* Metadata and Table Stuff */
const int IPV4_HOST_SIZE = 65536;
const int IPV4_LPM_SIZE  = 12288;

#define NEXTHOP_ID_WIDTH 14
typedef bit<NEXTHOP_ID_WIDTH> nexthop_id_t;
const int NEXTHOP_SIZE = 1 << NEXTHOP_ID_WIDTH;

/*
 * Portable Types for PortId and MirrorID that do not depend on the target
 */
typedef bit<16> P_PortId_t;
typedef bit<16> P_MirrorId_t;
typedef bit<8>  P_QueueId_t;

typedef bit<7> PortId_Pad_t;
typedef bit<6> MirrorId_Pad_t;
typedef bit<3> QueueId_Pad_t;
#define MIRROR_DEST_TABLE_SIZE 256

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}

header vlan_tag_h {
    bit<3>        pcp;
    bit<1>        cfi;
    bit<12>       vid;
    ether_type_t  ether_type;
}

header ipv4_h {
    bit<4>          version;
    bit<4>          ihl;
    bit<8>          diffserv;
    bit<16>         total_len;
    bit<16>         identification;
    bit<3>          flags;
    bit<13>         frag_offset;
    bit<8>          ttl;
    ip_protocol_t   protocol;
    bit<16>         hdr_checksum;
    ipv4_addr_t     src_addr;
    ipv4_addr_t     dst_addr;
}

header ipv4_option_h {	
    bit<24> deq_qdepth;
    bit<8> deq_congest_stat;

    //bit<32> deq_congest_stat;
    //bit<32> enq_qdepth; 
    //bit<32> enq_congest_stat;	
	//varbit<320> data;
}

header icmp_h {
    icmp_type_t msg_type;
    bit<8>      msg_code;
    bit<16>     checksum;
}

header arp_h {
    bit<16>       hw_type;
    ether_type_t  proto_type;
    bit<8>        hw_addr_len;
    bit<8>        proto_addr_len;
    arp_opcode_t  opcode;
}

header arp_ipv4_h {
    mac_addr_t   src_hw_addr;
    ipv4_addr_t  src_proto_addr;
    mac_addr_t   dst_hw_addr;
    ipv4_addr_t  dst_proto_addr;
}

/*** Internal Headers ***/

typedef bit<4> header_type_t;
typedef bit<4> header_info_t;

const header_type_t HEADER_TYPE_BRIDGE         = 0xB;
const header_type_t HEADER_TYPE_MIRROR_INGRESS = 0xC;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 0xD;

/*
 * This is a common "preamble" header that must be present in all internal
 * headers. The only time you do not need it is when you know that you are
 * not going to have more than one internal header type ever
 */

#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info


header inthdr_h {
    INTERNAL_HEADER;
}

/* Bridged metadata */
header bridge_h {
    INTERNAL_HEADER;

#ifdef FLEXIBLE_HEADERS
    @flexible     PortId_t ingress_port;
    @flexible     bit<48>  ingress_mac_tstamp;
    @flexible     bit<48>  ingress_global_tstamp;
#else
    @padding PortId_Pad_t    pad0; PortId_t   ingress_port;
                                   bit<48>    ingress_mac_tstamp;
                                   bit<48>    ingress_global_tstamp;
#endif
}

/* Ingress mirroring information */
const MirrorType_t ING_PORT_MIRROR = 3;

header ing_port_mirror_h {
    INTERNAL_HEADER;

#ifdef FLEXIBLE_HEADERS
    @flexible     PortId_t    ingress_port;
    @flexible     MirrorId_t  mirror_session;
    @flexible     bit<48>     ingress_mac_tstamp;
    @flexible     bit<48>     ingress_global_tstamp;
#else
    @padding PortId_Pad_t    pad0; PortId_t    ingress_port;
    @padding MirrorId_Pad_t  pad1; MirrorId_t  mirror_session;
                                   bit<48>     ingress_mac_tstamp;
                                   bit<48>     ingress_global_tstamp;
#endif
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    bridge_h           bridge;
    ethernet_h         ethernet;
    vlan_tag_h[2]      vlan_tag;
    arp_h              arp;
    arp_ipv4_h         arp_ipv4;
    ipv4_h             ipv4;
    ipv4_option_h     ipv4_option;
    icmp_h             icmp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    ipv4_addr_t   dst_ipv4;
    bit<1>        ipv4_csum_err;
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info;
    PortId_t       ingress_port;
    MirrorId_t     mirror_session;
    bit<48>        ingress_mac_tstamp;
    bit<48>        ingress_global_tstamp;

}

    /***********************  P A R S E R  **************************/

parser IngressParser(packet_in      pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    Checksum() ipv4_checksum;

    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
	meta = { 0, 0, 0, 0, 0, 0, 0, 0 };
	
	hdr.bridge.setValid();
        hdr.bridge.header_type  = HEADER_TYPE_BRIDGE;
        hdr.bridge.header_info  = 0;

        hdr.bridge.ingress_port = ig_intr_md.ingress_port;
        hdr.bridge.ingress_mac_tstamp = ig_intr_md.ingress_mac_tstamp;

        meta.ipv4_csum_err = 0;
        meta.dst_ipv4      = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.TPID :  parse_vlan_tag;
            ether_type_t.IPV4 :  parse_ipv4;
            ether_type_t.ARP  :  parse_arp;
            default:  accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ether_type_t.TPID :  parse_vlan_tag;
            ether_type_t.IPV4 :  parse_ipv4;
            ether_type_t.ARP  :  parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.dst_ipv4 = hdr.ipv4.dst_addr;
        ipv4_checksum.add(hdr.ipv4);

        transition select(hdr.ipv4.ihl) {
            0x5 : parse_ipv4_no_options;
            0x6 &&& 0xE : parse_ipv4_options;
            0x8 &&& 0x8 : parse_ipv4_options;
            default: reject; // Currently the same as accept
        }
    }

    state parse_ipv4_options {
        pkt.extract(hdr.ipv4_option);
          //  ((bit<32>)hdr.ipv4.ihl - 32w5) * 32);

        ipv4_checksum.add(hdr.ipv4_option);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
        meta.ipv4_csum_err = (bit<1>)ipv4_checksum.verify();
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            ( 0, ip_protocol_t.ICMP ) : parse_icmp;
            default     : accept;
        }
    }    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
            (0x0001, ether_type_t.IPV4) : parse_arp_ipv4;
            default: reject; // Currently the same as accept
        }
    }

    state parse_arp_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.dst_proto_addr;
        transition accept;
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
    nexthop_id_t    nexthop_id  = 0;
    mac_addr_t      mac_da      = 0;
    mac_addr_t      mac_sa      = 0;
    PortId_t        egress_port = 511; /* Non-existent port */
    bit<8>          ttl_dec     = 0;

    /****************** IPv4 Lookup ********************/
    action set_nexthop(nexthop_id_t nexthop) {
        nexthop_id = nexthop;
    }

    table ipv4_host {
        key     = { meta.dst_ipv4 : exact; }
        actions = { set_nexthop;  @defaultonly NoAction; }
        size    = IPV4_HOST_SIZE;
        const default_action = NoAction();
    }

    table ipv4_lpm {
        key            = { meta.dst_ipv4 : lpm; }
        actions        = { set_nexthop; }

        default_action = set_nexthop(0);
        size           = IPV4_LPM_SIZE;
    }

    /****************** Nexthop ********************/
    action send(PortId_t port) {
        mac_da      = hdr.ethernet.dst_addr;
        mac_sa      = hdr.ethernet.src_addr;
        egress_port = port;
        ttl_dec     = 0;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action l3_switch(PortId_t port, bit<48> new_mac_da, bit<48> new_mac_sa) {
        mac_da      = new_mac_da;
        mac_sa      = new_mac_sa;
        egress_port = port;
        ttl_dec     = 1;
    }

    table nexthop {
        key            = { nexthop_id : exact; }
        actions        = { send; drop; l3_switch; }
        size           = NEXTHOP_SIZE;
        default_action = drop();
    }

     /********* MIRRORING ************/
    action acl_mirror(MirrorId_t mirror_session) {
        ig_dprsr_md.mirror_type = ING_PORT_MIRROR;

        meta.mirror_header_type = HEADER_TYPE_MIRROR_INGRESS;
        meta.mirror_header_info = (header_info_t)ING_PORT_MIRROR;

        meta.ingress_port   = ig_intr_md.ingress_port;
        meta.mirror_session = mirror_session;

        meta.ingress_mac_tstamp    = ig_intr_md.ingress_mac_tstamp;
        meta.ingress_global_tstamp = ig_prsr_md.global_tstamp;
    }

    action acl_drop_and_mirror(MirrorId_t mirror_session) {
        acl_mirror(mirror_session);
        drop();
    }

    table port_acl {
        key = {
            ig_intr_md.ingress_port : ternary;
        }
        actions = {
            acl_mirror; acl_drop_and_mirror; drop; NoAction;
        }
        size = 512;
        default_action = NoAction();
    }


    /****************** Metadata Processing ********************/

    action send_back() {
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action forward_ipv4() {
        hdr.ethernet.dst_addr      = mac_da;
        hdr.ethernet.src_addr      = mac_sa;
        hdr.ipv4.ttl               = hdr.ipv4.ttl |-| ttl_dec;
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action send_arp_reply() {
        hdr.ethernet.dst_addr = hdr.arp_ipv4.src_hw_addr;
        hdr.ethernet.src_addr = mac_da;

        hdr.arp.opcode = arp_opcode_t.REPLY;
        hdr.arp_ipv4.dst_hw_addr    = hdr.arp_ipv4.src_hw_addr;
        hdr.arp_ipv4.dst_proto_addr = hdr.arp_ipv4.src_proto_addr;
        hdr.arp_ipv4.src_hw_addr    = mac_da;
        hdr.arp_ipv4.src_proto_addr = meta.dst_ipv4;

        send_back();
    }

    action send_icmp_echo_reply() {
        mac_addr_t  tmp_mac  = hdr.ethernet.src_addr;
        ipv4_addr_t tmp_ipv4 = hdr.ipv4.src_addr;

        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = tmp_mac;

        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_ipv4;

        hdr.ipv4.ttl      = hdr.ipv4.ttl |-| ttl_dec; /* Optional */
        hdr.icmp.msg_type = icmp_type_t.ECHO_REPLY;
        hdr.icmp.checksum = 0;

        send_back();
    }

    table forward_or_respond {
        key = {
            hdr.arp.isValid()       : exact;
            hdr.arp_ipv4.isValid()  : exact;
            hdr.ipv4.isValid()      : exact;
            hdr.icmp.isValid()      : exact;
            hdr.arp.opcode          : ternary;
            hdr.icmp.msg_type       : ternary;
        }
        actions = {
            forward_ipv4;
            send_arp_reply;
            send_icmp_echo_reply;
            drop;
        }
        const entries = {
            (false, false, true,  false, _, _) :
            forward_ipv4();

            (true,  true,  false, false, arp_opcode_t.REQUEST, _ ) :
            send_arp_reply();

            (false, false, true,   true, _, icmp_type_t.ECHO_REQUEST) :
            send_icmp_echo_reply();

            (false, false, true,   true, _, _) :
            forward_ipv4();
        }
        default_action = drop();
    }

    /* The algorithm */
    apply {
        if (meta.ipv4_csum_err == 0) {         /* No checksum error for ARP! */
            if (!ipv4_host.apply().hit) {
                ipv4_lpm.apply();
            }
        }

        nexthop.apply();
        forward_or_respond.apply();
	port_acl.apply();
	hdr.bridge.ingress_global_tstamp = ig_prsr_md.global_tstamp;
    }
}

    /*********************  D E P A R S E R  ************************/
#ifdef FLEXIBLE_HEADERS
#define PAD(field)  field
#else
#define PAD(field)  0, field
#endif

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    Mirror()   ing_port_mirror;

    apply {
	if (ig_dprsr_md.mirror_type == ING_PORT_MIRROR) {
            ing_port_mirror.emit<ing_port_mirror_h>(
                meta.mirror_session,
                {
                    meta.mirror_header_type, meta.mirror_header_info,
                    PAD(meta.ingress_port),
                    PAD(meta.mirror_session),
                    meta.ingress_mac_tstamp,
                    meta.ingress_global_tstamp
                });
        }


        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4_option.deq_qdepth,
		hdr.ipv4_option.deq_congest_stat
		//hdr.ipv4_option.deq_congest_stat 
		//hdr.ipv4_option.enq_qdepth, 
		//hdr.ipv4_option.enq_congest_stat
            });
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
    ipv4_option_h ipv4_option;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    inthdr_h           inthdr;
    bridge_h           bridge;
    MirrorId_t         mirror_session;
    bool               ing_mirrored;
    bool               egr_mirrored;
    ing_port_mirror_h  ing_port_mirror;
    header_type_t      mirror_header_type;
    header_info_t      mirror_header_info;
    MirrorId_t         egr_mirror_session;
    bit<16>            egr_mirror_pkt_length;

}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    Checksum() ipv4_checksum;
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
	meta.mirror_session        = 0;
        meta.ing_mirrored          = false;
        meta.egr_mirrored          = false;
        meta.mirror_header_type    = 0;
        meta.mirror_header_info    = 0;
        meta.egr_mirror_session    = 0;
        meta.egr_mirror_pkt_length = 0;

        pkt.extract(eg_intr_md);

	meta.inthdr = pkt.lookahead<inthdr_h>();
	
	transition select(meta.inthdr.header_type, meta.inthdr.header_info) {
            ( HEADER_TYPE_BRIDGE,         _ ) :
                           parse_bridge;
            ( HEADER_TYPE_MIRROR_INGRESS, (header_info_t)ING_PORT_MIRROR ):
                           parse_ing_port_mirror;
            default : parse_ethernet;
        }
    }

    state parse_bridge {
        pkt.extract(meta.bridge);
        transition accept;
    }

    state parse_ing_port_mirror {
        pkt.extract(meta.ing_port_mirror);
        meta.ing_mirrored   = true;
        meta.mirror_session = meta.ing_port_mirror.mirror_session;
        transition accept;
    }


    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.TPID:  parse_vlan_tag;
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ether_type_t.IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
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
    action just_send() {}

    table mirror_dest {
        key = {
            meta.ing_mirrored       : ternary;
            meta.egr_mirrored       : ternary;
            meta.mirror_session     : exact;
        }

        actions = {
            just_send;
        }
        default_action = just_send();
        size = MIRROR_DEST_TABLE_SIZE;
    }

    /********* EGRESS MIRRORING ************/
    action drop() {
        eg_dprsr_md.drop_ctl = 1;
    }


    action add_queue()
        {
             hdr.ipv4.ihl = 6;
             hdr.ipv4_option.setValid();
             hdr.ipv4.total_len = hdr.ipv4.total_len + 4;
             hdr.ipv4_option.deq_qdepth       = (bit<24>) eg_intr_md.deq_qdepth;
	     hdr.ipv4_option.deq_congest_stat = (bit<8>) eg_intr_md.deq_congest_stat;
	     //hdr.ipv4_option.enq_qdepth       = (bit<32>) eg_intr_md.enq_qdepth; 
	     //hdr.ipv4_option.enq_congest_stat = (bit<32>) eg_intr_md.enq_congest_stat; 
        }

    table ipv4_host {
        actions = {
                add_queue;
                NoAction;
        }
        default_action = add_queue;
        }


    apply {
	if (hdr.ipv4.isValid())
        {
        	ipv4_host.apply();
        }

        if (meta.ing_port_mirror.isValid())
           {mirror_dest.apply();
        }

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
    Checksum() ipv4_checksum;
    Mirror() egr_port_mirror;

    apply {
	 hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4_option.deq_qdepth,
		hdr.ipv4_option.deq_congest_stat 
 	//      hdr.ipv4_option.deq_congest_stat
	//	hdr.ipv4_option.enq_qdepth,
	//	hdr.ipv4_option.enq_congest_stat
            });

        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
