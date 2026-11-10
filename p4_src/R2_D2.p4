#include <core.p4>
#include <tna.p4>

#include "headers.p4"

#define COUPONS 2048
#define SKETCH_LENGTH 131072  // Length of each row in the sketch




/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out ingress_headers_t          hdr,
    out ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start{
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    /* Initialize custom Ingress metadata */
    state meta_init{
        meta.five_tuple = {0,0,0,0,0};
        meta.tmp_srcip = 0;
        meta.tmp_srcport = 0;
        meta.states = 0;
        meta.task_id = 0;
        meta.sketch_id = 0;
        meta.m_options = 0;
        meta.check_sum_flags = {false, false, false};
        meta.in_or_out = 1;
        meta.cookie = 0;
        meta.cookie_verification = 0;
        meta.color = 0;
        meta.row_index = 0;
        meta.index1 = 0;
        meta.index2 = 0;
        meta.index3 = 0;
        meta.index4 = 0;
        meta.reg_upd_val = 1;
        meta.check_sum_tmp = 0;
        meta.param = 0;
        meta.result = 65535;
        transition parse_ethernet;
    }

    /* Parse Ethernet header */
    state parse_ethernet{
        pkt.extract(hdr.ethernet);
        meta.tmp_srcaddr = hdr.ethernet.src_addr;
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default:  accept;
        }
    }

    /* Parse IPv4 header */
    state parse_ipv4{
        pkt.extract(hdr.ipv4);
        meta.five_tuple.src_addr = hdr.ipv4.src_addr;
        meta.five_tuple.dst_addr = hdr.ipv4.dst_addr;
        meta.five_tuple.protocol = hdr.ipv4.protocol;
        meta.tmp_srcip = hdr.ipv4.src_addr; 
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_ICMP: parse_icmp;
            PROTOCOL_TCP:  parse_tcp;
            PROTOCOL_UDP:  parse_udp;
            default: accept;
        }
    }

    /* Parse ICMP header */
    state parse_icmp {
        pkt.extract(hdr.icmp);
        meta.states = hdr.icmp.type;        
        transition accept;
    }

    /* Parse TCP header */
    state parse_tcp{
        pkt.extract(hdr.ports);
        meta.five_tuple.src_port = hdr.ports.src_port;
        meta.five_tuple.dst_port = hdr.ports.dst_port;
        meta.tmp_srcport = hdr.ports.src_port;
        
        pkt.extract(hdr.tcp);
        meta.states = hdr.tcp.flags;

        transition accept;
    }

    /* Parse UDP header */
    state parse_udp{
        pkt.extract(hdr.ports);
        meta.five_tuple.src_port = hdr.ports.src_port;
        meta.five_tuple.dst_port = hdr.ports.dst_port;
        meta.tmp_srcport = hdr.ports.src_port;
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout ingress_headers_t                          hdr,
    inout ingress_metadata_t                         meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    /* Drop the packet */
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* No-op action (empty action) */
    action noaction() {}

    /***************** Transport and Network Layer Defense Phase - Ingress *********************/
    
    
    /**** Dynamic hash for flexible memory access ****/

    // Five-tuple hash (src IP, dst IP, src port, dst port, protocol)
    action set_five_hash() {
        
    }
    
    // Session hash (hash based on session-level identifiers, e.g., flow or connection context)
    action set_session_hash() {
        meta.five_tuple.src_addr = meta.five_tuple.dst_addr;
        meta.five_tuple.dst_addr = meta.tmp_srcip;
        meta.five_tuple.src_port = meta.five_tuple.dst_port;
        meta.five_tuple.dst_port = meta.tmp_srcport;
    }
    
    // Three-tuple hash (src IP, dst IP, protocol)
    action set_three_hash() {
        meta.five_tuple.src_port = 0;
        meta.five_tuple.dst_port = 0;
    }

    @pragma stage 0
    table dynamic_hash{
        key = {
            ig_intr_md.ingress_port :exact;
            hdr.ipv4.protocol : exact;
            meta.states : range;
        }
        actions = {
            set_five_hash;
            set_session_hash;
            set_three_hash;
            noaction;
        }
        const default_action = noaction();
        size = 128;
    }

    /**** Generate or retrieve SYN cookie ****/
    Hash<bit<32>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<32>> (32w0x63a957be, true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF)) hash_unit_five;
    action hash_cookie_fun() {
        meta.cookie = hash_unit_five.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                             meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                             meta.five_tuple.protocol });
    }
    @pragma stage 1
    table tbl_hash_cookie{
        actions = {
            hash_cookie_fun;
        }
        const default_action = hash_cookie_fun();
        size = 1;
    }

    /**** Calculate virtual index ****/
    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0x3f0b, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit1;
    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0xf523, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit2;
    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0x7024, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit3;
    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0x0f79, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit4;

    action hash1_fun() {
        meta.index1[15:0] = hash_unit1.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                             meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                             meta.five_tuple.protocol });
    }
    action hash2_fun() {
        meta.index2[15:0] = hash_unit2.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                             meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                             meta.five_tuple.protocol });
    }
    action hash3_fun() {
        meta.index3[15:0] = hash_unit3.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                             meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                             meta.five_tuple.protocol });
    }
    action hash4_fun() {
        meta.index4[15:0] = hash_unit4.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                             meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                             meta.five_tuple.protocol });
    }
    @pragma stage 1
    table tlb_hash1{
        actions = {
            hash1_fun;
        }
        const default_action = hash1_fun();
        size = 1;
    }
    @pragma stage 1
    table tlb_hash2{
        actions = {
            hash2_fun;
        }
        const default_action = hash2_fun();
        size = 1;
    }
    @pragma stage 1
    table tlb_hash3{
        actions = {
            hash3_fun;
        }
        const default_action = hash3_fun();
        size = 1;
    }
    @pragma stage 1
    table tlb_hash4{
        actions = {
            hash4_fun;
        }
        const default_action = hash4_fun();
        size = 1;
    }


    /**** Declare meter resource variables for rate limiting operations ****/

    // GREEN = 8w0 (no congestion), YELLOW = 8w1 (warning), RED = 8w3 (congestion)
    Meter<bit<8>>(1 << 8, MeterType_t.BYTES) Rate_Limiting;
    
    // Meter coloring based on token bucket (rate limiting)
    action set_color(bit<8> meter_id) {
        meta.color = (bit<2>)Rate_Limiting.execute(meter_id);
    }

    /* Matching defense task based on predefined rules */
    action set_id(bit<8> task_id, bit<8> sketch_id, bit<3> option, bit<1> in_or_out, max_row_len mask_index, bit<8> meter_id, counter_type param) {
        meta.task_id = task_id;
        meta.sketch_id = sketch_id;
        meta.m_options = option;
        meta.in_or_out = in_or_out;
        meta.index1 = (max_row_len)(meta.index1 & mask_index);
        meta.index2 = (max_row_len)(meta.index2 & mask_index);
        meta.index3 = (max_row_len)(meta.index3 & mask_index);
        meta.index4 = (max_row_len)(meta.index4 & mask_index);
        meta.cookie_verification = meta.cookie + 1;
        meta.param = param;
        set_color(meter_id);
    }

    // Match defense task based on protocol number at the transport layer
    @pragma stage 2
    table match_first_id{
        key = {
            ig_intr_md.ingress_port :exact;
            hdr.ipv4.protocol : exact;
            meta.states : range;
        }
        actions = {
            set_id;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 64;
    }

    /* Calculate row index */
    Hash<bit<8>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<8>> (8w0x64, true, false, false, 8w0xFF, 8w0xFF)) hash_row;
    action hash_row_fun() {
        meta.row_index = (bit<2>)hash_row.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                                meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                                meta.five_tuple.protocol });
    }


    /**** Memory address translation, calculate the real index ****/
    action set_index_1(max_row_len offset1, max_row_len offset2, max_row_len offset3, max_row_len offset4) {
        meta.index1 = meta.index1 + offset1;
        meta.index2 = meta.index2 + offset2;
        meta.index3 = meta.index3 + offset3;
        meta.index4 = meta.index4 + offset4;
    }

    // Match offset using defense task Sketch ID and translate memory address
    @pragma stage 3
    table tlb_set_index1{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            set_index_1;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 16;
    }

    /* Retrieve the value for register update */
    action set_param(counter_type param)
    {
        meta.param = param;
    }

    /**** Register Update ****/

    /* Match if the defense task is configured to use register array 1 */
    @pragma stage 4
    table match_first_sketch_row1{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    /* Register pool: Register array 1 */
    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) first_sketch_row1;
    /* Whitelist update operation */
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row1) first_sketch_row1_whitelist = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value | meta.param;  // OR with 0 keeps the value unchanged, OR with 1 sets the value to 1
            reg_upd_val = value;         // reg_upd_val is the register value after the OR operation
        }
    };
    /* Detection and Rate_Limiting update operation */
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row1) first_sketch_row1_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param; // Addition operation, |+| operator prevents overflow
            reg_upd_val = value;
        }
    };
    /* One to One Cache update operation */
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row1) first_sketch_row1_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param; // Addition operation, cache update
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;          // 
                value = value |-| meta.param; // Subtraction operation, cache reduction
            }
            // Return the register value after cache addition or before cache reduction to avoid misjudgment
        }
    };
    action modify_whitelist_first_sketch_row1() {
        meta.reg_upd_val = first_sketch_row1_whitelist.execute(meta.index1);
    }
    action modify_count_first_sketch_row1() {
        meta.reg_upd_val = first_sketch_row1_count.execute(meta.index1);
    }
    action modify_cache_first_sketch_row1() {
        meta.reg_upd_val = first_sketch_row1_cache.execute(meta.index1);
    }
    
    @pragma stage 4
    table ALU_First_row1{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_whitelist_first_sketch_row1;
            modify_cache_first_sketch_row1;
            modify_count_first_sketch_row1;
        }
        const entries = {
            (0x01, 0x0) : modify_whitelist_first_sketch_row1();
            (0x02, 0x0) : modify_count_first_sketch_row1();
            (0x04, 0x0) : modify_cache_first_sketch_row1();
        }
        size = 4;
    }

    // Use "result" to record the minimum register value during the update process
    action set_first_result_1() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }


    /* Match if the defense task is configured to use register array 2 */
    @pragma stage 5
    table match_first_sketch_row2{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    /* Register pool: Register array 2 */
    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) first_sketch_row2;
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row2) first_sketch_row2_whitelist = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value | meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row2) first_sketch_row2_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row2) first_sketch_row2_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param;
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;
                value = value |-| meta.param;
            }
        }
    };

    action modify_whitelist_first_sketch_row2() {
        meta.reg_upd_val = first_sketch_row2_whitelist.execute(meta.index2);
    }
    action modify_count_first_sketch_row2() {
        meta.reg_upd_val = first_sketch_row2_count.execute(meta.index2);
    }
    action modify_cache_first_sketch_row2() {
        meta.reg_upd_val = first_sketch_row2_cache.execute(meta.index2);
    }

    @pragma stage 5
    table ALU_First_row2{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_whitelist_first_sketch_row2;
            modify_cache_first_sketch_row2;
            modify_count_first_sketch_row2;
        }
        const entries = {
            (0x01, 0x0) : modify_whitelist_first_sketch_row2();
            (0x02, 0x0) : modify_count_first_sketch_row2();
            (0x04, 0x1) : modify_cache_first_sketch_row2();
        }
        size = 4;
    }

    action set_first_result_2() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }


    /* Match if the defense task is configured to use register array 3 */
    @pragma stage 6
    table match_first_sketch_row3{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    /* Register pool: Register array 3 */
    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) first_sketch_row3;
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row3) first_sketch_row3_whitelist = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value | meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row3) first_sketch_row3_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row3) first_sketch_row3_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param;
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;
                value = value |-| meta.param;
            }
        }
    };
    
    action modify_whitelist_first_sketch_row3() {
        meta.reg_upd_val = first_sketch_row3_whitelist.execute(meta.index3);
    }
    action modify_count_first_sketch_row3() {
        meta.reg_upd_val = first_sketch_row3_count.execute(meta.index3);
    }
    action modify_cache_first_sketch_row3() {
        meta.reg_upd_val = first_sketch_row3_cache.execute(meta.index3);
    }

    @pragma stage 6
    table ALU_First_row3{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_whitelist_first_sketch_row3;
            modify_cache_first_sketch_row3;
            modify_count_first_sketch_row3;
        }
        const entries = {
            (0x01, 0x0) : modify_whitelist_first_sketch_row3();
            (0x02, 0x0) : modify_count_first_sketch_row3();
            (0x04, 0x2) : modify_cache_first_sketch_row3();
        }
        size = 4;
    }

    action set_first_result_3() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }


    /* Match if the defense task is configured to use register array 4 */
    @pragma stage 7
    table match_first_sketch_row4{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    /* Register pool: Register array 4 */
    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) first_sketch_row4;
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row4) first_sketch_row4_whitelist = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value | meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row4) first_sketch_row4_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(first_sketch_row4) first_sketch_row4_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param;
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;
                value = value |-| meta.param;
            }
        }
    };
    
    action modify_whitelist_first_sketch_row4() {
        meta.reg_upd_val = first_sketch_row4_whitelist.execute(meta.index4);
    }
    action modify_count_first_sketch_row4() {
        meta.reg_upd_val = first_sketch_row4_count.execute(meta.index4);
    }
    action modify_cache_first_sketch_row4() {
        meta.reg_upd_val = first_sketch_row4_cache.execute(meta.index4);
    }
    
    @pragma stage 7
    table ALU_First_row4{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_whitelist_first_sketch_row4;
            modify_cache_first_sketch_row4;
            modify_count_first_sketch_row4;
        }
        const entries = {
            (0x01, 0x0) : modify_whitelist_first_sketch_row4();
            (0x02, 0x0) : modify_count_first_sketch_row4();
            (0x04, 0x3) : modify_cache_first_sketch_row4();
        }
        size = 4;
    }

    action set_first_result_4() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }


    /**** Handle action matching for defense task execution ****/
    // For detection and rate-limiting, perform rate limiting based on update result and coloring value
    // For one-to-one cache, decide to drop or forward based on the update result
    // For proxy, decide to drop or forward based on the update result
    @pragma stage 9
    table first_result_drop{
        key = {
            meta.task_id : exact;
            meta.result : range;
            meta.color : range;
        }
        actions = {
            drop;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 32;
    }

    /**** route farword ****/
    action ipv4_forward(bit<9> port) {
        //set the output port that we also get from the table
        ig_tm_md.ucast_egress_port = port;
    }

    @pragma stage 10
    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 256;
        default_action = ipv4_forward(160);
    }



    apply{
        /***************** Transport and Network Layer Defense Phase - Ingress *********************/
        dynamic_hash.apply();

        // SYN cookie
        tbl_hash_cookie.apply();

        // virtual index
        tlb_hash1.apply();
        tlb_hash2.apply();
        tlb_hash3.apply();
        tlb_hash4.apply();
        
        // Defense task matching and preprocessing
        if(match_first_id.apply().hit) {
            tlb_set_index1.apply();
            if(meta.m_options == 2) {
                // Detection and Rate_Limiting
                set_param(1);
            }
            else if(meta.m_options == 4) {
                // One to One Cache
                //row index
                hash_row_fun();  
                if(meta.in_or_out == 0) {
                    // Cache record
                    set_param(8);
                }
                else
                {
                    // Cache reduction
                    set_param(1);
                }
            }
            else if(meta.m_options == 1) {
                if(hdr.tcp.flags == ACK) {
                    if(hdr.tcp.ack_no == meta.cookie_verification) { // Cookie validation successful, the cookie is valid
                        // Construct RST packet to notify the client to re-initiate the connection
                        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
                        hdr.ipv4.dst_addr = meta.tmp_srcip;
                        hdr.ports.src_port = hdr.ports.dst_port;
                        hdr.ports.dst_port = meta.tmp_srcport;
                        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
                        hdr.ethernet.dst_addr = meta.tmp_srcaddr;
                        hdr.tcp.seq_no = hdr.tcp.ack_no;
                        hdr.tcp.flags = RST;
                        // Checksum update
                        meta.check_sum_flags.checksum_update_ipv4 = true;
                        meta.check_sum_flags.checksum_update_tcp = true;
                        // Validation successful, record in the whitelist
                        set_param(1);
                    }
                }
            }

            // Register update
            if (match_first_sketch_row1.apply().hit)
            {
                ALU_First_row1.apply();
                set_first_result_1();
            }
            if (match_first_sketch_row2.apply().hit)
            {
                ALU_First_row2.apply();
                set_first_result_2();
            }
            if (match_first_sketch_row3.apply().hit)//stage 7
            {
                ALU_First_row3.apply();//stage 7
                set_first_result_3();//stage 8
            }
            if (match_first_sketch_row4.apply().hit)//stage 8
            {
                ALU_First_row4.apply();//stage 8
                set_first_result_4();//stage 9
            }

            // SYN-ACK response
            if(meta.m_options == 1)
            {
                // SYN packet not found in the whitelist, switch proactively returns a SYN-ACK packet
                if(hdr.tcp.flags == SYN && meta.reg_upd_val == 0) { 
                    hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
                    hdr.ipv4.dst_addr = meta.tmp_srcip;
                    hdr.ports.src_port = hdr.ports.dst_port;
                    hdr.ports.dst_port = meta.tmp_srcport;
                    hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
                    hdr.ethernet.dst_addr = meta.tmp_srcaddr;
                    hdr.tcp.ack_no = hdr.tcp.seq_no + 1;
                    hdr.tcp.seq_no = meta.cookie;
                    hdr.tcp.flags = SYN_ACK;

                    meta.check_sum_flags.checksum_update_ipv4 = true;
                    meta.check_sum_flags.checksum_update_tcp = true;
                }
            }


            if(meta.m_options == 2 || meta.m_options == 4) {
                first_result_drop.apply();
            }
        }        
        
        ipv4_lpm.apply();
    }
}




/*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout ingress_headers_t                       hdr,
    in    ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply{
        pkt.emit(hdr);
    }
}



/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

 /***********************  H E A D E R S  ************************/

// struct egress_headers_t {
// }

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

// struct egress_metadata_t {
// }

/***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out egress_headers_t          hdr,
    out egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start{
        pkt.extract(eg_intr_md);
        transition meta_init;
    }

    /* Initialize custom Egress metadata */
    state meta_init{
        meta.five_tuple = {0,0,0,0,0};
        meta.tmp_srcip = 0;
        meta.tmp_srcport = 0;
        meta.states = 0;
        meta.task_id = 0;
        meta.sketch_id = 0;
        // meta.mask_index = 0x1FFFF;
        meta.m_options = 0;
        meta.in_or_out = 1;
        meta.color = 0;
        meta.row_index = 0;
        meta.index1 = 0;
        meta.index2 = 0;
        meta.index3 = 0;
        meta.index4 = 0;
        meta.reg_upd_val = 1;
        meta.param = 0;
        meta.result = 65535;
        transition parse_ethernet;
    }

    /* Parse Ethernet header */
    state parse_ethernet{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default:  accept;
        }
    }

    /* Parse IPv4 header */
    state parse_ipv4{
        pkt.extract(hdr.ipv4);
        meta.five_tuple.src_addr = hdr.ipv4.src_addr;
        meta.five_tuple.dst_addr = hdr.ipv4.dst_addr;
        meta.five_tuple.protocol = hdr.ipv4.protocol;
        meta.tmp_srcip = hdr.ipv4.src_addr; 
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_TCP: parse_tcp;
            PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    /* Parse TCP header */
    state parse_tcp{
        pkt.extract(hdr.ports);
        meta.five_tuple.src_port = hdr.ports.src_port;
        meta.five_tuple.dst_port = hdr.ports.dst_port;
        meta.tmp_srcport = hdr.ports.src_port;
        
        pkt.extract(hdr.tcp);
        meta.states = hdr.tcp.flags;

        transition accept;
    }

    /* Parse UDP header */
    state parse_udp{
        pkt.extract(hdr.ports);
        meta.five_tuple.src_port = hdr.ports.src_port;
        meta.five_tuple.dst_port = hdr.ports.dst_port;
        meta.tmp_srcport = hdr.ports.src_port;
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout egress_headers_t                          hdr,
    inout egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{    
    /* Drop the packet */
    action drop() {
        eg_dprsr_md.drop_ctl = 1;
    }

    /* No-op action (empty action) */
    action noaction() {}

    /***************** Application Layer Defense Phase - Ingress *********************/
    
    
    /**** Dynamic hash for flexible memory access ****/

    action set_five_hash() {
        
    }
    action set_session_hash() {
        meta.five_tuple.src_addr = meta.five_tuple.dst_addr;
        meta.five_tuple.dst_addr = meta.tmp_srcip;
        meta.five_tuple.src_port = meta.five_tuple.dst_port;
        meta.five_tuple.dst_port = meta.tmp_srcport;
    }
    action set_three_hash() {
        meta.five_tuple.src_port = 0;
        meta.five_tuple.dst_port = 0;
    }
    @pragma stage 0
    table dynamic_hash_second{
        key = {
            eg_intr_md.egress_port :exact;
            hdr.ports.src_port : ternary;
            hdr.ports.dst_port : ternary;
        }
        actions = {
            set_five_hash;
            set_session_hash;
            set_three_hash;
            noaction;
        }
        const default_action = noaction();
    }

    /**** Calculate virtual index ****/

    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0x3f0b, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit5;
    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0xf523, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit6;
    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0x7024, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit7;
    Hash<bit<16>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<16>> (16w0x0f79, true, false, false, 16w0xFFFF, 16w0xFFFF)) hash_unit8;
    action hash5_fun() {
        meta.index1[15:0] = hash_unit5.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                     meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                     meta.five_tuple.protocol });
    }
    action hash6_fun() {
        meta.index2[15:0] = hash_unit6.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                     meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                     meta.five_tuple.protocol });
    }
    action hash7_fun() {
        meta.index3[15:0] = hash_unit7.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                     meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                     meta.five_tuple.protocol });
    }
    action hash8_fun() {
        meta.index4[15:0] = hash_unit8.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                     meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                     meta.five_tuple.protocol });
    }
    @pragma stage 2
    table tlb_hash5{
        actions = {
            hash5_fun;
        }
        const default_action = hash5_fun();
        size = 1;
    }
    @pragma stage 2
    table tlb_hash6{
        actions = {
            hash6_fun;
        }
        const default_action = hash6_fun();
        size = 1;
    }
    @pragma stage 2
    table tlb_hash7{
        actions = {
            hash7_fun;
        }
        const default_action = hash7_fun();
        size = 1;
    }
    @pragma stage 2
    table tlb_hash8{
        actions = {
            hash8_fun;
        }
        const default_action = hash8_fun();
        size = 1;
    }


    
    Meter<bit<8>>(1 << 8, MeterType_t.BYTES) Rate_Limiting;
    action set_color(bit<8> meter_id) {
        meta.color = (bit<2>)Rate_Limiting.execute(meter_id);
    }

    action set_id(bit<8> task_id, bit<8> sketch_id, bit<3> option, bit<1> in_or_out, max_row_len mask_index, bit<8> meter_id, counter_type param) {
        meta.task_id = task_id;
        meta.sketch_id = sketch_id;
        meta.m_options = option;
        meta.in_or_out = in_or_out;
        meta.index1 = (max_row_len)(meta.index1 & mask_index);
        meta.index2 = (max_row_len)(meta.index2 & mask_index);
        meta.index3 = (max_row_len)(meta.index3 & mask_index);
        meta.index4 = (max_row_len)(meta.index4 & mask_index);
        meta.param = param;
        set_color(meter_id);
    }

    /* Match defense tasks at the application layer based on protocol number and port number */
    @pragma stage 3
    table match_second_id{
        key = {
            eg_intr_md.egress_port :exact;
            hdr.ports.src_port : ternary;
            hdr.ports.dst_port : ternary;
        }
        actions = {
            set_id;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 64;
    }


    Hash<bit<8>> (HashAlgorithm_t.CUSTOM, CRCPolynomial<bit<8>> (8w0x64, true, false, false, 8w0xFF, 8w0xFF)) hash_row;
    action hash_row_fun() {
        meta.row_index = (bit<2>)hash_row.get({ meta.five_tuple.src_addr, meta.five_tuple.dst_addr, 
                                                meta.five_tuple.src_port, meta.five_tuple.dst_port, 
                                                meta.five_tuple.protocol });
    }

    action set_index_2(max_row_len offset1, max_row_len offset2, max_row_len offset3, max_row_len offset4) {
        meta.index1 = meta.index1 + offset1;
        meta.index2 = meta.index2 + offset2;
        meta.index3 = meta.index3 + offset3;
        meta.index4 = meta.index4 + offset4;
    }
    @pragma stage 4
    table tlb_set_index2{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            set_index_2;
            @defaultonly NoAction;
        }
            const default_action = NoAction();
            size = 64;
    }


    action set_param(counter_type param)
    {
        meta.param = param;
    }


    @pragma stage 5
    table match_second_sketch_row1{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) second_sketch_row1;
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row1) second_sketch_row1_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row1) second_sketch_row1_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param;
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;
                value = value |-| meta.param;
            }
        }
    };

    action modify_count_second_sketch_row1() {
        meta.reg_upd_val = second_sketch_row1_count.execute(meta.index1);
    }
    action modify_cache_second_sketch_row1() {
        meta.reg_upd_val = second_sketch_row1_cache.execute(meta.index1);
    }
    @pragma stage 5
    table ALU_second_row1{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_count_second_sketch_row1;
            modify_cache_second_sketch_row1;
        }
        const entries = {
            (0x02, 0x00) : modify_count_second_sketch_row1();
            (0x04, 0x00) : modify_cache_second_sketch_row1();
        }
        size = 4;
    }

    action set_second_result_1() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }



    @pragma stage 6
    table match_second_sketch_row2{
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) second_sketch_row2;
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row2) second_sketch_row2_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row2) second_sketch_row2_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param;
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;
                value = value |-| meta.param;
            }
        }
    };

    action modify_count_second_sketch_row2() {
        meta.reg_upd_val = second_sketch_row2_count.execute(meta.index2);
    }
    action modify_cache_second_sketch_row2() {
        meta.reg_upd_val = second_sketch_row2_cache.execute(meta.index2);
    }
    @pragma stage 6
    table ALU_second_row2{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_count_second_sketch_row2;
            modify_cache_second_sketch_row2;
        }
        const entries = {
            (0x02, 0x00) : modify_count_second_sketch_row2();
            (0x04, 0x01) : modify_cache_second_sketch_row2();
        }
        size = 4;
    }

    action set_second_result_2() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }



    @pragma stage 7
    table match_second_sketch_row3 {
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) second_sketch_row3;
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row3) second_sketch_row3_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row3) second_sketch_row3_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param;
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;
                value = value |-| meta.param;
            }
        }
    };

    action modify_count_second_sketch_row3() {
        meta.reg_upd_val = second_sketch_row3_count.execute(meta.index3);
    }
    action modify_cache_second_sketch_row3() {
        meta.reg_upd_val = second_sketch_row3_cache.execute(meta.index3);
    }
    @pragma stage 7
    table ALU_second_row3{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_count_second_sketch_row3;
            modify_cache_second_sketch_row3;
        }
        const entries = {
            (0x02, 0x00) : modify_count_second_sketch_row3();
            (0x04, 0x02) : modify_cache_second_sketch_row3();
        }
        size = 4;
    }

    action set_second_result_3() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }



    @pragma stage 8
    table match_second_sketch_row4 {
        key = {
            meta.sketch_id : exact;
        }
        actions = {
            noaction;
        }
        const default_action = noaction();
        size = 64;
    }

    Register<counter_type, max_row_len>(SKETCH_LENGTH, 0) second_sketch_row4;
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row4) second_sketch_row4_count = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            value = value |+| meta.param;
            reg_upd_val = value;
        }
    };
    RegisterAction<counter_type, max_row_len, counter_type>(second_sketch_row4) second_sketch_row4_cache = {
        void apply(inout counter_type value, out counter_type reg_upd_val) {
            if(meta.in_or_out == 0){
                value = value |+| meta.param;
                reg_upd_val = value;
            }
            else{
                reg_upd_val = value;
                value = value |-| meta.param;
            }
        }
    };

    action modify_count_second_sketch_row4() {
        meta.reg_upd_val = second_sketch_row4_count.execute(meta.index4);
    }
    action modify_cache_second_sketch_row4() {
        meta.reg_upd_val = second_sketch_row4_cache.execute(meta.index4);
    }
    @pragma stage 8
    table ALU_second_row4{
        key = {
            meta.m_options : exact;
            meta.row_index : exact;
        }
        actions = {
            modify_count_second_sketch_row4;
            modify_cache_second_sketch_row4;
        }
        const entries = {
            (0x02, 0x00) : modify_count_second_sketch_row4();
            (0x04, 0x03) : modify_cache_second_sketch_row4();
        }
        size = 4;
    }

    action set_second_result_4() {
        if (meta.reg_upd_val < meta.result) {
            meta.result = meta.reg_upd_val;
        }
    }




    @pragma stage 10
    table second_result_drop{
        key = {
            meta.task_id : exact;
            meta.result : range;
            meta.color : range;
        }
        actions = {
            drop;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 32;
    }
    



    apply{
        dynamic_hash_second.apply(); // stage 1

        tlb_hash5.apply();//stage 2
        tlb_hash6.apply();//stage 2
        tlb_hash7.apply();//stage 2
        tlb_hash8.apply();//stage 2
        
        if(match_second_id.apply().hit) {//stage 3

            tlb_set_index2.apply();//stage 5

            if(meta.m_options == 2) {
                set_param(1);
            }
            else if(meta.m_options == 4) {
                hash_row_fun();
                if(meta.in_or_out == 0) {
                    set_param(8);
                }
                else
                {
                    set_param(1);
                }
            }
            else if(meta.m_options == 1) {
                // Currently unavailable
            }

            
            if (match_second_sketch_row1.apply().hit)//stage 6
            {
                ALU_second_row1.apply();//stage 6
                set_second_result_1();//stage 7
            }
            if (match_second_sketch_row2.apply().hit)//stage 7
            {
                ALU_second_row2.apply();//stage 7
                set_second_result_2();//stage 8
            }
            if (match_second_sketch_row3.apply().hit)//stage 8
            {
                ALU_second_row3.apply();//stage 8
                set_second_result_3();//stage 9
            }
            if (match_second_sketch_row4.apply().hit)//stage 9
            {
                ALU_second_row4.apply();//stage 9
                set_second_result_4();//stage 10
            }
            

            if(meta.m_options == 2 || meta.m_options == 4) {
                second_result_drop.apply();//stage 11
            }
        }
    }
}

/*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout egress_headers_t                       hdr,
    in    egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply{
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