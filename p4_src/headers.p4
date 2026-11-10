/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
typedef bit<11> coupons_len;                   // Length of the "Beaucoup" in the detection module
typedef bit<16> counter_type;                  // Data type for each register in the register pool
typedef bit<17> max_row_len;                   // Data type for the length of each row in the register pool

const bit<16> ETHERTYPE_IPV4 = 0x0800;         // Ethertype for IPv4 packets

const bit<8> PROTOCOL_ICMP = 0x01;             // Protocol number for ICMP
const bit<8> PROTOCOL_UDP = 0x11;              // Protocol number for UDP
const bit<8> PROTOCOL_TCP = 0x06;              // Protocol number for TCP

const bit<8> SYN = 0x02;                       // TCP SYN flag
const bit<8> SYN_ACK = 0x12;                   // TCP SYN + ACK flags
const bit<8> ACK = 0x10;                       // TCP ACK flag
const bit<8> RST = 0x04;                       // TCP RST flag

/* Five-tuple metadata (used for identifying a flow) */
struct five_tuple_metadata_t {
    bit<32> src_addr;    // Source IP address
    bit<32> dst_addr;    // Destination IP address
    bit<8>  protocol;    // Protocol (e.g., TCP = 6, UDP = 17, ICMP = 1)
    bit<16> src_port;    // Source port number (for TCP/UDP)
    bit<16> dst_port;    // Destination port number (for TCP/UDP)
}

struct Check_sum_flags {
    bool checksum_update_ipv4;  // Flag indicating if the IPv4 checksum needs to be updated
    bool checksum_update_icmp;  // Flag indicating if the ICMP checksum needs to be updated
    bool checksum_update_tcp;   // Flag indicating if the TCP checksum needs to be updated
}



/*************************************************************************
 *************************** M E T A D A T A  ****************************
*************************************************************************/
/* Custom Ingress metadata */
struct ingress_metadata_t {
    five_tuple_metadata_t five_tuple;     // Five-tuple metadata
    bit<32> tmp_srcip;                    // Temporary source IP address
    bit<16> tmp_srcport;                  // Temporary source port number
    bit<48> tmp_srcaddr;                  // Temporary source MAC address
    bit<8> states;                        // Type of the TCP packet
    bit<8> task_id;                       // Defense task ID
    bit<8> sketch_id;                     // Sketch ID used in the defense task
    bit<3> m_options;                     // Indicating the defense approached used in defense task: 1 - Proxy, 2 - Detection and Rate Limiting, 3 - One-to-One Cache
    Check_sum_flags check_sum_flags;      // Indicating whether checksum update is required
    bit<1> in_or_out;                     // Indicating whether the packet is from internal or external source
    bit<32> cookie;                       // Cookie used in SYN proxy
    bit<32> cookie_verification;          // Auxiliary key for cookie verification
    bit<2> color;                         // Coloring result from the meter (token bucket), used for rate limiting
    bit<2> row_index;                     // Row index used in one-to-one cache for locating the register to update
    max_row_len index1;                   // Column index 1
    max_row_len index2;                   // Column index 2
    max_row_len index3;                   // Column index 3
    max_row_len index4;                   // Column index 4
    bit<16> check_sum_tmp;                // Temporary storage for checksum calculation
    counter_type reg_upd_val;             // Return value after the register is updated
    counter_type param;                   // Value used for register update (e.g., addition or subtraction)
    counter_type result;                  // Result after the memory is updated by the packet
}

/* Custom Egress metadata */
struct egress_metadata_t {
    five_tuple_metadata_t five_tuple;     // Five-tuple metadata
    bit<32> tmp_srcip;                    // Temporary source IP address
    bit<16> tmp_srcport;                  // Temporary source port number
    bit<8> states;                        // Type of the TCP packet
    bit<8> task_id;                       // Defense task ID
    bit<8> sketch_id;                     // Sketch ID used in the defense task
    bit<3> m_options;                     // Indicating the defense approached used in defense task: 1 - Proxy, 2 - Detection and Rate Limiting, 3 - One-to-One Cache
    bit<1> in_or_out;                     // Indicating whether the packet is from internal or external source
    bit<2> color;                         // Coloring result from the meter (token bucket), used for rate limiting
    bit<2> row_index;                     // Row index used in one-to-one cache for locating the register to update
    max_row_len index1;                   // Column index 1
    max_row_len index2;                   // Column index 2
    max_row_len index3;                   // Column index 3
    max_row_len index4;                   // Column index 4
    counter_type reg_upd_val;             // Return value after the register is updated
    counter_type param;                   // Value used for register update (e.g., addition or subtraction)
    counter_type result;                  // Result after the memory is updated by the packet
}



/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

 /* Standard ethernet header */
header ethernet_h{
    bit<48>  dst_addr;
    bit<48>  src_addr;
    bit<16>  ether_type;
}

/* IPv4 header */
header ipv4_h {
    bit<4>   version;        // IP version (should be 4 for IPv4)
    bit<4>   ihl;            // Internet Header Length (number of 32-bit words)
    bit<8>   diffserv;       // Differentiated Services Field (DSCP + ECN)
    bit<16>  total_len;      // Total length of the IP packet (header + payload)
    bit<16>  identification; // Packet ID used for fragmentation
    bit<3>   flags;          // Fragmentation control flags
    bit<13>  frag_offset;    // Fragment offset
    bit<8>   ttl;            // Time To Live
    bit<8>   protocol;       // Protocol (e.g., TCP = 6, UDP = 17)
    bit<16>  hdr_checksum;   // Header checksum
    bit<32>  src_addr;       // Source IP address
    bit<32>  dst_addr;       // Destination IP address
}

/* ICMP header */
header icmp_h {
    bit<8>  type;        // ICMP message type (e.g., 8 = Echo Request, 0 = Echo Reply)
    bit<8>  code;        // ICMP subtype code (provides more detail about the type)
    bit<16> checksum;    // ICMP header checksum
    bit<16> identifier;  // Identifier to match requests and replies
    bit<16> seq_num;     // Sequence number for tracking requests
}


/* A common L4 header for TCP and UDP */
header l4port_h {
    bit<16> src_port;  // Source port number
    bit<16> dst_port;  // Destination port number
}

/* TCP header */
header tcp_h {
    bit<32> seq_no;       // Sequence number
    bit<32> ack_no;       // Acknowledgment number
    bit<4>  data_offset;  // Data offset (number of 32-bit words in the TCP header)
    bit<4>  res;          // Reserved bits (set to 0)
    bit<8>  flags;        // TCP flags (e.g., SYN, ACK, FIN)
    bit<16> window;       // Window size for flow control
    bit<16> checksum;     // TCP checksum for error checking
    bit<16> urgent_ptr;   // Urgent pointer (if URG flag is set)
}

/* UDP header */
header udp_h {
    bit<16> len;        // Length of the UDP packet (header + payload)
    bit<16> checksum;   // UDP checksum for error checking
}


struct ingress_headers_t {
    ethernet_h ethernet;  // Ethernet header
    ipv4_h ipv4;          // IPv4 header
    icmp_h icmp;          // ICMP header (used for ICMP packets)
    l4port_h ports;       // Transport layer port header (common for TCP and UDP)
    tcp_h tcp;            // TCP header (if the packet is TCP)
    udp_h udp;            // UDP header (if the packet is UDP)
}

struct egress_headers_t {
    ethernet_h ethernet;  // Ethernet header
    ipv4_h ipv4;          // IPv4 header
    l4port_h ports;       // Transport layer port header (common for TCP and UDP)
    tcp_h tcp;            // TCP header (if the packet is TCP)
    udp_h udp;            // UDP header (if the packet is UDP)
}

