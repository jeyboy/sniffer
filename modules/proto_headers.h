#ifndef PROTO_HEADERS
#define PROTO_HEADERS

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

//#include <time.h>
#include <string>

//typedef struct _IPHeader {
//    unsigned char  header_len :4;   // ver and length of header
//    unsigned char  header_ver :4;   // ver and length of header
//    unsigned char  tos;             // type of service (0 1 2 3 ... 7)
//    unsigned short length;          // packet length
//    unsigned short id;              // Id
//    unsigned short flgs_offset;     // offset
//    unsigned char  ttl;             // life time
//    unsigned char  protocol;        // protocol
//    unsigned short xsum;            // control sum
//    unsigned long  src;             // sender IP
//    unsigned long  dest;            // receiver IP
////    //------------------------------------------------------------
////    unsigned short *params;         // 320 bits length
////    unsigned char  *data;           // limit is 65535
//} IPHeader;

typedef struct ip_hdr {
    unsigned char header_len :4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    unsigned char header_ver :4; // 4-bit IPv4 version
    unsigned char tos; // IP type of service
    unsigned short total_length; // Total length
    unsigned short id; // Unique identifier

    unsigned char frag_offset :5; // Fragment offset field

    unsigned char more_fragment :1;
    unsigned char dont_fragment :1;
    unsigned char reserved_zero :1;

    unsigned char frag_offset1; //fragment offset

    unsigned char ttl; // Time to live
    unsigned char protocol; // Protocol(TCP,UDP etc)
    unsigned short checksum; // IP checksum
    unsigned int srcaddr; // Source address
    unsigned int destaddr; // Source address
} IPV4_HDR;

typedef struct udp_hdr {
    unsigned short source_port; // Source port no.
    unsigned short dest_port; // Dest. port no.
    unsigned short length; // Udp packet length
    unsigned short checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header {
    unsigned short source_port; // source port
    unsigned short dest_port; // destination port
    unsigned int sequence; // sequence number - 32 bits
    unsigned int acknowledge; // acknowledgement number - 32 bits

    unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
    unsigned char reserved_part1:3; //according to rfc
    unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
    This indicates where the data begins.
    The length of the TCP header is always a multiple
    of 32 bits.*/

    unsigned char fin :1; //Finish Flag
    unsigned char syn :1; //Synchronise Flag
    unsigned char rst :1; //Reset Flag
    unsigned char psh :1; //Push Flag
    unsigned char ack :1; //Acknowledgement Flag
    unsigned char urg :1; //Urgent Flag

    unsigned char ecn :1; //ECN-Echo Flag
    unsigned char cwr :1; //Congestion Window Reduced Flag

    ////////////////////////////////

    unsigned short window; // window
    unsigned short checksum; // checksum
    unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr {
    BYTE type; // ICMP Error type
    BYTE code; // Type sub code
    USHORT checksum;
    USHORT id;
    USHORT seq;
} ICMP_HDR;

#endif // PROTO_HEADERS
