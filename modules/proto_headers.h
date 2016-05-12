#ifndef PROTO_HEADERS
#define PROTO_HEADERS

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <string>

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

#include <qhash.h>
#include <qstring.h>

#define CONST_CHAR(qstring) qstring.toStdString().c_str()

#define NSTR(num) QString::number(num)
#define UNSTR(num) QString::number((unsigned int)num)
#define NSTR_HOST_BYTES_ORDER(num) NSTR(ntohs(num))
#define NLSTR_HOST_BYTES_ORDER(num) NSTR(ntohl(num))

#define ULONG_BYTE4(u) ((u & 0xFF000000) >> 24)
#define ULONG_BYTE3(u) ((u & 0xFF0000) >> 16)
#define ULONG_BYTE2(u) ((u & 0xFF00) >> 8)
#define ULONG_BYTE1(u) (u & 0xFF)

#define TIMESTAMP_STR QDateTime::currentDateTime().time().toString()

#define SOCK_ATTR_TIMESTAMP QStringLiteral("Timestamp")
#define SOCK_ATTR_NUM_PROTOCOL QStringLiteral("NProtocol")
#define SOCK_ATTR_PROTOCOL QStringLiteral("Protocol")
#define SOCK_ATTR_DIRECTION QStringLiteral("Direction")
#define SOCK_ATTR_SRC_IP QStringLiteral("Source IP")
#define SOCK_ATTR_DEST_IP QStringLiteral("Destination IP")
#define SOCK_ATTR_SRC QStringLiteral("Source")
#define SOCK_ATTR_DEST QStringLiteral("Destination")
#define SOCK_ATTR_PAYLOAD QStringLiteral("Payload")
#define SOCK_ATTR_LENGTH QStringLiteral("Length")
#define SOCK_ATTR_APP QStringLiteral("App")
#define SOCK_ATTR_SRC_PORT QStringLiteral("Source Port")
#define SOCK_ATTR_DEST_PORT QStringLiteral("Destination Port")

#define SOCK_DIRECTION_IN QStringLiteral("in")
#define SOCK_DIRECTION_OUT QStringLiteral("out")

class SocketUtils {
public:
    static QString pidToPath(DWORD pid) {
        if (pid == 0) return QString();

        HANDLE processHandle = NULL;
        WCHAR filename[MAX_PATH];
        bool res = false;
        QString def_result;

        processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (processHandle != NULL) {
            res = GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) != 0;
            if (GetLastError() == ERROR_ACCESS_DENIED) {
//                res = GetProcessImageFileName(processHandle, filename, MAX_PATH) != 0;

                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(processHandle, &hMod, sizeof(hMod), &cbNeeded))
                    res = GetModuleBaseName(processHandle, hMod, filename, MAX_PATH) != 0;

                if (GetLastError() == ERROR_ACCESS_DENIED)
                    def_result = QStringLiteral("Not accessable PID:%1").arg(pid);
            }

            CloseHandle(processHandle);
        } else {
            if (GetLastError() == ERROR_ACCESS_DENIED)
                def_result = QStringLiteral("Not accessable PID:%1").arg(pid);
            else
                def_result = QStringLiteral("Undefined (%1) PID:%2").arg(GetLastError()).arg(pid);
        }

        return res ? QString::fromWCharArray(filename) :def_result;
    }

    static DWORD addrTcpToPid(DWORD port) {
        DWORD pid = 0;
        DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
        DWORD dwRetValue = 0;

        PMIB_TCPTABLE_OWNER_PID ptTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);

        do {
            dwRetValue = GetExtendedTcpTable(ptTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (dwRetValue != ERROR_INSUFFICIENT_BUFFER)
                break;

            free(ptTable);
            ptTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        }
        while(true);

        if (dwRetValue == ERROR_SUCCESS) {
            DWORD entry_num = ptTable -> dwNumEntries;

            for(DWORD i = 0; i < entry_num; i++) {
                if (ptTable -> table[i].dwLocalPort == port) {
                    pid = ptTable -> table[i].dwOwningPid;
                    break;
                }
            }
        }

        free(ptTable);

        if (pid == 0)
            pid = addrTcp6ToPid(port);

        return pid;
    }

    static DWORD addrTcp6ToPid(DWORD port) {
        DWORD pid = 0;
        DWORD dwSize = sizeof(MIB_TCP6TABLE_OWNER_PID);
        DWORD dwRetValue = 0;

        PMIB_TCP6TABLE_OWNER_PID ptTable = (PMIB_TCP6TABLE_OWNER_PID)malloc(dwSize);

        do {
            dwRetValue = GetExtendedTcpTable(ptTable, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (dwRetValue != ERROR_INSUFFICIENT_BUFFER)
                break;

            free(ptTable);
            ptTable = (PMIB_TCP6TABLE_OWNER_PID)malloc(dwSize);
        }
        while(true);

        if (dwRetValue == ERROR_SUCCESS) {
            DWORD entry_num = ptTable -> dwNumEntries;

            for(DWORD i = 0; i < entry_num; i++) {
                if (ptTable -> table[i].dwLocalPort == port) {
                    pid = ptTable -> table[i].dwOwningPid;
                    break;
                }
            }
        }

        free(ptTable);
        return pid;
    }

    static DWORD addrUdpToPid(DWORD port) {
        DWORD pid = 0;
        DWORD dwRetValue = 0;
        DWORD dwSize = sizeof(PMIB_UDPTABLE_OWNER_PID);

        PMIB_UDPTABLE_OWNER_PID ptTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);

        do {
            dwRetValue = GetExtendedUdpTable(ptTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (dwRetValue != ERROR_INSUFFICIENT_BUFFER)
                break;

            free(ptTable);
            ptTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
        }
        while(true);

        if (dwRetValue == ERROR_SUCCESS) {
            DWORD entry_num = ptTable -> dwNumEntries;

            for(DWORD i = 0; i < entry_num; i++) {
                if (ptTable -> table[i].dwLocalPort == port) {
                    pid = ptTable -> table[i].dwOwningPid;
                    break;
                }
            }
        }

        free(ptTable);

        if (pid == 0)
            pid = addrUdp6ToPid(port);

        return pid;
    }

    static DWORD addrUdp6ToPid(DWORD port) {
        DWORD pid = 0;
        DWORD dwRetValue = 0;
        DWORD dwSize = sizeof(PMIB_UDP6TABLE_OWNER_PID);

        PMIB_UDP6TABLE_OWNER_PID ptTable = (PMIB_UDP6TABLE_OWNER_PID)malloc(dwSize);

        do {
            dwRetValue = GetExtendedUdpTable(ptTable, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (dwRetValue != ERROR_INSUFFICIENT_BUFFER)
                break;

            free(ptTable);
            ptTable = (PMIB_UDP6TABLE_OWNER_PID)malloc(dwSize);
        }
        while(true);

        if (dwRetValue == ERROR_SUCCESS) {
            DWORD entry_num = ptTable -> dwNumEntries;

            for(DWORD i = 0; i < entry_num; i++) {
                if (ptTable -> table[i].dwLocalPort == port) {
                    pid = ptTable -> table[i].dwOwningPid;
                    break;
                }
            }
        }

        free(ptTable);
        return pid;
    }

    static QString ucharsToStr(char * buff, int length) {
//        char * b = buff;
//        QString s; //(length, Qt::Uninitialized);
//        for(int i = 0; i < length; i++, b++) {
////            a = ( *b >=32 && *b <=128) ? (unsigned char) *b : '.';
//            char cch = (*b >= 32) ? (unsigned char) *b : '.';
//            s[i] = cch;
//        }
//        return s;

        return QString::fromUtf8(buff, length);
    }

    static QString hostToHostName(const QString & ip_str) {
        struct addrinfo * res = 0;
        struct addrinfo hints;

        memset(&hints, 0, sizeof hints); // make sure the struct is empty
        hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
        hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

        if (getaddrinfo(CONST_CHAR(ip_str), 0, &hints, &res) == 0) {
            char host[NI_MAXHOST];

            // get first entry only
            getnameinfo(res -> ai_addr, res -> ai_addrlen, host, sizeof(host), 0, 0, 0);
            freeaddrinfo(res);

            return QString(host);
        }

        return QString();
    }

    static QString hostToHostName(unsigned long host_ip) {
        return hostToHostName(hostToStr(host_ip));
    }

    static QString protocolToStr(unsigned char protocol) {
        switch(protocol) {
            case 0: return "HOPOPT";
            case 1: return "ICMP";
            case 2: return "IGMP";
            case 3: return "GGP";
            case 4: return "IP";
            case 5: return "ST";
            case 6: return "TCP";
            case 7: return "CBT";
            case 8: return "EGP";
            case 9: return "IGP";
            case 10: return "BBN_RCC_MON";
            case 11: return "NVP_II";
            case 12: return "PUP";
            case 13: return "ARGUS";
            case 14: return "EMCON";
            case 15: return "XNET";
            case 16: return "CHAOS";
            case 17: return "UDP";
            case 18: return "MUX";
            case 19: return "DCN_MEAS";
            case 20: return "HMP";
            case 21: return "PRM";
            case 22: return "XNS-IDP";
            case 23: return "TRUNK-1";
            case 24: return "TRUNK-2";
            case 25: return "LEAF-1";
            case 26: return "LEAF-2";
            case 27: return "RDP";
            case 28: return "IRTP";
            case 29: return "ISO-TP4";
            case 30: return "NETBLT";
            case 31: return "MFE-NSP";
            case 32: return "MERIT-INP";
            case 33: return "DCCP";
            case 34: return "3PC";
            case 35: return "IDPR";
            case 36: return "XTP";
            case 37: return "DDP";
            case 38: return "IDPR-CMTP";
            case 39: return "TP++";
            case 40: return "IL";
            case 41: return "IPv6";
            case 42: return "SDRP";
            case 43: return "IPv6-Route";
            case 44: return "IPv6-Frag";
            case 45: return "IDRP";
            case 46: return "RSVP";
            case 47: return "GRE";
            case 48: return "DSR";
            case 49: return "BNA";
            case 50: return "ESP";
            case 51: return "AH";
            case 52: return "I-NLSP";
            case 53: return "SWIPE";
            case 54: return "NARP";
            case 55: return "MOBILE";
            case 56: return "TLSP";
            case 57: return "SKIP";
            case 58: return "IPv6-ICMP";
            case 59: return "IPv6-NoNxt";
            case 60: return "IPv6-Opts";
            case 61: return "ANY-HOST-INTERNAL";
            case 62: return "CFTP";
            case 63: return "ANY-LOCAL";
            case 64: return "SAT-EXPAK";
            case 65: return "KRYPTOLAN";
            case 66: return "RVD";
            case 67: return "IPPC";
            case 68: return "ANY-FILE-SYSTEM";
            case 69: return "SAT-MON";
            case 70: return "VISA";
            case 71: return "IPCV";
            case 72: return "CPNX";
            case 73: return "CPHB";
            case 74: return "WSN";
            case 75: return "PVP";
            case 76: return "BR-SAT-MON";
            case 77: return "SUN-ND";
            case 78: return "WB-MON";
            case 79: return "WB-EXPAK";
            case 80: return "ISO-IP";
            case 81: return "VMTP";
            case 82: return "SECURE-VMTP";
            case 83: return "VINES";
            case 84: return "TTP";
            case 85: return "NSFNET-IGP";
            case 86: return "DGP";
            case 87: return "TCF";
            case 88: return "EIGRP";
            case 89: return "OSPFIGP";
            case 90: return "Sprite-RPC";
            case 91: return "LARP";
            case 92: return "MTP";
            case 93: return "AX.25";
            case 94: return "IPIP";
            case 95: return "MICP";
            case 96: return "SCC-SP";
            case 97: return "ETHERIP";
            case 98: return "ENCAP";
            case 99: return "ANY-ENCRYPT";
            case 100: return "GMTP";
            case 101: return "IFMP";
            case 102: return "PNNI";
            case 103: return "PIM";
            case 104: return "ARIS";
            case 105: return "SCPS";
            case 106: return "QNX";
            case 107: return "A/N";
            case 108: return "IPComp";
            case 109: return "SNP";
            case 110: return "Compaq-Peer";
            case 111: return "IPX-in-IP";
            case 112: return "VRRP";
            case 113: return "PGM";
            case 114: return "ANY-0-HOP";
            case 115: return "L2TP";
            case 116: return "DDX";
            case 117: return "IATP";
            case 118: return "STP";
            case 119: return "SRP";
            case 120: return "UTI";
            case 121: return "SMP";
            case 122: return "SM";
            case 123: return "PTP";
            case 124: return "ISIS over IPv4";
            case 125: return "FIRE";
            case 126: return "CRTP";
            case 127: return "CRUDP";
            case 128: return "SSCOPMCE";
            case 129: return "IPLT";
            case 130: return "SPS";
            case 131: return "PIPE";
            case 132: return "SCTP";
            case 133: return "FC";
            case 134: return "RSVP-E2E-IGNORE";
            case 135: return "Mobility Header";
            case 136: return "UDPLite";
            case 137: return "MPLS-in-IP";
            case 138: return "manet";
            case 139: return "HIP";
            case 140: return "Shim6";

            case 253:
            case 254: return "Experiments and testings";
            case 255: return "Reserved";

            default: return "Unassigned";
        }
    }

    static QString hostToStr(in_addr addr) {
        return hostToStr(addr.s_addr);
    }

    static QString hostToStr(unsigned long host) {
        host = ntohl(host);
        return QString("%1.%2.%3.%4").arg(ULONG_BYTE4(host)).arg(ULONG_BYTE3(host)).arg(ULONG_BYTE2(host)).arg(ULONG_BYTE1(host));
    }

    static QStringList hostsList() {
        QStringList list;

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2,2), &wsaData) == 0) {

    //        if (WSAIoctl(raw_socket, SIO_ADDRESS_LIST_QUERY, 0, 0, addrlist, sizeof(addrlist), &N, 0, 0) == SOCKET_ERROR){
    //            printf("-ERR:WSAIoctl(,SIO_ADDRESS_LIST_QUERY) error %d\n", WSAGetLastError()); return -1;
    //        }

    //        if ((n_addr = llist->iAddressCount) == 0) {
    //            printf("-ERR:IP list is empty\n");return -1;
    //        }

    //        // Print the list of available interfaces
    //        for(a = 0; a < n_addr; a++)
    //            printf("IP - %s\n", inet_ntoa(((struct sockaddr_in*) llist->Address[a].lpSockaddr)->sin_addr));

            char hostname[128];

            gethostname(hostname, sizeof(hostname));
            HOSTENT * host_info = gethostbyname(hostname);

            if (host_info == NULL) {
                int dwError = WSAGetLastError();
                if (dwError != 0) {
                    if (dwError == WSAHOST_NOT_FOUND) {
    //                    err = "Host info error: Host not found";
                        return list;
                    } else if (dwError == WSANO_DATA) {
    //                    err = "Host info error: No data record found";
                        return list;
                    } else {
    //                    err = "Host info error: " + QString::number(WSAGetLastError());
                        return list;
                    }
                }
            }

            struct in_addr **pptr = (struct in_addr **)host_info -> h_addr_list;

            while(*pptr != NULL)
                list << hostToStr(**(pptr++));

            WSACleanup();
        }

        return list;
    }


    static QHash<QString, QString> packetProcess(char * buffer, int size) {
        IPV4_HDR * iphdr = (IPV4_HDR *)buffer;

        switch (iphdr -> protocol) {
            case IPPROTO_ICMP: return parseIcmpPacket(buffer, size);
            case IPPROTO_TCP: return parseTcpPacket(buffer, size);
            case IPPROTO_UDP: return parseUdpPacket(buffer, size);

            default:
                QHash<QString, QString> res;
                parseIpHeader(buffer, size, res, true);
                return res;
        }
    }

    static int parseIpHeader(char * buffer, int size, QHash<QString, QString> & res, bool raw_payload = false) {
        IPV4_HDR * iphdr = (IPV4_HDR *)buffer;
        unsigned short iphdrlen = iphdr -> header_len * 4;

        res.insert(SOCK_ATTR_TIMESTAMP,             TIMESTAMP_STR);
        res.insert("IP Version",                    UNSTR(iphdr -> header_ver));
        res.insert("IP Header Length",              UNSTR(iphdrlen));
        res.insert("IP Type Of Service",            UNSTR(iphdr -> tos));
        res.insert("IP Total Length",               NSTR_HOST_BYTES_ORDER(iphdr -> total_length));
        res.insert("IP Identification",             NSTR_HOST_BYTES_ORDER(iphdr -> id));
        res.insert("IP Reserved ZERO Field",        UNSTR(iphdr -> reserved_zero));
        res.insert("IP Dont Fragment Field",        UNSTR(iphdr -> dont_fragment));
        res.insert("IP More Fragment Field",        UNSTR(iphdr -> more_fragment));
        res.insert("IP TTL",                        UNSTR(iphdr -> ttl));
        res.insert(SOCK_ATTR_NUM_PROTOCOL,          UNSTR(iphdr -> protocol));
        res.insert(SOCK_ATTR_PROTOCOL,              protocolToStr((unsigned int)iphdr -> protocol));
        res.insert("IP Checksum",                   NSTR_HOST_BYTES_ORDER(iphdr -> checksum));

        res.insert(SOCK_ATTR_SRC_IP,                hostToStr(iphdr -> srcaddr));
        res.insert(SOCK_ATTR_DEST_IP,               hostToStr(iphdr -> destaddr));

        if (raw_payload)
            res.insert(SOCK_ATTR_PAYLOAD,           ucharsToStr(buffer + iphdrlen, size - iphdrlen));

        return iphdrlen;
    }

    static QHash<QString, QString> parseTcpPacket(char * buffer, int size) {
        QHash<QString, QString> res;
        unsigned short iphdrlen = parseIpHeader(buffer, size, res);

        TCP_HDR * tcpheader = (TCP_HDR *)(buffer + iphdrlen);
        int data_offset = tcpheader -> data_offset * 4;

        res.insert(SOCK_ATTR_SRC_PORT,              NSTR_HOST_BYTES_ORDER(tcpheader -> source_port));
        res.insert(SOCK_ATTR_DEST_PORT,             NSTR_HOST_BYTES_ORDER(tcpheader -> dest_port));
        res.insert("TCP Sequence Number",           NLSTR_HOST_BYTES_ORDER(tcpheader -> sequence));
        res.insert("TCP Acknowledge Number",        NLSTR_HOST_BYTES_ORDER(tcpheader -> acknowledge));
        res.insert("TCP Header Length",             UNSTR(data_offset));
        res.insert("TCP CWR Flag",                  UNSTR(tcpheader -> cwr));
        res.insert("TCP ECN Flag",                  UNSTR(tcpheader -> ecn));
        res.insert("TCP Urgent Flag",               UNSTR(tcpheader -> urg));
        res.insert("TCP Acknowledgement Flag",      UNSTR(tcpheader -> ack));
        res.insert("TCP Push Flag",                 UNSTR(tcpheader -> psh));
        res.insert("TCP Reset Flag",                UNSTR(tcpheader -> rst));
        res.insert("TCP Synchronise Flag",          UNSTR(tcpheader -> syn));
        res.insert("TCP Finish Flag",               UNSTR(tcpheader -> fin));
        res.insert("TCP Window",                    NSTR_HOST_BYTES_ORDER(tcpheader -> window));
        res.insert("TCP Checksum",                  NSTR_HOST_BYTES_ORDER(tcpheader -> checksum));
        res.insert("TCP Urgent Pointer",            NSTR(tcpheader -> urgent_pointer));
        res.insert(SOCK_ATTR_PAYLOAD,
            ucharsToStr(
                buffer + iphdrlen + data_offset,
                size - iphdrlen - data_offset
            )
        );

        return res;
    }

    static QHash<QString, QString> parseUdpPacket(char * buffer, int size) {
        QHash<QString, QString> res;
        unsigned short iphdrlen = parseIpHeader(buffer, size, res);

        UDP_HDR * udpheader = (UDP_HDR *)(buffer + iphdrlen);

        res.insert(SOCK_ATTR_SRC_PORT,              NSTR_HOST_BYTES_ORDER(udpheader -> source_port));
        res.insert(SOCK_ATTR_DEST_PORT,             NSTR_HOST_BYTES_ORDER(udpheader -> dest_port));
        res.insert("UDP Length",                    NSTR_HOST_BYTES_ORDER(udpheader -> length));
        res.insert("UDP Checksum",                  NSTR_HOST_BYTES_ORDER(udpheader -> checksum));

        res.insert(SOCK_ATTR_PAYLOAD,
            ucharsToStr(
                buffer + sizeof(UDP_HDR) + iphdrlen,
                size - sizeof(UDP_HDR) - iphdrlen
            )
        );

        return res;
    }

    static QHash<QString, QString> parseIcmpPacket(char * buffer, int size) {
        QHash<QString, QString> res;
        unsigned short iphdrlen = parseIpHeader(buffer, size, res);

        ICMP_HDR * icmpheader = (ICMP_HDR*)(buffer + iphdrlen);

        QString icmp_type = NSTR(icmpheader -> type);

        switch(icmpheader -> type) {
            case 0: icmp_type += " (ICMP Echo Reply)"; break;
            case 11: icmp_type += " (TTL Expired)"; break;
//            defaut: break;
        }

        res.insert("ICMP Type",                     icmp_type);
        res.insert("ICMP Code",                     UNSTR(icmpheader -> code));
        res.insert("ICMP Code",                     NSTR_HOST_BYTES_ORDER(icmpheader -> checksum));
        res.insert("ICMP ID",                       NSTR_HOST_BYTES_ORDER(icmpheader -> id));
        res.insert("ICMP Sequence",                 NSTR_HOST_BYTES_ORDER(icmpheader -> seq));

        res.insert(SOCK_ATTR_PAYLOAD,
            ucharsToStr(
                buffer + sizeof(ICMP_HDR) + iphdrlen,
                size - sizeof(ICMP_HDR) - iphdrlen
            )
        );

        return res;
    }
};

#endif // PROTO_HEADERS
