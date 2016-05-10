#ifndef RAW_SOCKET
#define RAW_SOCKET

#include <qobject.h>
#include <qstring.h>
#include <qhash.h>

#include "proto_defines.h"
#include "proto_headers.h"

#define MAX_PACKET_SIZE 0x10000

#define ULONG_BYTE4(u) ((u & 0xFF000000) >> 24)
#define ULONG_BYTE3(u) ((u & 0xFF0000) >> 16)
#define ULONG_BYTE2(u) ((u & 0xFF00) >> 8)
#define ULONG_BYTE1(u) (u & 0xFF)

#define BYTE_L(u) (u & 0xF)
#define BYTE_H(u) (u >> 4)

#define IP_FLAGS(f) (f >> 13)
#define IP_OFFSET(o) (o & 0x1FFF)

#define CONST_CHAR(qstring) qstring.toStdString().c_str()

#define NSTR(num) QString::number(num)
#define UNSTR(num) QString::number((unsigned int)num)
#define NSTR_HOST_BYTES_ORDER(num) NSTR(ntohs(num))
#define NLSTR_HOST_BYTES_ORDER(num) NSTR(ntohl(num))

class RawSocket : public QObject {
    Q_OBJECT

    bool initiated, ready;
    mutable bool blocked;

    int af_type;

    SOCKET _socket;
    SOCKADDR_IN	socket_address;

    char buffer[MAX_PACKET_SIZE];  // 64 Kb

    QHash<unsigned char, int> protocol_counters;
    QHash<bool, int> direction_counters;
    QHash<QString, bool> local_ips;
signals:
    void error(QString);
    void packetReady(QHash<QString, QString>);

public:
    static QString hostToHostName(unsigned long host_ip) {
        struct addrinfo * res = 0;
        QString ip_str = hostToStr(host_ip);

        if (getaddrinfo(CONST_CHAR(ip_str), 0, 0, &res) == 0) {
            char host[NI_MAXHOST];

            // get first entry only
            getnameinfo(res -> ai_addr, res -> ai_addrlen, host, sizeof(host), 0, 0, 0);
            freeaddrinfo(res);

            return QString(host);
        }

        return QString();
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

    //SOCK_STREAM
    RawSocket(QHash<QString, bool> & local_ips, int sock_type = SOCK_RAW, int protocol = IPPROTO_IP, int af = AF_INET)
        : ready(false), af_type(af), _socket(INVALID_SOCKET), local_ips(local_ips) {
        WSADATA wsaData;
        initiated = WSAStartup(MAKEWORD(2,2), &wsaData) == 0;

        if (!initiated) {
            emit error("WSAStartup error: " + QString::number(WSAGetLastError()));
            return;
        }

        _socket = socket(af_type, sock_type, protocol);

        initiated = _socket != INVALID_SOCKET;

        if (!initiated)
            emit error("Socket error: " + QString::number(WSAGetLastError()));
    }

    ~RawSocket() {
        if (_socket != INVALID_SOCKET)
            closesocket(_socket);

        if (initiated)
            WSACleanup();
    }

    bool isReady() { return ready; }

    bool binding(const QString & ip = QString()/*"127.0.0.1"*/, int port = -1) {
        if (!initiated) return false;

        if (!initSocketAddr(ip, port)) return false;

        ready = bind(_socket, (SOCKADDR *)&socket_address, sizeof(SOCKADDR)) != SOCKET_ERROR;

        if (!ready)
            emit error("Socket bind error: " + QString::number(WSAGetLastError()));

        return ready;
    }

    void blockableSniffing() {
        blocked = true;
        sockaddr_storage sender_addr;
        int sender_addr_size = sizeof(sender_addr);

        while(blocked) {
            int count = recvfrom(_socket, buffer, sizeof(buffer), MSG_PEEK, (sockaddr *)&sender_addr, &sender_addr_size);

            if (count > 0) {
//                switch (sender_addr.ss_family) {
//                    case AF_INET: {
//                        sockaddr_in * from = ((struct sockaddr_in*)&sender_addr);
//                        break;}
//                    case AF_INET6: {
//                        sockaddr_in6 * from = ((struct sockaddr_in6*)&sender_addr);
//                    break;}
//                }

                emit packetReady(packetProcess(buffer, count));
            }
        }
    }

    void stopBlockableSniffing() {
        blocked = false;
    }

    QHash<QString, QString> packetSniff() {
//        int count = recv(_socket, buffer, sizeof(buffer), MSG_PEEK);
        sockaddr_storage sender_addr;
        int sender_addr_size = sizeof(sender_addr);

        int count = recvfrom(_socket, buffer, sizeof(buffer), MSG_PEEK, (sockaddr *)&sender_addr, &sender_addr_size);

//        switch (sender_addr.ss_family) {
//            case AF_INET: {
//                sockaddr_in * from = ((struct sockaddr_in*)&sender_addr);
//                break;}
//            case AF_INET6: {
//                sockaddr_in6 * from = ((struct sockaddr_in6*)&sender_addr);
//            break;}
//        }

        if (count > 0)
            return packetProcess(buffer, count);
        else return stubData();
    }

    // mixed mode
    bool enablePromMode(bool enable = true) {
        if (ready) {
            DWORD n;
            u_long prom_mode = enable ? 1 : 0;
//            return ioctlsocket(_socket, SIO_RCVALL, &prom_mode) != SOCKET_ERROR;
            return WSAIoctl(_socket, SIO_RCVALL, &prom_mode, sizeof(prom_mode), 0, 0, &n, 0, 0) != SOCKET_ERROR;
        }

        return false;
    }

    void enableIncludeHeader(bool enable = true) {
        int optval = enable ? 1 : 0;
        setsockopt(_socket, IPPROTO_IP, IP_HDRINCL, (char *)&optval, sizeof optval);
    }

    bool enableBlocking(bool enable = true) {
        if (ready) {
            u_long arg = enable ? 1 : 0;
            return ioctlsocket(_socket, FIONBIO, &arg) != SOCKET_ERROR;
        }

        return false;
    }

private:
    QHash<QString, QString> stubData() { return QHash<QString, QString>(); }

    QHash<QString, QString> packetProcess(char * buffer, int size) {
        IPV4_HDR * iphdr = (IPV4_HDR *)buffer;

        protocol_counters[iphdr -> protocol] = protocol_counters.value(iphdr -> protocol, 0) + 1;

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

    int parseIpHeader(char * buffer, int size, QHash<QString, QString> & res, bool raw_payload = false) {
        IPV4_HDR * iphdr = (IPV4_HDR *)buffer;
        unsigned short iphdrlen = iphdr -> header_len * 4;

        res.insert("IP Version",                    UNSTR(iphdr -> header_ver));
        res.insert("IP Header Length",              UNSTR(iphdrlen));
        res.insert("IP Type Of Service",            UNSTR(iphdr -> tos));
        res.insert("IP Total Length",               NSTR_HOST_BYTES_ORDER(iphdr -> total_length));
        res.insert("IP Identification",             NSTR_HOST_BYTES_ORDER(iphdr -> id));
        res.insert("IP Reserved ZERO Field",        UNSTR(iphdr -> reserved_zero));
        res.insert("IP Dont Fragment Field",        UNSTR(iphdr -> dont_fragment));
        res.insert("IP More Fragment Field",        UNSTR(iphdr -> more_fragment));
        res.insert("IP TTL",                        UNSTR(iphdr -> ttl));
        res.insert("IP NProtocol",                  UNSTR(iphdr -> protocol));
        res.insert("IP Protocol",                   protocolToStr((unsigned int)iphdr -> protocol));
        res.insert("IP Checksum",                   NSTR_HOST_BYTES_ORDER(iphdr -> checksum));

        QString dest_ip = hostToStr(iphdr -> destaddr);
        bool income = local_ips.contains(dest_ip);

        direction_counters[income] = direction_counters.value(income, 0) + 1;

        res.insert("Direction",                     income ? QStringLiteral("in") : QStringLiteral("out"));

        res.insert("Source IP",                     hostToStr(iphdr -> srcaddr));
        res.insert("Destination IP",                dest_ip);

        res.insert("Source",                        hostToHostName(iphdr -> srcaddr));
        res.insert("Destination",                   hostToHostName(iphdr -> destaddr));

        if (raw_payload)
            res.insert("Raw Payload",               QString::fromUtf8(buffer + iphdrlen, size - iphdrlen));

        res.insert("-I",                            UNSTR(direction_counters[true]));
        res.insert("-O",                            UNSTR(direction_counters[false]));

        return iphdrlen;
    }

    QHash<QString, QString> parseTcpPacket(char * buffer, int size) {
        QHash<QString, QString> res;
        unsigned short iphdrlen = parseIpHeader(buffer, size, res);

        TCP_HDR * tcpheader = (TCP_HDR *)(buffer + iphdrlen);

        res.insert("TCP Source Port",               NSTR_HOST_BYTES_ORDER(tcpheader -> source_port));
        res.insert("TCP Destination Port",          NSTR_HOST_BYTES_ORDER(tcpheader -> dest_port));
        res.insert("TCP Sequence Number",           NLSTR_HOST_BYTES_ORDER(tcpheader -> sequence));
        res.insert("TCP Acknowledge Number",        NLSTR_HOST_BYTES_ORDER(tcpheader -> acknowledge));
        res.insert("TCP Header Length",             UNSTR(tcpheader -> data_offset * 4));
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
        res.insert("TCP Payload",
            QString::fromUtf8(
                buffer + iphdrlen + tcpheader -> data_offset * 4,
                size - iphdrlen - tcpheader -> data_offset * 4
            )
        );

        return res;
    }

    QHash<QString, QString> parseUdpPacket(char * buffer, int size) {
        QHash<QString, QString> res;
        unsigned short iphdrlen = parseIpHeader(buffer, size, res);

        UDP_HDR * udpheader = (UDP_HDR *)(buffer + iphdrlen);

        res.insert("UDP Source Port",               NSTR_HOST_BYTES_ORDER(udpheader -> source_port));
        res.insert("UDP Destination Port",          NSTR_HOST_BYTES_ORDER(udpheader -> dest_port));
        res.insert("UDP Length",                    NSTR_HOST_BYTES_ORDER(udpheader -> length));
        res.insert("UDP Checksum",                  NSTR_HOST_BYTES_ORDER(udpheader -> checksum));

        res.insert("UDP Payload",
            QString::fromUtf8(
                buffer + sizeof(UDP_HDR) + iphdrlen,
                size - sizeof(UDP_HDR) - iphdrlen
            )
        );

        return res;
    }

    QHash<QString, QString> parseIcmpPacket(char * buffer, int size) {
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

        res.insert("ICMP Payload",
            QString::fromUtf8(
                buffer + sizeof(ICMP_HDR) + iphdrlen,
                size - sizeof(ICMP_HDR) - iphdrlen
            )
        );

        return res;
    }

    bool initSocketAddr(const QString & ip, int port = -1) {
        ZeroMemory(&socket_address, sizeof(socket_address));
        socket_address.sin_family = af_type;

        if (!ip.isEmpty()) {
            unsigned long addr = inet_addr(CONST_CHAR(ip));
            socket_address.sin_addr.s_addr = addr;
        }

        if (port > 0)
            socket_address.sin_port = htons(port);

        return true;
    }
};



//    static DWORD GetClientPid(SOCKET client) {
//        DWORD pid = 0;

//        sockaddr_in ServerAddr = {0};
//        int ServerAddrSize = sizeof(ServerAddr);

//        sockaddr_in ClientAddr = {0};
//        int ClientAddrSize = sizeof(ClientAddr);

//        if ((getsockname(client, (sockaddr*)&ServerAddr, &ServerAddrSize) == 0) &&
//            (getpeername(client, (sockaddr*)&ClientAddr, &ClientAddrSize) == 0))
//        {
//            PMIB_TCPTABLE2 TcpTable = NULL;
//            ULONG TcpTableSize = 0;
//            ULONG result;

//            do {
//                result = GetTcpTable2(TcpTable, &TcpTableSize, TRUE);
//                if (result != ERROR_INSUFFICIENT_BUFFER)
//                    break;

//                LocalFree(TcpTable);
//                TcpTable = (PMIB_TCPTABLE2) LocalAlloc(LMEM_FIXED, TcpTableSize);
//            }
//            while (TcpTable != NULL);

//            if (result == NO_ERROR) {
//                for (DWORD dw = 0; dw < TcpTable->dwNumEntries; ++dw) {
//                    PMIB_TCPROW2 row = &(TcpTable->table[dw]);

//                    if ((row->dwState == MIB_TCP_STATE_ESTAB) &&
//                        (row->dwLocalAddr == ClientAddr.sin_addr.s_addr) &&
//                        ((row->dwLocalPort & 0xFFFF) == ClientAddr.sin_port) &&
//                        (row->dwRemoteAddr == ServerAddr.sin_addr.s_addr) &&
//                        ((row->dwRemotePort & 0xFFFF) == ServerAddr.sin_port))
//                    {
//                        pid = row -> dwOwningPid;
//                        break;
//                    }
//                }
//            }

//            LocalFree(TcpTable);
//        }

//        return pid;
//    }





//    void registerApp() {
//        HKEY hk;
//        DWORD dw;

//        string skey = path + ":*:Enabled:@xpsp2res.dll,-22019";

//        RegCreateKeyExA(
//            HKEY_LOCAL_MACHINE,
//            "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List",
//            0,
//            NULL,
//            REG_OPTION_NON_VOLATILE,
//            KEY_WRITE,
//            NULL,
//            &hk,
//            &dw
//            );

//        RegSetValueExA(
//            hk,
//            path.c_str(),
//            0,
//            REG_SZ,
//            (BYTE*)skey.c_str(),
//            (DWORD)skey.length()
//            );

//        RegCloseKey(hk);
//    }




//    unsigned short checksum(unsigned short *buf, int size)
//    {
//        unsigned long chksum=0;

//        //Calculate the checksum
//        while (size>1)
//        {
//            chksum+=*buf++;
//            size-=sizeof(unsigned short);
//        }

//        //If we have one char left
//        if (size)
//            chksum+=*(unsigned char*)buf;

//        //Complete the calculations
//        chksum=(chksum >> 16) + (chksum & 0xffff);
//        chksum+=(chksum >> 16);

//        //Return the value (inversed)
//        return (unsigned short)(~chksum);
//    }

#endif // RAW_SOCKET
