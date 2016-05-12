#ifndef RAW_SOCKET
#define RAW_SOCKET

#include <qobject.h>
#include <qstring.h>
#include <qhash.h>
#include <qdatetime.h>
#include <qdebug.h>

#include "proto_defines.h"
#include "proto_headers.h"

#define MAX_PACKET_SIZE 0x10000

class RawSocket : public QObject {
    Q_OBJECT

    bool initiated, ready;
    mutable bool blocked;

    int af_type;

    SOCKET _socket;
    SOCKADDR_IN	socket_address;
    QString ip;

    char buffer[MAX_PACKET_SIZE];  // 64 Kb
signals:
    void error(QString message);
    void packetReady(char * buffer, int length, int port);

public:
    //SOCK_STREAM
    RawSocket(int sock_type = SOCK_RAW, int protocol = IPPROTO_IP, int af = AF_INET)
        : ready(false), af_type(af), _socket(INVALID_SOCKET) {
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

    bool binding(const QString & sock_ip = QString()/*"127.0.0.1"*/, int port = -1) {
        if (!initiated) return false;

        ip = sock_ip;

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
            int count = recvfrom(_socket, buffer, sizeof(buffer), 0, (sockaddr *)&sender_addr, &sender_addr_size);

            if (count > 0) {
                // Once you have their address, you can use inet_ntop(), getnameinfo(), or gethostbyaddr() to print or get more information
                int port = 0;

                switch (sender_addr.ss_family) {
                    case AF_INET: {
                        sockaddr_in * from = ((struct sockaddr_in*)&sender_addr);
                        port = ntohs(from -> sin_port);
//                        ip = from -> sin_addr.s_addr;
                        break;}
                    case AF_INET6: {
                        sockaddr_in6 * from = ((struct sockaddr_in6*)&sender_addr);
                        port = ntohs(from -> sin6_port);
//                        struct in6_addr sin6_addr;
                    break;}
                }

                char * send_buff = (char *)malloc(count);
                memcpy(send_buff, buffer, count);
                emit packetReady(send_buff, count, port);
            }
        }
    }

    void stopBlockableSniffing() {
        blocked = false;
    }

    // mixed mode
    bool enablePromMode(bool enable = true) {
        if (ready) {
            DWORD n;
            u_long prom_mode = enable ? 1 : 0;
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
