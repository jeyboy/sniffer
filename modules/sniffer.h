#ifndef SNIFFER
#define SNIFFER


//void ColorPacket(const IPHeader *h, const u_long haddr, const u_long whost = 0)
//{
//	if (h->xsum)
//		SetConsoleTextColor(0x17);
//	else
//		SetConsoleTextColor(0x07);

//	if (haddr == h->src)
//	{
//		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/
//			FOREGROUND_RED | FOREGROUND_INTENSITY);
//	}
//	else if (haddr == h->dest)
//	{
//		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/
//			FOREGROUND_GREEN | FOREGROUND_INTENSITY);
//	}

//	if (h->protocol == PROT_ICMP || h->protocol == PROT_IGMP)
//	{
//		SetConsoleTextColor(0x70);
//	}
//	else if(h->protocol == PROT_IP || h->protocol == 115)
//	{
//		SetConsoleTextColor(0x4F); // IP-in-IP, L2TP
//	}
//	else if(h->protocol == 53 || h->protocol == 56)
//	{
//		SetConsoleTextColor(0x4C); // TLS, IP with Encryption
//	}

//	if(whost == h->dest || whost == h->src)
//	{
//		SetConsoleTextColor(0x0A);
//	}
//}


//void ShowHelp()
//{
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("IP-datagram structure:\n");
//	printf("ver");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Internet Protocol version. Common Defaults: usually 4 (IPv4) or 6 (IPv6), 4 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("hlen");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": IP header length(in bytes), 4 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("tos");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Type of Service flags controls the priority of the packet. The first 3 bits stand for routing priority, the next 4 bits for the type of service (delay, throughput, reliability and cost), 8 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("len");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Total length must contain the total length of the IP datagram. This includes IP, ICMP, TCP or UDP header and payload size in bytes, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("id");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": The ID sequence number is mainly used for reassembly of fragmented IP datagrams, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("flags");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Flags, 3 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("offset");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Offset, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("ttl");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Time to live, 8 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("prot");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": The transport layer protocol. Can be tcp (6), udp(17), icmp(1), or whatever protocol follows the IP header, 8 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("crc");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": The header checksum. Every time anything in the header changes, it needs to be recalculated, or the packet will be discarded by the next router, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("src");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Source address, 32 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("dest");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Destination address, 32 bits;\n");
//}

#include <qobject.h>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrentRun>

#include "raw_socket.h"

class Sniffer : public QObject {
    Q_OBJECT

    QHash<QString, QFutureWatcher<void> *> servers;
    QHash<QString, RawSocket *> sockets;
signals:
    void packetReceived(const QHash<QString, QString> & attrs);
    void error(QString message);

public:
    ~Sniffer() {
        for(QHash<QString, QFutureWatcher<void> *>::Iterator it = servers.begin(); it != servers.end(); it++) {
            QFutureWatcher<void> * server = it.value();

            if (server && server -> isRunning()) {
                server -> cancel();
                server -> waitForFinished();
            }
        }

        for(QHash<QString, RawSocket *>::Iterator it = sockets.begin(); it != sockets.end(); it++) {
            delete it.value();
        }
    }

    Sniffer(QObject * parent, int port = -1) : QObject(parent) {
        qRegisterMetaType<QHash<QString,QString> >("QHash<QString,QString>");

        QStringList hosts = RawSocket::hostsList();

        for(QStringList::Iterator h = hosts.begin(); h != hosts.end(); h++) {
            RawSocket * sock = new RawSocket();
            if (sock -> binding(*h, port)) {
                if (!sock -> enablePromMode())
                    emit error(sock -> error());
                sock -> enableIncludeHeader(false);
                sock -> enableBlocking(false);
            }

            if (!sock -> error().isEmpty())
                emit error(sock -> error());
            else {
                sockets.insert(*h, sock);

                QFutureWatcher<void> * server = new QFutureWatcher<void>();
                server -> setFuture(QtConcurrent::run(this, &Sniffer::checkPackets, sock, server));
                servers.insert(*h, server);
            }
        }
    }

    void checkPackets(RawSocket * sock, QFutureWatcher<void> * initiator) {
        while(!initiator -> isCanceled()) {
            QHash<QString, QString> attrs = sock -> packetSniff();
            if (!attrs.isEmpty()) {
                emit packetReceived(attrs);
                QThread::msleep(25);
            }
        }
    }
};

#endif // SNIFFER
