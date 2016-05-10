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
