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

#include "sniffer_wrapper.h"

class Sniffer : public QObject {
    Q_OBJECT

    QHash<QString, SnifferSocketWrapper *> wrappers;

    void registerWrapper(QHash<QString, bool> ips, const char * packetSlot, const char * errorSlot, const QString & ip = QString(), int port = -1) {
        SnifferSocketWrapper * wrapper = new SnifferSocketWrapper(ips);
        wrapper -> instantiate(parent(), packetSlot, errorSlot, ip, port);
        wrappers.insert(ip, wrapper);

        QThread * thread = new QThread();

        connect(thread, SIGNAL(started()), wrapper, SLOT(process()));
        connect(wrapper, SIGNAL(finished()), thread, SLOT(quit()));
        connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

        wrapper -> moveToThread(thread);
        thread -> start(QThread::TimeCriticalPriority);
    }
public:
    Sniffer(QObject * parent) : QObject(parent) {
        qRegisterMetaType<QHash<QString,QString> >("QHash<QString,QString>");
    }

    void start(const char * packetSlot, const char * errorSlot, int port = -1) {
        if (!wrappers.isEmpty()) return;

        QStringList hosts = RawSocket::hostsList();

        QHash<QString, bool> ips;
        for(QStringList::Iterator h = hosts.begin(); h != hosts.end(); h++)
            ips.insert(*h, true);

        QString host = hosts.first();
        qDebug() << "HOST:" << host;
        registerWrapper(ips, packetSlot, errorSlot, host, port);
    }

    void stop() {
        for(QHash<QString, SnifferSocketWrapper *>::Iterator it = wrappers.begin(); it != wrappers.end(); it++) {
            it.value() -> stop();
            it.value() -> deleteLater();
        }

        wrappers.clear();
    }

    ~Sniffer() { stop(); }
};

#endif // SNIFFER
