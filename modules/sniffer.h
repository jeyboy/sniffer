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
    QHash<QString, bool> local_ips;
    QHash<QString, QString> host_names;
    QHash<QString, int> protocol_counters;
    QHash<bool, int> direction_counters;


    void registerWrapper(const char * packetSlot, const char * errorSlot, const QString & ip = QString(), int port = -1) {
        connect(this, SIGNAL(sendPacket(QHash<QString,QString>)), parent(), packetSlot);

        SnifferSocketWrapper * wrapper = new SnifferSocketWrapper();
        wrapper -> instantiate(this, SLOT(procPacket(char*,int)), parent(), errorSlot, ip, port);
        wrappers.insert(ip, wrapper);

        QThread * thread = new QThread();

        connect(thread, SIGNAL(started()), wrapper, SLOT(process()));
        connect(wrapper, SIGNAL(finished()), thread, SLOT(quit()));
        connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

        wrapper -> moveToThread(thread);
        thread -> start(QThread::TimeCriticalPriority);
    }

    QString getHostName(QString & ip) {
        QString name = host_names.value(ip);

        if (name.isEmpty()) {
            name = SocketUtils::hostToHostName(ip);
            host_names.insert(ip, name);
        }

        return name;
    }

signals:
    void sendPacket(QHash<QString, QString>);
public slots:
    void procPacket(char * data, int length) {
        QHash<QString, QString> attrs = SocketUtils::packetProcess(data, length);

        protocol_counters[attrs[SOCK_ATTR_PROTOCOL]] = protocol_counters.value(attrs[SOCK_ATTR_PROTOCOL], 0) + 1;

        QString dest_ip = attrs[SOCK_ATTR_DEST_IP];
        bool income = local_ips.contains(dest_ip);

        direction_counters[income] = direction_counters.value(income, 0) + 1;

        attrs.insert(SOCK_ATTR_DIRECTION,               income ? QStringLiteral("in") : QStringLiteral("out"));

        attrs.insert(SOCK_ATTR_SRC,                     getHostName(attrs[SOCK_ATTR_SRC_IP]));
        attrs.insert(SOCK_ATTR_DEST,                    getHostName(attrs[SOCK_ATTR_DEST_IP]));

        attrs.insert(SOCK_STAT_INCOME,                  UNSTR(direction_counters[true]));
        attrs.insert(SOCK_STAT_OUTCOME,                 UNSTR(direction_counters[false]));

        free(data);
        emit sendPacket(attrs);
    }
public:
    Sniffer(QObject * parent) : QObject(parent) {
        qRegisterMetaType<QHash<QString,QString> >("QHash<QString,QString>");
    }

    void start(const char * packetSlot, const char * errorSlot, int port = -1) {
        if (!wrappers.isEmpty()) return;

        QStringList hosts = SocketUtils::hostsList();

        for(QStringList::Iterator h = hosts.begin(); h != hosts.end(); h++) {
            local_ips.insert(*h, true);
            registerWrapper(packetSlot, errorSlot, *h, port);
        }
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
