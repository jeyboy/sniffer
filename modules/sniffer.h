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

    bool resolve_ip_sender;
    bool resolve_ip_receiver;
    bool resolve_app;

    void procPacketAsync(QHash<QString, QString> attrs, int port) {
        protocol_counters[attrs[SOCK_ATTR_PROTOCOL]]++;

        QString dest_ip = attrs[SOCK_ATTR_DEST_IP];
        bool income = local_ips.contains(dest_ip);

        direction_counters[income]++;

        attrs.insert(SOCK_ATTR_DIRECTION,                   income ? SOCK_DIRECTION_IN : SOCK_DIRECTION_OUT);

        if (resolve_app && !income) {
            if (port == 0) port = htons(attrs.value(SOCK_ATTR_DEST_PORT, QStringLiteral("0")).toInt());

            if (port > 0) {
                DWORD pid = 0;

                if (attrs[SOCK_ATTR_PROTOCOL] == QStringLiteral("TCP"))
                    pid = SocketUtils::addrTcpToPid(port);
                else if (attrs[SOCK_ATTR_PROTOCOL] == QStringLiteral("UDP"))
                    pid = SocketUtils::addrUdpToPid(port);

                QString app_path = pid > 0 ? SocketUtils::pidToPath(pid) : QStringLiteral("Unknown PORT:%1").arg(port);
                attrs.insert(SOCK_ATTR_APP,                 app_path);
            }
        }

        if (resolve_ip_sender)
            attrs.insert(SOCK_ATTR_SRC,                     getHostName(attrs[SOCK_ATTR_SRC_IP]));

        if (resolve_ip_receiver)
            attrs.insert(SOCK_ATTR_DEST,                    getHostName(attrs[SOCK_ATTR_DEST_IP]));

        emit sendPacket(attrs);
    }

    void registerWrapper(const char * packetSlot, const char * errorSlot, const QString & ip = QString(), int port = -1) {
        connect(this, SIGNAL(sendPacket(QHash<QString,QString>)), parent(), packetSlot);

        SnifferSocketWrapper * wrapper = new SnifferSocketWrapper();
        wrapper -> instantiate(this, SLOT(procPacket(char*,int,int)), parent(), errorSlot, ip, port);
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
protected slots:
    void procPacket(char * data, int length, int port) {
        QHash<QString, QString> attrs = SocketUtils::packetProcess(data, length);
        attrs.insert(SOCK_ATTR_LENGTH,                  NSTR(length));
        free(data);

        //QFutureWatcher<void> * server = new QFutureWatcher<void>();
        /*server -> setFuture(*/QtConcurrent::run(this, &Sniffer::procPacketAsync, attrs, port)/*)*/;
    }
public:
    Sniffer(QObject * parent) : QObject(parent), resolve_ip_sender(false), resolve_ip_receiver(false), resolve_app(false) {
        qRegisterMetaType<QHash<QString,QString> >("QHash<QString,QString>");
    }

    ~Sniffer() { stop(); }

    void enableSenderIpResolving(bool enabled = true) { resolve_ip_sender = enabled; }
    void enableReceiverIpResolving(bool enabled = true) { resolve_ip_receiver = enabled; }
    void enableAppPathResolving(bool enabled = true) { resolve_app = enabled; }

    QString stat() {
        return QStringLiteral("income: %1 ||| outcome: %2").arg(direction_counters[true]).arg(direction_counters[false]);
    }

    int protoStat(const QString & proto) { return protocol_counters.value(proto, 0); }

    QStringList getHostsList() { return SocketUtils::hostsList(); }

    void start(const char * packetSlot, const char * errorSlot, int port = -1) {
        if (!wrappers.isEmpty()) return;

        QStringList hosts = getHostsList();

        for(QStringList::Iterator h = hosts.begin(); h != hosts.end(); h++)
            local_ips.insert(*h, true);

        registerWrapper(packetSlot, errorSlot, hosts.first(), port);
    }

    void stop() {
        for(QHash<QString, SnifferSocketWrapper *>::Iterator it = wrappers.begin(); it != wrappers.end(); it++) {
            it.value() -> stop();
            it.value() -> deleteLater();
        }

        wrappers.clear();
    }


};

#endif // SNIFFER
