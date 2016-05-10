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

    int outcome, income;

    void registerWrapper(QHash<QString, bool> ips, const char * packetSlot, const char * errorSlot, const QString & ip = QString(), int port = -1) {
        SnifferSocketWrapper * wrapper = new SnifferSocketWrapper(this);
        wrapper -> instantiate(ips, parent(), packetSlot, errorSlot, ip, port);
        wrappers.insert(ip, wrapper);

        QThread * thread = new QThread();

        connect(thread, SIGNAL(started()), wrapper, SLOT(process()));
        connect(wrapper, SIGNAL(finished()), thread, SLOT(quit()));
        connect(this, SIGNAL(stopAll()), wrapper, SLOT(stop()));
        connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

        wrapper -> moveToThread(thread);
        thread -> start(QThread::TimeCriticalPriority);
    }

signals:
    void stopAll();

public slots:
    void updateStat(int income_val, int outcome_val) {
        income += income_val;
        outcome += outcome_val;
    }
public:
    QString stat() { return QStringLiteral("income: ") + QString::number(income) + QStringLiteral(" ||| outcome: ") + QString::number(outcome); }

    Sniffer(QObject * parent, const char * packetSlot, const char * errorSlot, int port = -1) : QObject(parent), outcome(0), income(0) {
        qRegisterMetaType<QHash<QString,QString> >("QHash<QString,QString>");

        QStringList hosts = RawSocket::hostsList();
        QHash<QString, bool> ips;

//        registerSocket(QString(), port);

        for(QStringList::Iterator h = hosts.begin(); h != hosts.end(); h++) {
            ips.insert(*h, true);
//            registerSocket(*h, port);
        }

        registerWrapper(ips, packetSlot, errorSlot, hosts.first(), port);
    }

    ~Sniffer() {
        emit stopAll();
    }

//    void checkPackets(RawSocket * sock, QFutureWatcher<void> * initiator) {
//        while(!initiator -> isCanceled()) {
//            QHash<QString, QString> attrs = sock -> packetSniff();
//            if (!attrs.isEmpty()) {
//                if (addresses.contains(attrs["Destination IP"]))
//                    income++;
//                else
//                    outcome++;

//                emit packetReceived(attrs);
////                QThread::usleep(5);
//            }
//        }
//    }
};

#endif // SNIFFER
