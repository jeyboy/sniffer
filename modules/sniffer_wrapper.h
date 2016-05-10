#ifndef SNIFFER_WRAPPER
#define SNIFFER_WRAPPER

#include <qobject.h>
#include <qthread.h>

#include "raw_socket.h"

class SnifferSocketWrapper : public QObject {
    Q_OBJECT

    RawSocket * sock;
    QString ip;
    int port;

    QHash<QString, bool> ips;
signals:
    void finished();
    void error(QString);
    void updateStat(int, int);
public:
    SnifferSocketWrapper(QObject * parent) : QObject() {
        sock = new RawSocket();

        QObject::connect(this, SIGNAL(updateStat(int,int)), parent, SLOT(updateStat(int,int)));
    }

    void instantiate(QHash<QString, bool> ips, QObject * receiver, const char * packetSlot, const char * errorSlot, const QString & ip = QString(), int port = -1) {
        ips = ips;

        QObject::connect(this, SIGNAL(finished()), this, SLOT(deleteLater()));
        QObject::connect(this, SIGNAL(error(QString)), receiver, errorSlot);
        QObject::connect(sock, SIGNAL(error(QString)), receiver, errorSlot);
        QObject::connect(sock, SIGNAL(packetReady(QHash<QString,QString>)), receiver, packetSlot);
        QObject::connect(sock, SIGNAL(packetReady(QHash<QString,QString>)), this, SLOT(packetReady(QHash<QString,QString>)));

        if (sock -> binding(ip, port)) {
            sock -> enablePromMode();
            sock -> enableIncludeHeader(true);
            sock -> enableBlocking(true);
        }
    }
private slots:
    void packetReady(QHash<QString,QString> attrs) {
        int income = 0, outcome = 0;

        ips.contains(attrs["Destination IP"]) ? income++ : outcome++;
        emit updateStat(income, outcome);
    }

public slots:
    void process() {
        if (sock -> isReady())
            sock -> blockableSniffing();
        emit finished();
    }
    void stop() {
        sock -> stopBlockableSniffing();
        QThread::currentThread() -> wait();
    }
};

#endif // SNIFFER_WRAPPER
