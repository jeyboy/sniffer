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
signals:
    void finished();
    void error(QString);
    void updateStat(int, int);
public:
    SnifferSocketWrapper(QHash<QString, bool> & ips) : QObject() {
        sock = new RawSocket(ips);
    }

    ~SnifferSocketWrapper() {
        delete sock;
    }

    void instantiate(QObject * receiver, const char * packetSlot, const char * errorSlot, const QString & ip = QString(), int port = -1) {
        QObject::connect(this, SIGNAL(finished()), this, SLOT(deleteLater()));
        QObject::connect(this, SIGNAL(error(QString)), receiver, errorSlot);
        QObject::connect(sock, SIGNAL(error(QString)), receiver, errorSlot);
        QObject::connect(sock, SIGNAL(packetReady(QHash<QString,QString>)), receiver, packetSlot);

        if (sock -> binding(ip, port)) {
            sock -> enablePromMode();
            sock -> enableIncludeHeader(true);
            sock -> enableBlocking(false);
        }
    }

public slots:
    void process() {
        if (sock -> isReady())
            sock -> blockableSniffing();
        emit finished();
    }
    void stop() {
        sock -> stopBlockableSniffing();
    }
};

#endif // SNIFFER_WRAPPER
