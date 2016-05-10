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
    SnifferSocketWrapper() : QObject() {
        sock = new RawSocket();
    }

    ~SnifferSocketWrapper() {
        delete sock;
    }

    void instantiate(QObject * packet_receiver, const char * packetSlot, QObject * err_receiver,
                     const char * errorSlot, const QString & ip = QString(), int port = -1)
    {
        QObject::connect(this, SIGNAL(finished()), this, SLOT(deleteLater()));
        QObject::connect(this, SIGNAL(error(QString)), err_receiver, errorSlot);
        QObject::connect(sock, SIGNAL(error(QString)), err_receiver, errorSlot);
        QObject::connect(sock, SIGNAL(packetReady(char*,int)), packet_receiver, packetSlot);

        if (sock -> binding(ip, port)) {
            sock -> enablePromMode();
//            sock -> enableIncludeHeader(true);
//            sock -> enableBlocking(false);
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
