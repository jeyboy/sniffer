#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui -> setupUi(this);

    sniffer = new Sniffer(this);

    connect(sniffer, SIGNAL(packetReceived(QHash<QString,QString>)), this, SLOT(packetInfoReceived(QHash<QString,QString>)));
    connect(sniffer, SIGNAL(error(QString)), this, SLOT(errorReceived(QString)));
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::packetInfoReceived(const QHash<QString, QString> & attrs) {
    QString html = QString("<ul>");
    for(QHash<QString, QString>::ConstIterator it = attrs.cbegin(); it != attrs.cend(); it++)
        html += QStringLiteral("<li>") + it.key() + QStringLiteral(" : ") + it.value() + QStringLiteral("</li>");

    html += QStringLiteral("</ul><br>");

//    QString text = QString("<span style='color: green'>%1 ::: %2 ::: %3 ::: %4 ::: %5</span>").arg(ver, protocol, from, to, body);
    ui -> log -> appendHtml(html);
}
void MainWindow::errorReceived(QString message) {
    qDebug() << "ERR:" << message;
    QString text = QString("<span style='color: red'>%1</span>").arg(message);
    ui -> log -> appendHtml(text);
}
