#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui -> setupUi(this);

    sniffer = new Sniffer(this, SLOT(packetInfoReceived(QHash<QString,QString>)), SLOT(errorReceived(QString)));
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::packetInfoReceived(QHash<QString, QString> attrs) {
    QString stat = QStringLiteral("income: %1 ||| outcome: %2").arg(attrs.take(QStringLiteral("-I")), attrs.take(QStringLiteral("-O")));
    setWindowTitle(stat);

//    QString html = QString("<ul>");
//    for(QHash<QString, QString>::ConstIterator it = attrs.cbegin(); it != attrs.cend(); it++)
//        html += QStringLiteral("<li>") + it.key() + QStringLiteral(" : ") + it.value() + QStringLiteral("</li>");

//    html += QStringLiteral("</ul><br>");

//    ui -> log -> appendHtml(html);
}
void MainWindow::errorReceived(QString message) {
    qDebug() << "ERR:" << message;
    QString text = QString("<span style='color: red'>%1</span>").arg(message);
    ui -> log -> appendHtml(text);
}
