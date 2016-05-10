#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui -> setupUi(this);

    ui -> table -> setColumnCount(5);
    ui -> table -> setHorizontalHeaderLabels(QStringList() << "Timestamp" << "Direction" << "Protocol" << "Source" << "Destination");

    sniffer = new Sniffer(this);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::packetInfoReceived(QHash<QString, QString> attrs) {
    QString stat = QStringLiteral("income: %1 ||| outcome: %2").arg(attrs.take(QStringLiteral("-I")), attrs.take(QStringLiteral("-O")));
    setWindowTitle(stat);

    int row = ui -> table -> rowCount();
    ui -> table -> insertRow(row);

    QTableWidgetItem * timew = new QTableWidgetItem(attrs["Timestamp"]);
    timew -> setData(-1, attrs["Payload"]);
    ui -> table -> setItem(row, 0, timew);

    QTableWidgetItem * directw = new QTableWidgetItem(attrs["Direction"]);
    ui -> table -> setItem(row, 1, directw);

    QTableWidgetItem * protow = new QTableWidgetItem(attrs["Protocol"]);
    ui -> table -> setItem(row, 2, protow);

    QString src = attrs["Source IP"];
    if (src != attrs["Source"])
        src = QStringLiteral("%1 (%2)").arg(src, attrs["Source"]);

    QTableWidgetItem * sourcew = new QTableWidgetItem(src);
    ui -> table -> setItem(row, 3, sourcew);


    QString dst = attrs["Destination IP"];
    if (dst != attrs["Destination"])
        dst = QStringLiteral("%1 (%2)").arg(dst, attrs["Destination"]);

    QTableWidgetItem * destw = new QTableWidgetItem(dst);
    ui -> table -> setItem(row, 4, destw);
}
void MainWindow::errorReceived(QString message) {
    int row = ui -> table -> rowCount();
    ui -> table -> insertRow(row);

    QTableWidgetItem * timew = new QTableWidgetItem(QDateTime::currentDateTime().toString());
    timew -> setBackgroundColor(Qt::red);
    ui -> table -> setItem(row, 0, timew);

    QTableWidgetItem * directw = new QTableWidgetItem(message);
    timew -> setBackgroundColor(Qt::red);
    ui -> table -> setItem(row, 1, directw);
}

void MainWindow::on_actionStart_triggered() {
    sniffer -> start(SLOT(packetInfoReceived(QHash<QString,QString>)), SLOT(errorReceived(QString)));
}

void MainWindow::on_actionStop_triggered() {
    sniffer -> stop();
}
