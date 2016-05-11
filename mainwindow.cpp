#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <qmessagebox.h>

MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui -> setupUi(this);

    QStringList headers = QStringList() << "Timestamp" << "Direction" << "Protocol" << "Source IP" << "Destination IP" << "Source Name" << "Destination Name" << "Length" << "Payload";

    ui -> table -> setColumnCount(headers.length());
    ui -> table -> setHorizontalHeaderLabels(headers);
    ui -> table -> setSortingEnabled(true);

    ui -> table -> setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui -> table -> setSelectionBehavior(QAbstractItemView::SelectRows);

    sniffer = new Sniffer(this);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::packetInfoReceived(QHash<QString, QString> attrs) {
    setWindowTitle(sniffer -> stat());

    int row = ui -> table -> rowCount();
    ui -> table -> insertRow(row);

    QTableWidgetItem * timew = new QTableWidgetItem(attrs[SOCK_ATTR_TIMESTAMP]);
    ui -> table -> setItem(row, 0, timew);

    QTableWidgetItem * directw = new QTableWidgetItem(attrs[SOCK_ATTR_DIRECTION]);
    ui -> table -> setItem(row, 1, directw);

    QTableWidgetItem * protow = new QTableWidgetItem(attrs[SOCK_ATTR_PROTOCOL]);
    ui -> table -> setItem(row, 2, protow);

    QTableWidgetItem * sourceipw = new QTableWidgetItem(attrs[SOCK_ATTR_SRC_IP]);
    ui -> table -> setItem(row, 3, sourceipw);

    QTableWidgetItem * destipw = new QTableWidgetItem(attrs[SOCK_ATTR_DEST_IP]);
    ui -> table -> setItem(row, 4, destipw);

    QTableWidgetItem * sourcew = new QTableWidgetItem(attrs[SOCK_ATTR_SRC]);
    ui -> table -> setItem(row, 5, sourcew);

    QTableWidgetItem * destw = new QTableWidgetItem(attrs[SOCK_ATTR_DEST]);
    ui -> table -> setItem(row, 6, destw);

    QTableWidgetItem * lengw = new QTableWidgetItem(attrs[SOCK_ATTR_LENGTH]);
    ui -> table -> setItem(row, 7, lengw);

    QTableWidgetItem * payw = new QTableWidgetItem(attrs[SOCK_ATTR_PAYLOAD]);
    ui -> table -> setItem(row, 8, payw);
}
void MainWindow::errorReceived(QString message) {
    int row = ui -> table -> rowCount();
    ui -> table -> insertRow(row);

    QTableWidgetItem * timew = new QTableWidgetItem(TIMESTAMP_STR);
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

void MainWindow::on_table_cellDoubleClicked(int row, int /*column*/) {
    QString payload = ui -> table -> item(row, ui -> table -> columnCount() - 1) -> text();
    QMessageBox::information(this, "Payload", payload);
}

void MainWindow::on_actionSender_triggered(bool checked) {
    sniffer -> enableSenderIpResolving(checked);
}

void MainWindow::on_actionReceiver_triggered(bool checked) {
    sniffer -> enableReceiverIpResolving(checked);
}
