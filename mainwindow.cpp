#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <qmessagebox.h>

MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(new Ui::MainWindow), ignore_invalid(false), filter(QString()) {
    ui -> setupUi(this);

    bar = new QToolBar(ui -> panel);
    ui -> panel -> layout() -> addWidget(bar);

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

void MainWindow::registerProtoBtn(const QString & proto) {
    QPushButton * btn = proto_btns.value(proto, 0);

    if (!btn) {
        btn = new QPushButton(bar);
        proto_btns.insert(proto, btn);
        QAction * act = bar -> addWidget(btn);
        act -> setProperty("proto", proto);
        connect(act, SIGNAL(triggered(bool)), this, SLOT(protoBtnTriggered(bool)));
    }

    btn -> setText(QStringLiteral("%1 (%2)").arg(proto).arg(sniffer -> protoStat(proto)));
}

void MainWindow::packetInfoReceived(QHash<QString, QString> attrs) {
    setWindowTitle(sniffer -> stat());

    bool hidden = false;

    if (!filter.isEmpty())
        hidden = !attrs[SOCK_ATTR_PAYLOAD].contains(filter, Qt::CaseInsensitive);

    if (!hidden && proto_filters.value(attrs[SOCK_ATTR_PROTOCOL], false))
        hidden = true;

    if (ignore_invalid && hidden) return;

    int row = ui -> table -> rowCount();
    ui -> table -> insertRow(row);

    QTableWidgetItem * timew = new QTableWidgetItem(attrs[SOCK_ATTR_TIMESTAMP]);
    ui -> table -> setItem(row, 0, timew);

    QTableWidgetItem * directw = new QTableWidgetItem(attrs[SOCK_ATTR_DIRECTION]);
    ui -> table -> setItem(row, 1, directw);

    QTableWidgetItem * protow = new QTableWidgetItem(attrs[SOCK_ATTR_PROTOCOL]);
    ui -> table -> setItem(row, (protocol_col = 2), protow);

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
    ui -> table -> setItem(row, (payload_col = 8), payw);

    registerProtoBtn(attrs[SOCK_ATTR_PROTOCOL]);

    ui -> table -> setRowHidden(row, hidden);
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

void MainWindow::protoBtnTriggered(bool on) {
    QAction * act = (QAction *)sender();
    QString proto = act -> property("proto").toString();
    proto_filters[proto] = on;
    on_filterBtn_clicked();
}

void MainWindow::on_actionStart_triggered() {
    sniffer -> start(SLOT(packetInfoReceived(QHash<QString,QString>)), SLOT(errorReceived(QString)));
}

void MainWindow::on_actionStop_triggered() {
    sniffer -> stop();
}

void MainWindow::on_table_cellDoubleClicked(int row, int /*column*/) {
    QString payload = ui -> table -> item(row, payload_col) -> text();
    QMessageBox::information(this, "Payload", payload);
}

void MainWindow::on_actionSender_triggered(bool checked) {
    sniffer -> enableSenderIpResolving(checked);
}

void MainWindow::on_actionReceiver_triggered(bool checked) {
    sniffer -> enableReceiverIpResolving(checked);
}

void MainWindow::on_filterBtn_clicked() {
    filter = ui -> text_filter -> text();

    bool payload_filter_on = !filter.isEmpty();
    bool proto_filter_on = !proto_filters.isEmpty();
    int payload_column = ui -> table -> columnCount() - 1;

    for(int row = 0; row < ui -> table -> rowCount(); row++) {
        bool hidden = payload_filter_on && !ui -> table -> item(row, payload_column) -> text().contains(filter, Qt::CaseInsensitive);

        if (!hidden && proto_filter_on) {
            QString proto = ui -> table -> item(row, protocol_col) -> text();
            hidden = proto_filters.value(proto, false);
        }

        ui -> table -> setRowHidden(row, hidden);
    }
}

void MainWindow::on_cut_opt_clicked(bool checked) {
    ignore_invalid = checked;
}
