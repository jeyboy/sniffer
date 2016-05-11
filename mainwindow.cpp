#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <qmessagebox.h>

MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(new Ui::MainWindow), ignore_invalid(false), filter(QString()) {
    ui -> setupUi(this);

    bar = new QToolBar(ui -> panel);
    ui -> panel -> layout() -> addWidget(bar);

    filter_info = new QLabel("No filters");
    ui -> statusBar -> addWidget(filter_info);

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
        btn -> setCheckable(true);
        btn -> setChecked(true);
        btn -> setProperty("amount", 0);
        proto_btns.insert(proto, btn);
        bar -> addWidget(btn);
        btn -> setProperty("proto", proto);
        connect(btn, SIGNAL(clicked(bool)), this, SLOT(protoBtnTriggered(bool)));
    }


    int val = btn -> property("amount").toInt() + 1;
    btn -> setText(QStringLiteral("%1 (%2)").arg(proto).arg(/*sniffer -> protoStat(proto)*/val));
    btn -> setProperty("amount", val);
}

void MainWindow::setInfo() {
    QString output_text;

    if (!filter.isEmpty())
        output_text = "Filter by payload; ";

    QString proto_state;
    for(QHash<QString, bool>::Iterator it = proto_filters.begin(); it != proto_filters.end(); it++)
        if (!it.value())
            proto_state += " " + it.key();

    if (!proto_state.isEmpty())
        output_text += "Filter by protocols: " + proto_state;

    filter_info -> setText(output_text);
}

void MainWindow::packetInfoReceived(QHash<QString, QString> attrs) {
    setWindowTitle(sniffer -> stat());

    bool hidden = false;

    if (!filter.isEmpty())
        hidden = !attrs[SOCK_ATTR_PAYLOAD].contains(filter, Qt::CaseInsensitive);

    if (!hidden && !proto_filters.value(attrs[SOCK_ATTR_PROTOCOL], true))
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
    QPushButton * btn = (QPushButton *)sender();
    QString proto = btn -> property("proto").toString();
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

    setInfo();

    bool payload_filter_on = !filter.isEmpty();
    bool proto_filter_on = !proto_filters.isEmpty();
    int payload_column = ui -> table -> columnCount() - 1;
    int rows_limit = ui -> table -> rowCount();

    for(int row = 0; row < rows_limit; row++) {
        bool hidden = payload_filter_on && !ui -> table -> item(row, payload_column) -> text().contains(filter, Qt::CaseInsensitive);

        if (!hidden && proto_filter_on) {
            QString proto = ui -> table -> item(row, protocol_col) -> text();
            hidden = !proto_filters.value(proto, true);
        }

        ui -> table -> setRowHidden(row, hidden);
    }
}

void MainWindow::on_cut_opt_clicked(bool checked) {
    ignore_invalid = checked;
}
