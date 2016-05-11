#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <qmessagebox.h>

MainWindow::MainWindow(QWidget * parent) : QMainWindow(parent), ui(new Ui::MainWindow), ignore_invalid(false), ignore_other_proto(false),
    filter_in_proc(false), filter(QString()), src_col(5), dst_col(6)
{
    ui -> setupUi(this);

    setWindowTitle("Sniffer");

    bar = new QToolBar(ui -> panel);
    ui -> panel -> layout() -> addWidget(bar);

    filter_info = new QLabel("No filters");
    ui -> statusBar -> addWidget(filter_info);

    initAddProtoPanel();

    QStringList headers = QStringList() << "Timestamp" << "Direction" << "Protocol" << "Source IP" << "Destination IP" << "Source Name" << "Destination Name" << "Length" << "Payload";

    ui -> table -> setColumnCount(headers.length());
    ui -> table -> setHorizontalHeaderLabels(headers);
    ui -> table -> setSortingEnabled(true);

    ui -> table -> setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui -> table -> setSelectionBehavior(QAbstractItemView::SelectRows);

    sniffer = new Sniffer(this);

    on_actionSender_triggered(false);
    on_actionReceiver_triggered(false);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::initAddProtoPanel() {
    newProtoBtn();

    QWidget * add_proto_panel = new QWidget();

    protos_list = new QComboBox(add_proto_panel);

    QStringList protos;
    for(int i = 0; i <= 140; i++)
        protos << SocketUtils::protocolToStr(i);

    protos_list -> insertItems(0, protos);

    QWidget * buttons = new QWidget(add_proto_panel);
    QVBoxLayout * vl = new QVBoxLayout(buttons);

    QPushButton * okBtn = new QPushButton("Add", buttons);
    vl -> addWidget(okBtn);
    connect(okBtn, SIGNAL(clicked()), this, SLOT(protoAddBtnTriggered()));

    QPushButton * cancelBtn = new QPushButton("Cancel", buttons);
    vl -> addWidget(cancelBtn);
    connect(cancelBtn, SIGNAL(clicked()), this, SLOT(protoCancelBtnTriggered()));

    vl -> setMargin(0); vl -> setSpacing(0);

    QHBoxLayout * hl = new QHBoxLayout(add_proto_panel);
    hl -> addWidget(protos_list, 1);
    hl -> addWidget(buttons, 0);
    hl -> setMargin(0); hl -> setSpacing(0);

    (new_proto_panel = bar -> addWidget(add_proto_panel)) -> setVisible(false);
    bar -> addSeparator();
}

void MainWindow::newProtoBtn() {
    QWidget * new_proto_btn_panel = new QWidget(bar);
    QVBoxLayout * vl = new QVBoxLayout(new_proto_btn_panel);

    QCheckBox * ignore_other_proto_check = new QCheckBox("Ignore other proto");
    ignore_other_proto_check -> setMinimumHeight(24);
    vl -> addWidget(ignore_other_proto_check);
    connect(ignore_other_proto_check, SIGNAL(clicked(bool)), this, SLOT(cut_proto_opt_clicked(bool)));

    QPushButton * btn = new QPushButton("Add proto filter", bar);
    btn -> setMinimumHeight(24);
    vl -> addWidget(btn);
    connect(btn, SIGNAL(clicked()), this, SLOT(newProtoBtnTriggered()));

    new_proto_panel_btn = bar -> addWidget(new_proto_btn_panel);
}

QPushButton * MainWindow::registerProtoBtn(const QString & proto, QAction * before_action) {
    if (proto.isEmpty()) return 0;

    QPushButton * btn = proto_btns.value(proto, 0);

    if (!btn) {
        btn = new QPushButton(proto, bar);
        btn -> setCheckable(true);
        btn -> setChecked(true);
        btn -> setProperty("amount", 0);
        btn -> setMinimumHeight(44);
        proto_btns.insert(proto, btn);
        if (before_action)
            bar -> insertWidget(before_action, btn);
        else
            bar -> addWidget(btn);
        btn -> setProperty("proto", proto);
        connect(btn, SIGNAL(clicked(bool)), this, SLOT(protoBtnTriggered(bool)));
    }

    return btn;
}

void MainWindow::iterProtoBtnText(QPushButton * btn) {
    QString proto = btn -> property("proto").toString();
    int val = btn -> property("amount").toInt() + 1;
    btn -> setText(QStringLiteral("%1\n(%2)").arg(proto).arg(/*sniffer -> protoStat(proto)*/val));
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

    if (ignore_other_proto && !proto_btns.contains(attrs[SOCK_ATTR_PROTOCOL]))
        return;

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
    ui -> table -> setItem(row, (src_col = 5), sourcew);

    QTableWidgetItem * destw = new QTableWidgetItem(attrs[SOCK_ATTR_DEST]);
    ui -> table -> setItem(row, (dst_col = 6), destw);

    QTableWidgetItem * lengw = new QTableWidgetItem(attrs[SOCK_ATTR_LENGTH]);
    ui -> table -> setItem(row, 7, lengw);

    QTableWidgetItem * payw = new QTableWidgetItem(attrs[SOCK_ATTR_PAYLOAD]);
    ui -> table -> setItem(row, (payload_col = 8), payw);

    QPushButton * btn = registerProtoBtn(attrs[SOCK_ATTR_PROTOCOL]);
    iterProtoBtnText(btn);

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
    if (on)
        proto_filters.remove(proto);
    else
        proto_filters[proto] = false;

    on_filterBtn_clicked();
}

void MainWindow::newProtoBtnTriggered() {
    new_proto_panel -> setVisible(true);
    new_proto_panel_btn -> setVisible(false);
}

void MainWindow::protoAddBtnTriggered() {
    registerProtoBtn(protos_list -> currentText());
    protoCancelBtnTriggered();
}

void MainWindow::protoCancelBtnTriggered() {
    new_proto_panel -> setVisible(false);
    new_proto_panel_btn -> setVisible(true);
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
    ui -> table -> setColumnHidden(src_col, !checked);
}

void MainWindow::on_actionReceiver_triggered(bool checked) {
    sniffer -> enableReceiverIpResolving(checked);
    ui -> table -> setColumnHidden(dst_col, !checked);
}

void MainWindow::procFilter() {
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

        if (hidden)
            QMetaObject::invokeMethod(
                ui -> table, "hideRow", Qt::AutoConnection, Q_ARG(int, row)
            );
        else
            QMetaObject::invokeMethod(
                ui -> table, "showRow", Qt::AutoConnection, Q_ARG(int, row)
            );
    }

    filter_in_proc = false;
}

void MainWindow::on_filterBtn_clicked() {
    filter = ui -> text_filter -> text();

    setInfo();

    if (!filter_in_proc) {
        filter_in_proc = true;
        QtConcurrent::run(this, &MainWindow::procFilter);
    }
}

void MainWindow::on_cut_opt_clicked(bool checked) {
    ignore_invalid = checked;
}

void MainWindow::cut_proto_opt_clicked(bool checked) {
    ignore_other_proto = checked;
}
