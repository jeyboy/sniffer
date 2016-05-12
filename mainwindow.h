#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qpushbutton.h>
#include <qlabel.h>
#include <qcombobox.h>
#include <qtoolbar.h>

#include "modules/sniffer.h"

namespace Ui { class MainWindow; }

class QListWidget;
class QListWidgetItem;

class MainWindow : public QMainWindow {
    Q_OBJECT

    QHash<QString, QPushButton *> proto_btns;
    QHash<QString, bool> proto_filters;
    QHash<QString, bool> direction_filters;
    QHash<QString, bool> src_ips;
    QHash<QString, bool> dst_ips;

    void newProtoBtn();
    QPushButton * registerProtoBtn(const QString & proto, QAction * before_action = 0);
    void iterProtoBtnText(QPushButton * btn);
    void iterDirectBtnText(const QString & direct);
    void setInfo();
    void procFilter();
    void initAddProtoPanel();

    void createTab(int row);
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
public slots:
    void packetInfoReceived(QHash<QString, QString> attrs);
    void errorReceived(QString message);

private slots:
    void srcIpsFlagClicked(bool);
    void dstIpsFlagClicked(bool);

    void srcItemDoubleClicked(QListWidgetItem *);
    void dstItemDoubleClicked(QListWidgetItem *);

    void protoBtnTriggered(bool);
    void newProtoBtnTriggered();

    void protoAddBtnTriggered();
    void protoCancelBtnTriggered();

    void on_table_cellDoubleClicked(int row, int column);

    void on_filterBtn_clicked();

    void on_cut_opt_clicked(bool checked);
    void cut_proto_opt_clicked(bool checked);

    void on_incomeBtn_clicked(bool checked);

    void on_outcomeBtn_clicked(bool checked);

    void on_procBtn_clicked(bool checked);

    void on_resolveSenderNameBtn_clicked(bool checked);

    void on_resolveReceiverNameBtn_clicked(bool checked);

    void on_resolveAppBtn_clicked(bool checked);

    void on_scrollEndBtn_clicked(bool checked);

    void on_table_customContextMenuRequested(const QPoint & pos);

    void sourceToFilterList();
    void sourceFromFilterList();

    void destToFilterList();
    void destFromFilterList();

private:
    Ui::MainWindow * ui;
    Sniffer * sniffer;
    QToolBar * bar;
    QLabel * filter_info;
    QComboBox * protos_list;

    QListWidget * srcList, * dstList;
    QAction * new_proto_panel, * new_proto_panel_btn;
    bool ignore_invalid, ignore_other_proto, filter_in_proc, scroll_to_end, block_src_ips, block_dst_ips;
    int protocol_col, payload_col, src_col, dst_col, direct_col, app_col;
    QString filter;
};

#endif // MAINWINDOW_H
