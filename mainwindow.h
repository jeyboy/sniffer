#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qpushbutton.h>
#include <qlabel.h>
#include <qcombobox.h>

#include "modules/sniffer.h"

namespace Ui { class MainWindow; }

class MainWindow : public QMainWindow {
    Q_OBJECT

    QHash<QString, QPushButton *> proto_btns;
    QHash<QString, bool> proto_filters;

    void newProtoBtn();
    QPushButton * registerProtoBtn(const QString & proto, QAction * before_action = 0);
    void iterProtoBtnText(QPushButton * btn);
    void setInfo();
    void procFilter();
    void initAddProtoPanel();
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
public slots:
    void packetInfoReceived(QHash<QString, QString> attrs);
    void errorReceived(QString message);

private slots:
    void protoBtnTriggered(bool);
    void newProtoBtnTriggered();

    void protoAddBtnTriggered();
    void protoCancelBtnTriggered();

    void on_actionStart_triggered();

    void on_actionStop_triggered();

    void on_table_cellDoubleClicked(int row, int column);

    void on_actionSender_triggered(bool checked);

    void on_actionReceiver_triggered(bool checked);

    void on_filterBtn_clicked();

    void on_cut_opt_clicked(bool checked);
    void cut_proto_opt_clicked(bool checked);

private:
    Ui::MainWindow * ui;
    Sniffer * sniffer;
    QToolBar * bar;
    QLabel * filter_info;
    QComboBox * protos_list;

    QAction * new_proto_panel, * new_proto_panel_btn;
    bool ignore_invalid, ignore_other_proto, filter_in_proc;
    int protocol_col, payload_col, src_col, dst_col;
    QString filter;
};

#endif // MAINWINDOW_H
