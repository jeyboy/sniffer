#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qpushbutton.h>

#include "modules/sniffer.h"

namespace Ui { class MainWindow; }

class MainWindow : public QMainWindow {
    Q_OBJECT

    QHash<QString, QPushButton *> proto_btns;
    QHash<QString, bool> proto_filters;

    void registerProtoBtn(const QString & proto);
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
public slots:
    void packetInfoReceived(QHash<QString, QString> attrs);
    void errorReceived(QString message);

private slots:
    void protoBtnTriggered(bool);

    void on_actionStart_triggered();

    void on_actionStop_triggered();

    void on_table_cellDoubleClicked(int row, int column);

    void on_actionSender_triggered(bool checked);

    void on_actionReceiver_triggered(bool checked);

    void on_filterBtn_clicked();

private:
    Ui::MainWindow * ui;
    Sniffer * sniffer;
    QToolBar * bar;

    int protocol_col, payload_col;
    QString filter;
};

#endif // MAINWINDOW_H
