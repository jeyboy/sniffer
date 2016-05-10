#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "modules/sniffer.h"

namespace Ui { class MainWindow; }

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
public slots:
    void packetInfoReceived(QHash<QString, QString> attrs);
    void errorReceived(QString message);

private slots:
    void on_actionStart_triggered();

    void on_actionStop_triggered();

private:
    Ui::MainWindow * ui;
    Sniffer * sniffer;
};

#endif // MAINWINDOW_H
