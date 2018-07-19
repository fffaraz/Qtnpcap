#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "npcap.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void npcap_newPacket(QDateTime timestamp, QString proto, QString saddr, u_short sport, QString daddr, u_short dport, bpf_u_int32 len);
    void on_btnStart_clicked();
    void on_cmbIfs_currentIndexChanged(int index);

private:
    Ui::MainWindow *ui;
    Npcap npcap;
};

#endif // MAINWINDOW_H
