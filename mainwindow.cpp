#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(&npcap, &Npcap::newPacket, this, &MainWindow::npcap_newPacket, Qt::QueuedConnection);
    npcap.print();
    for(int i = 0; i < npcap.devs.size(); ++i)
    {
        QString description(npcap.devs[i]->description);
        if(description.contains("Connection")) ui->cmbIfs->addItem(description, i);
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::npcap_newPacket(QDateTime timestamp, QString proto, QString saddr, u_short sport, QString daddr, u_short dport, bpf_u_int32 len)
{

}

void MainWindow::on_btnStart_clicked()
{
    ui->grpDevs->setEnabled(false);
    npcap.start();
}

void MainWindow::on_cmbIfs_currentIndexChanged(int index)
{
    npcap.inum = ui->cmbIfs->itemData(index).toInt();
}
