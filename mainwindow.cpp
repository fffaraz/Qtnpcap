#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    npcap.print();

    printf("Enter the interface number (1-%d): ", npcap.devs.size());
    int inum;
    scanf("%d", &inum);
    npcap.inum = inum - 1;

    npcap.start();
}

MainWindow::~MainWindow()
{
    delete ui;
}
