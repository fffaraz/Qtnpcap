#include <QApplication>
#include <QDebug>

#include "mainwindow.h"
#include "npcap.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    //MainWindow w;
    //w.show();

    Npcap npcap;
    npcap.print();

    printf("Enter the interface number (1-%d): ", npcap.devs.size());
    int inum;
    scanf("%d", &inum);
    inum--;

    npcap.open(inum);

    return a.exec();
}
