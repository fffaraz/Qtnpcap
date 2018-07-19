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

private:
    Ui::MainWindow *ui;
    Npcap npcap;
};

#endif // MAINWINDOW_H
