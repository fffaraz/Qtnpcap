#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtAlgorithms>
#include <algorithm>

#include <QMainWindow>
#include <QTimer>
#include <QClipboard>
#include <QList>
#include <QPair>
#include <QMutex>

#include "npcap.h"

namespace Ui {
class MainWindow;
}

struct Mykey
{
    quint64 ts;
    QString proto;
    QString saddr;
    quint16 sport;
    QString daddr;
    quint16 dport;
    QString toString() const
    {
        const char separator[] = " | ";
        QString r;
        r.append(QDateTime::fromSecsSinceEpoch(ts).toString("yyyy-MM-dd HH"));
        r.append(separator);
        r.append(proto.leftJustified(4));
        r.append(separator);
        r.append(saddr);
        r.append(separator);
        r.append(QString::number(sport).rightJustified(5));
        r.append(separator);
        r.append(daddr);
        r.append(separator);
        r.append(QString::number(dport).rightJustified(5));
        return r;
    }
};

inline bool operator==(const Mykey &a, const Mykey &b)
{
    return a.ts == b.ts && a.proto == b.proto && a.saddr == b.saddr && a.sport == b.sport && a.daddr == b.daddr && a.dport == b.dport;
}

inline uint qHash(const Mykey &key, uint seed)
{
    uint r = 0;
    r ^= qHash(key.ts, seed);
    r ^= qHash(key.proto, seed);
    r ^= qHash(key.saddr, seed);
    r ^= qHash(key.sport, seed);
    r ^= qHash(key.daddr, seed);
    r ^= qHash(key.dport, seed);
    return r;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void timer_timeout();
    void npcap_newPacket(QDateTime timestamp, QString proto, QString saddr, u_short sport, QString daddr, u_short dport, bpf_u_int32 len);
    void on_btnStart_clicked();
    void on_cmbIfs_currentIndexChanged(int index);
    void on_btnClipboard_clicked();
    void on_btnRefresh_clicked();

private:
    Ui::MainWindow *ui;
    QMutex m_mutex;
    QTimer m_timer;
    QString m_string;
    Npcap npcap;
    QHash<Mykey, quint64> m_map;

    bool isSame(QString addr);
};

#endif // MAINWINDOW_H
