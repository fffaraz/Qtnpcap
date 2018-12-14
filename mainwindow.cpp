#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QFont font("Monospace");
    font.setStyleHint(QFont::TypeWriter); // QFont::Monospace
    ui->plainTextEdit->setFont(font);

    connect(&m_timer, &QTimer::timeout, this, &MainWindow::timer_timeout);
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

struct QPairSecondComparer
{
    template<typename T1, typename T2>
    bool operator()(const QPair<T1,T2> & a, const QPair<T1,T2> & b) const
    {
        return a.second > b.second;
    }
};

void MainWindow::timer_timeout()
{
    //on_btnRefresh_clicked();
}

void MainWindow::npcap_newPacket(QDateTime timestamp, QString proto, QString saddr, u_short sport, QString daddr, u_short dport, bpf_u_int32 len)
{
    Mykey key;
    int d = 3600 * 24;
    key.ts = timestamp.toSecsSinceEpoch();
    key.ts = key.ts - (key.ts % d);
    key.proto = proto;

    key.saddr = saddr;

    if(isSame(saddr) && sport >= 49152) key.sport = 0;
    else key.sport = sport;

    key.daddr = daddr;

    if(isSame(daddr) && dport >= 49152) key.dport = 0;
    else key.dport = dport;

    // https://en.wikipedia.org/wiki/Multicast_address
    if(daddr.startsWith("239.") || daddr.startsWith("224.  0.")) key.sport = 0;

    m_mutex.lock();
    m_map[key] = m_map[key] + len;
    // TODO: packet count map
    // m_map2[key] = m_map2[key] + 1;
    m_mutex.unlock();
}

void MainWindow::on_btnStart_clicked()
{
    ui->grpDevs->setEnabled(false);
    npcap.start();
    m_timer.start(5000);
}

void MainWindow::on_cmbIfs_currentIndexChanged(int index)
{
    npcap.inum = ui->cmbIfs->itemData(index).toInt();
}

void MainWindow::on_btnClipboard_clicked()
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->clear();
    clipboard->setText(m_string);
}

void MainWindow::on_btnRefresh_clicked()
{
    QList<QPair<QString, quint64>> list;
    m_mutex.lock();
    {
        QHashIterator<Mykey, quint64> i(m_map);
        while(i.hasNext())
        {
            i.next();
            if(i.value() > 0) list.append(qMakePair(i.key().toString(), i.value()));
        }
    }
    m_mutex.unlock();

    std::sort(list.begin(), list.end(), QPairSecondComparer());

    m_string.clear();
    m_string.append(Mykey::headers());
    for(int i = 0; i < list.size(); ++i) m_string.append(list[i].first + " | " + QString::number(list[i].second / 1024).rightJustified(10) + "\n");

    ui->plainTextEdit->clear();
    ui->plainTextEdit->appendPlainText(m_string);
    ui->plainTextEdit->moveCursor(QTextCursor::Start);
    ui->plainTextEdit->ensureCursorVisible();
}

bool MainWindow::isSame(QString addr)
{
    addr = addr.remove(' ');
    foreach(const QString &addr2, npcap.addrs.values(npcap.inum)) if(addr.compare(addr2) == 0) return true;
    return false;
}
