#ifndef NPCAP_H
#define NPCAP_H

#include <QObject>
#include <QVector>
#include <QDebug>

#include <pcap.h>

class Npcap : public QObject
{
    Q_OBJECT
public:
    explicit Npcap(QObject *parent = nullptr);
    virtual ~Npcap();

    void print();
    void open(int inum);

    QVector<pcap_if_t *> devs;

private:
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif // NPCAP_H
