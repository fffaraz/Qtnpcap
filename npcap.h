#ifndef NPCAP_H
#define NPCAP_H

#include <QObject>
#include <QThread>
#include <QVector>
#include <QDebug>

#include <pcap.h>
#include <Packet.h>

class Npcap : public QThread
{
    Q_OBJECT

public:
    explicit Npcap(QObject *parent = nullptr);
    virtual ~Npcap();
    void print();

    int inum = -1;
    QVector<pcap_if_t *> devs; // list of devices

private:
    pcap_if_t *alldevs  = nullptr;
    pcap_t    *adhandle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    virtual void run() override;

    static void packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data);
    void process_packet(pcpp::Packet &parsedPacket, const pcap_pkthdr *header, const u_char *pkt_data);

    static std::string protocolTypeToString(pcpp::ProtocolType protocolType);
    static std::string ipv4ToString(int ip);
    static std::string timevalToString(timeval ts);
};

#endif // NPCAP_H
