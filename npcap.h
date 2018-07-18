#ifndef NPCAP_H
#define NPCAP_H

#include <QObject>
#include <QVector>
#include <QDebug>

#include <pcap.h>
#include <Packet.h>

class Npcap : public QObject
{
    Q_OBJECT

public:
    explicit Npcap(QObject *parent = nullptr);
    virtual ~Npcap();

    void print();
    void open(int inum);

    QVector<pcap_if_t *> devs; // list of devices

private:
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    static void packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data);
    void process_packet(pcpp::Packet &parsedPacket, const pcap_pkthdr *header, const u_char *pkt_data);

    static std::string protocolTypeToString(pcpp::ProtocolType protocolType);
    static std::string ipv4ToString(int ip);
    static std::string timevalToString(timeval ts);
};

#endif // NPCAP_H
