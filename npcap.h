#ifndef NPCAP_H
#define NPCAP_H

#include <QObject>
#include <QThread>
#include <QVector>
#include <QDateTime>
#include <QDebug>

#include <pcap.h>
#include <Packet.h>
#include <IPv4Layer.h>

class Npcap : public QThread
{
    Q_OBJECT

public:
    explicit Npcap(QObject *parent = nullptr);
    virtual ~Npcap();
    void print();

    int inum = -1;
    QVector<pcap_if_t *> devs; // list of devices
    QMultiMap<int, QString> addrs;  // list of addresses

signals:
    void newPacket(QDateTime timestamp, QString proto, QString saddr, u_short sport, QString daddr, u_short dport, bpf_u_int32 len);

private:
    pcap_if_t *alldevs  = nullptr;
    pcap_t    *adhandle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    virtual void run() override;

    static void packet_handler(u_char *param,       const pcap_pkthdr *header, const u_char *pkt_data);
    void process_packet(pcpp::Packet &parsedPacket, const pcap_pkthdr *header, const u_char *pkt_data);
    void process_ipv4  (pcpp::IPv4Layer *ipv4Layer, const pcap_pkthdr *header, const u_char *pkt_data);

    static QString protocolTypeToString(pcpp::ProtocolType protocolType);
    static std::string ipv4ToString(int ip);
    static std::string timevalToString(timeval ts);
};

#endif // NPCAP_H
