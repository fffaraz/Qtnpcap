#include "npcap.h"

#include <EthLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

void Npcap::process_packet(pcpp::Packet &parsedPacket, const pcap_pkthdr *header, const u_char *pkt_data)
{
    // get the Ethernet layer
    pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if(ethernetLayer == NULL)
    {
        printf("Something went wrong, couldn't find Ethernet layer\n");
        return;
    }

    pcpp::Layer* nextLayer = ethernetLayer->getNextLayer();

    if     (nextLayer->getProtocol() == pcpp::IPv4) process_ipv4((pcpp::IPv4Layer*)nextLayer, header, pkt_data);
    else if(nextLayer->getProtocol() == pcpp::ARP)  process_arp ((pcpp::ArpLayer *)nextLayer, header, pkt_data);
    else if(nextLayer->getProtocol() == pcpp::IPv6) qDebug() << "TODO: IPv6";
    else
    {
        printf("\n");
        printf("%s    %s  ->  %s \n", timevalToString(header->ts).c_str(), ethernetLayer->getSourceMac().toString().c_str(), ethernetLayer->getDestMac().toString().c_str());
        printf("%s    len: %d     HeaderLen: %d    PayloadSize: %d \n", nextLayer->toString().c_str(), (int)header->len, (int)nextLayer->getHeaderLen(), (int)nextLayer->getLayerPayloadSize());
        QByteArray ba((const char *)nextLayer->getData(), (int)nextLayer->getDataLen());
        qDebug() << ba.size() << ba;
    }
}

void Npcap::process_ipv4(pcpp::IPv4Layer *ipv4Layer, const pcap_pkthdr *header, const u_char *pkt_data)
{
    Q_UNUSED(pkt_data);

    std::string saddr = ipv4ToString(ipv4Layer->getSrcIpAddress().toInt());
    std::string daddr = ipv4ToString(ipv4Layer->getDstIpAddress().toInt());
    u_short     sport = 0;
    u_short     dport = 0;

    // get the Transport layer
    pcpp::Layer* transportLayer  = ipv4Layer->getNextLayer();
    pcpp::ProtocolType protoType = transportLayer->getProtocol();

    if(protoType == pcpp::TCP)
    {
        pcpp::TcpLayer* tcpLayer = (pcpp::TcpLayer*) transportLayer;
        sport = ntohs(tcpLayer->getTcpHeader()->portSrc);
        dport = ntohs(tcpLayer->getTcpHeader()->portDst);
    }
    else if(protoType == pcpp::UDP)
    {
        pcpp::UdpLayer* udpLayer = (pcpp::UdpLayer*) transportLayer;
        sport = ntohs(udpLayer->getUdpHeader()->portSrc);
        dport = ntohs(udpLayer->getUdpHeader()->portDst);
        // TODO: UDP 67, 68 -> parse DHCP
    }

    QString proto = protocolTypeToString(protoType);
    emit newPacket(QDateTime::currentDateTime(), proto, QString::fromStdString(saddr), sport, QString::fromStdString(daddr), dport, header->len);

    // print timestamp and length of the packet and ip addresses and ports
    if(protoType != pcpp::TCP && protoType != pcpp::UDP && protoType != pcpp::ICMP)
        printf("%s    %-4s    %s : %5d  ->  %s : %5d    len: %4d \n", timevalToString(header->ts).c_str(), proto.toStdString().c_str(), saddr.c_str(), sport, daddr.c_str(), dport, header->len);
}

void Npcap::process_arp(pcpp::ArpLayer *arpLayer, const pcap_pkthdr *header, const u_char *pkt_data)
{
    Q_UNUSED(pkt_data);

    QString proto = "ARP";
    uint16_t opcode = arpLayer->getArpHeader()->opcode;
    if(opcode == 0x0100)      proto = "ARPQ"; // pcpp::ARP_REQUEST
    else if(opcode == 0x0200) proto = "ARPR"; // pcpp::ARP_REPLY
    else proto.append(QString::number(opcode));

    std::string saddr = ipv4ToString(arpLayer->getSenderIpAddr().toInt());
    std::string daddr = ipv4ToString(arpLayer->getTargetIpAddr().toInt());

    emit newPacket(QDateTime::currentDateTime(), proto, QString::fromStdString(saddr), 0, QString::fromStdString(daddr), 0, header->len);
}
