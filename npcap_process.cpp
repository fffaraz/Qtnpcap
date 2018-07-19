#include "npcap.h"

#include <EthLayer.h>
#include <IPv4Layer.h>
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

    // get the IPv4 layer
    pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if(ipv4Layer == NULL)
    {
        //printf("Something went wrong, couldn't find IPv4 layer\n");
        printf("%s    %s    len: %4d \n", timevalToString(header->ts).c_str(), ethernetLayer->getNextLayer()->toString().c_str(), header->len);
        //QByteArray ba((const char *)pkt_data, header->caplen); qDebug() << ba;
        return;
    }

    std::string saddr = ipv4ToString(ipv4Layer->getSrcIpAddress().toInt());
    std::string daddr = ipv4ToString(ipv4Layer->getDstIpAddress().toInt());
    u_short     sport = 0;
    u_short     dport = 0;

    // get the Transport layer
    pcpp::Layer* transportLayer = ipv4Layer->getNextLayer();
    pcpp::ProtocolType protoType = transportLayer->getProtocol();
    std::string proto = protocolTypeToString(protoType);

    if(protoType == pcpp::TCP)
    {
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        sport = ntohs(tcpLayer->getTcpHeader()->portSrc);
        dport = ntohs(tcpLayer->getTcpHeader()->portDst);
    }
    else if(protoType == pcpp::UDP)
    {
        pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        sport = ntohs(udpLayer->getUdpHeader()->portSrc);
        dport = ntohs(udpLayer->getUdpHeader()->portDst);
    }

    emit newPacket(QDateTime::currentDateTime(), QString::fromStdString(proto), QString::fromStdString(saddr), sport, QString::fromStdString(daddr), dport, header->len);

    // print timestamp and length of the packet and ip addresses and ports
    if(protoType != pcpp::TCP && protoType != pcpp::UDP)
        printf("%s    %-4s    %s : %5d  ->  %s : %5d    len: %4d \n", timevalToString(header->ts).c_str(), proto.c_str(), saddr.c_str(), sport, daddr.c_str(), dport, header->len);
}
