#include "npcap.h"

#include <RawPacket.h>
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

std::string printipv4(int ip)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%3d.%3d.%3d.%3d", (ip & 0x000000ff) >> 0, (ip & 0x0000ff00) >> 8, (ip & 0x00ff0000) >> 16, (ip & 0xff000000) >> 24);
    return std::string(buffer, sizeof(buffer));
}

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch(protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::IPv6:
        return "IPv6";
    case pcpp::TCP:
        return "TCP";
    case pcpp::UDP:
        return "UDP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}

// Callback function invoked by libpcap for every incoming packet
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    Q_UNUSED(param);

    // convert the timestamp to readable format
    char timestr[16];
    {
        time_t local_tv_sec = header->ts.tv_sec;
        tm *ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    }

    bpf_u_int32 pkt_len = header->len;
    if(header->len != header->caplen)
    {
        qDebug() << "WARNING: header->len != header->caplen" << header->len << header->caplen;
        return;
    }

    pcpp::RawPacket rawPacket(pkt_data, pkt_len, header->ts, false);
    pcpp::Packet parsedPacket(&rawPacket);

    // now let's get the Ethernet layer
    pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL)
    {
        printf("Something went wrong, couldn't find Ethernet layer\n");
        return;
    }

    // let's get the IPv4 layer
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer == NULL)
    {
        //printf("Something went wrong, couldn't find IPv4 layer\n");
        printf("%s,%.6d    %s \n", timestr, header->ts.tv_usec, ethernetLayer->getNextLayer()->toString().c_str());
        return;
    }

    u_short sport = 0;
    u_short dport = 0;
    std::string proto = "    ";

    pcpp::Layer* tcpudpLayer = ipLayer->getNextLayer();
    pcpp::ProtocolType protoType = tcpudpLayer->getProtocol();
    if(protoType == pcpp::TCP)
    {
        proto = "TCP ";
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        sport = ntohs(tcpLayer->getTcpHeader()->portSrc);
        dport = ntohs(tcpLayer->getTcpHeader()->portDst);
    }
    else if(protoType == pcpp::UDP)
    {
        proto = "UDP ";
        pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        sport = ntohs(udpLayer->getUdpHeader()->portSrc);
        dport = ntohs(udpLayer->getUdpHeader()->portDst);
    }
    else if(protoType == pcpp::ICMP)
    {
        proto = "ICMP";
    }

    // print timestamp and length of the packet and ip addresses and ports
    printf("%s,%.6d    %s    %s : %5d  ->  %s : %5d    len: %4d \n", timestr, header->ts.tv_usec, proto.c_str(), printipv4(ipLayer->getSrcIpAddress().toInt()).c_str(), sport, printipv4(ipLayer->getDstIpAddress().toInt()).c_str(), dport, pkt_len);
}

Npcap::Npcap(QObject *parent) : QObject(parent)
{
    // Retrieve the device list
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }
    for(pcap_if_t *d = alldevs; d; d = d->next) devs.append(d);
}

Npcap::~Npcap()
{
    if(alldevs != nullptr) pcap_freealldevs(alldevs);
}

void Npcap::print()
{
    // Print the list
    if(devs.size() == 0) printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    for(int i = 0; i < devs.size(); ++i)
    {
        printf("%d. %s", i + 1, devs[i]->name);
        if(devs[i]->description) printf(" (%s)\n", devs[i]->description);
        else printf(" (No description available)\n");
    }
}

void Npcap::open(int inum)
{
    if(inum < 0 || inum >= devs.size())
    {
        printf("\nInterface number out of range.\n");
        return;
    }

    // Open the device
    // Open the adapter
    pcap_t *adhandle = pcap_open_live(devs[inum]->name,	// name of the device
                                      65536,            // portion of the packet to capture.65536 grants that the whole packet will be captured on all the MACs.
                                      1,                // promiscuous mode (nonzero means promiscuous)
                                      1000,             // read timeout
                                      errbuf            // error buffer
                                      );
    if(adhandle == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", devs[inum]->name);
        fprintf(stderr, "Error in pcap_open_live: %s\n", errbuf);
        return;
    }

    // Check the link layer. We support only Ethernet for simplicity.
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        return;
    }

    /*
    if(pcap_set_immediate_mode(adhandle, 1) != 0)
    {
        fprintf(stderr, "\nERROR: pcap_set_immediate_mode: %s\n", pcap_geterr(adhandle));
        return;
    }
    */

    /*
    if(pcap_setdirection(adhandle, PCAP_D_IN) != 0)
    {
        fprintf(stderr, "\nERROR: pcap_setdirection: %s\n", pcap_geterr(adhandle));
        return;
    }
    */

    if(0) // Filter
    {
        u_int netmask;
        if(devs[inum]->addresses != NULL)
            // Retrieve the mask of the first address of the interface
            netmask = ((struct sockaddr_in *)(devs[inum]->addresses->netmask))->sin_addr.S_un.S_addr;
        else
            // If the interface is without addresses we suppose to be in a C class network
            netmask = 0xffffff;

        // compile the filter
        bpf_program fcode;
        char packet_filter[] = "ip and tcp";
        if(pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
        {
            fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
            return;
        }

        // set the filter
        if(pcap_setfilter(adhandle, &fcode) < 0)
        {
            fprintf(stderr, "\nError setting the filter.\n");
            return;
        }
    }

    printf("\nlistening on %s...\n", devs[inum]->description);
    // At this point, we don't need any more the device list. Free it

    // start the capture
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
}

