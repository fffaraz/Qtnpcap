#include "npcap.h"

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

std::string Npcap::protocolTypeToString(pcpp::ProtocolType protocolType)
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
    case pcpp::ICMP:
        return "ICMP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}

std::string Npcap::ipv4ToString(int ip)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%3d.%3d.%3d.%3d", (ip & 0x000000ff) >> 0, (ip & 0x0000ff00) >> 8, (ip & 0x00ff0000) >> 16, (ip & 0xff000000) >> 24);
    return std::string(buffer, sizeof(buffer));
}

std::string Npcap::timevalToString(timeval ts)
{
    // convert the timestamp to readable format
    char timestr[16];
    time_t local_tv_sec = ts.tv_sec;
    tm *ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s,%.6d", timestr, ts.tv_usec);
    return std::string(buffer, sizeof(buffer));
}
