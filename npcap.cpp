#include "npcap.h"

Npcap::Npcap(QObject *parent) : QThread(parent)
{
    // Retrieve the device list
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }
    for(pcap_if_t *d = alldevs; d; d = d->next)
    {
        devs.append(d);
        for(pcap_addr *addr = d->addresses; addr; addr = addr->next)
        {
            char buffer[INET6_ADDRSTRLEN] = {};
            switch(addr->addr->sa_family) {
            case AF_INET:
            {
                sockaddr_in *addr_in = (sockaddr_in *)addr->addr;
                inet_ntop(AF_INET, &(addr_in->sin_addr), buffer, INET_ADDRSTRLEN);
                break;
            }
            case AF_INET6:
            {
                sockaddr_in6 *addr_in6 = (sockaddr_in6 *)addr->addr;
                inet_ntop(AF_INET6, &(addr_in6->sin6_addr), buffer, INET6_ADDRSTRLEN);
                break;
            }
            default:
                break;
            }
            addrs.insertMulti(devs.size() - 1, QString(buffer));
        }
    }
}

Npcap::~Npcap()
{
    if(isRunning())
    {
        pcap_breakloop(adhandle);
        wait();
    }
    if(alldevs != nullptr) pcap_freealldevs(alldevs);
}

void Npcap::print()
{
    // Print the list
    if(devs.size() == 0) printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    for(int i = 0; i < devs.size(); ++i)
    {
        printf("%d. %s ", i + 1, devs[i]->name);
        if(devs[i]->description) printf("%s\n", devs[i]->description);
        else printf("No description available.\n");
        foreach(const QString &addr, addrs.values(i)) printf("\t%s\n", addr.toStdString().c_str());
    }
}

QString Npcap::protocolTypeToString(pcpp::ProtocolType protocolType)
{
    switch(protocolType)
    {
    case pcpp::UnknownProtocol:
        return "Unknown";
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::IPv6:
        return "IPv6";
    case pcpp::IP:
        return "IP";
    case pcpp::TCP:
        return "TCP";
    case pcpp::UDP:
        return "UDP";
    case pcpp::HTTPRequest:
        return "HTTPRequest";
    case pcpp::HTTPResponse:
        return "HTTPResponse";
    case pcpp::HTTP:
        return "HTTP";
    case pcpp::ARP:
        return "ARP";
    case pcpp::VLAN:
        return "VLAN";
    case pcpp::ICMP:
        return "ICMP";
    case pcpp::PPPoESession:
        return "PPPoESession";
    case pcpp::PPPoEDiscovery:
        return "PPPoEDiscovery";
    case pcpp::PPPoE:
        return "PPPoE";
    case pcpp::DNS:
        return "DNS";
    case pcpp::MPLS:
        return "MPLS";
    case pcpp::GREv0:
        return "GREv0";
    case pcpp::GREv1:
        return "GREv1";
    case pcpp::GRE:
        return "GRE";
    case pcpp::PPP_PPTP:
        return "PPP_PPTP";
    case pcpp::SSL:
        return "SSL";
    case pcpp::SLL:
        return "SLL";
    case pcpp::DHCP:
        return "DHCP";
    case pcpp::NULL_LOOPBACK:
        return "NULL_LOOPBACK";
    case pcpp::IGMP:
        return "IGMP";
    case pcpp::IGMPv1:
        return "IGMPv1";
    case pcpp::IGMPv2:
        return "IGMPv2";
    case pcpp::IGMPv3:
        return "IGMPv3";
    case pcpp::GenericPayolad:
        return "GenericPayolad";
    case pcpp::VXLAN:
        return "VXLAN";
    case pcpp::SIPRequest:
        return "SIPRequest";
    case pcpp::SIPResponse:
        return "SIPResponse";
    case pcpp::SIP:
        return "SIP";
    case pcpp::SDP:
        return "SDP";
    default:
        return QString::number(protocolType);
    }
}

std::string Npcap::ipv4ToString(int ip)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%3d.%3d.%3d.%3d", (ip & 0x000000ff) >> 0, (ip & 0x0000ff00) >> 8, (ip & 0x00ff0000) >> 16, (ip & 0xff000000) >> 24);
    return std::string(buffer);
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
    return std::string(buffer);
}
