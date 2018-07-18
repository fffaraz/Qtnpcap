#include "npcap.h"

#include <RawPacket.h>

// Callback function invoked by libpcap for every incoming packet
void Npcap::packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data)
{
    if(header->len != header->caplen)
    {
        qDebug() << "WARNING: header->len != header->caplen" << header->len << header->caplen;
        return;
    }

    pcpp::RawPacket rawPacket(pkt_data, header->caplen, header->ts, false);
    pcpp::Packet parsedPacket(&rawPacket);

    Npcap *npcap = reinterpret_cast<Npcap*>(param);
    npcap->process_packet(parsedPacket, header, pkt_data);
}
