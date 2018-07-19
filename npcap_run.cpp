#include "npcap.h"

void Npcap::run()
{
    if(inum < 0 || inum >= devs.size())
    {
        printf("\nInterface number out of range.\n");
        return;
    }

    // Open the device and the adapter
    adhandle = pcap_open_live(devs[inum]->name,	// name of the device
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
    if(pcap_loop(adhandle, 0, &Npcap::packet_handler, reinterpret_cast<u_char*>(this)) == -1)
    {
        fprintf(stderr, "\nERROR: pcap_loop: %s\n", pcap_geterr(adhandle));
        return;
    }

    pcap_close(adhandle);
}
