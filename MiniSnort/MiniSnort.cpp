#include <iostream>
#include <pcap.h>
#include "Sniffer.h"
#include"Praser.h"
void PrintInterfaces(const pcap_if_t* alldevs);
const pcap_if_t* UserChoice(const pcap_if_t* alldevs);
void PrintPacket(u_char* user, const pcap_pkthdr* packetHeader, const u_char* packetData);
static void PrintIPv4(uint32_t ip)
{
    std::cout
        << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
}
int main()
{
    // Get list of all capture devices
    Sniffer sniffer;
    Praser praser;
    if (!sniffer.DiscoverInterfaces()) {
        std::cout << "Could not find network intefaces check if npcap installed or premissions";
        return 1;
    }
    const pcap_if_t* alldevs = sniffer.GetInterfaces();
    PrintInterfaces(alldevs);
    const pcap_if_t* chosen = UserChoice(alldevs);
    if (chosen == nullptr) {
        std::cout << "Noting was choosen exiting the progam";
        return 0;
    }
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(chosen->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cout << errbuf;
        return 0;
    }
    
    pcap_loop(handle, 10,PrintPacket , (u_char*) & praser);
    return 0;
}
void PrintInterfaces(const pcap_if_t* alldevs) {
    int i = 0;
    for (const pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << " [" << i++ << "] "
            << (d->name ? d->name : "NoName");

        if (d->description) {
            std::cout << " - " << d->description;
        }

        std::cout << "\n";
    }
}
const pcap_if_t* UserChoice(const pcap_if_t* alldevs) {
    const pcap_if_t* c = alldevs;
    const pcap_if_t* d = nullptr;
    int count = 0;
    for (d = alldevs; d != nullptr; d = d->next) {
        count++;
    }
    int choice;
    std::cout << "Please choose network interface: ";
    std::cin >> choice;
    if (choice >= count || choice < 0) {
        std::cout << "Not a possible choice\n";
        return nullptr;
    }
    for (; choice > 0; choice--) {
        c = c->next;
    }
    std::cout << "\n The Choosen Device is: " << c->description << "\n";
    return c;
}
void PrintPacket(u_char* user,const pcap_pkthdr* packetHeader, const u_char* packetData) {
    Praser* praser = reinterpret_cast<Praser*>(user);

    std::cout << "\n-------------------------------------------------------------------------\n";
    std::cout << "Packet len: " << packetHeader->len
        << " caplen: " << packetHeader->caplen
        << " TimeStamp: " << packetHeader->ts.tv_sec;

    // Ethernet minimum
    if (!praser->CheckLimit(packetHeader, 0, 14)) {
        std::cout << "\nPacket too small for Ethernet header\n";
        std::cout << "-------------------------------------------------------------------------\n";
        return;
    }

    uint16_t etherType = praser->EtherType(packetData);

    std::cout << " EtherType: ";
    if (etherType == 0x0800) {
        std::cout << "IPv4";

        // L3 starts after Ethernet header
        int l3Offset = 14;

        IPv4Info ipv4;
        if (!praser->ReadIPv4Info(packetHeader, packetData, l3Offset, ipv4)) {
            std::cout << "\nBad/Truncated IPv4 header\n";
            std::cout << "-------------------------------------------------------------------------\n";
            return;
        }

        std::cout << "\nIPv4 Src: ";
        PrintIPv4(ipv4.srcIP);
        std::cout << " Dst: ";
        PrintIPv4(ipv4.dstIP);
        std::cout << " Protocol: " << int(ipv4.protocol);

        // L4 dispatch by protocol
        if (ipv4.protocol == 6) { // TCP
            TcpInfo tcp;
            if (!praser->ReadTCPInfo(packetHeader, packetData, ipv4.l4Offset, tcp)) {
                std::cout << "\nBad/Truncated TCP header\n";
                std::cout << "-------------------------------------------------------------------------\n";
                return;
            }

            std::cout << "\nTCP SrcPort: " << tcp.srcPort
                << " DstPort: " << tcp.dstPort
                << " Flags: 0x" << std::hex << int(tcp.flags) << std::dec
                << " HeaderLen: " << int(tcp.headerLength)
                << " PayloadOffset: " << tcp.payloadOffset;
        }
        else if (ipv4.protocol == 17) { // UDP
            UdpInfo udp;
            if (!praser->ReadUDPInfo(packetHeader, packetData, ipv4.l4Offset, udp)) {
                std::cout << "\nBad/Truncated UDP header\n";
                std::cout << "-------------------------------------------------------------------------\n";
                return;
            }

            std::cout << "\nUDP SrcPort: " << udp.srcPort
                << " DstPort: " << udp.dstPort
                << " Length: " << udp.length
                << " HeaderLen: " << int(udp.headerLength)
                << " PayloadOffset: " << udp.payloadOffset;
        }
        else if (ipv4.protocol == 1) { // ICMP
            IcmpInfo icmp;
            if (!praser->ReadICMPInfo(packetHeader, packetData, ipv4.l4Offset, icmp)) {
                std::cout << "\nBad/Truncated ICMP header\n";
                std::cout << "-------------------------------------------------------------------------\n";
                return;
            }

            std::cout << "\nICMP Type: " << int(icmp.type)
                << " Code: " << int(icmp.code)
                << " Checksum: 0x" << std::hex << icmp.checksum << std::dec
                << " HeaderLen: " << int(icmp.headerLength)
                << " PayloadOffset: " << icmp.payloadOffset;
        }
        else {
            std::cout << "\nUnsupported IPv4 L4 protocol: " << int(ipv4.protocol);
        }
    }
    else if (etherType == 0x0806) {
        std::cout << "ARP";
    }
    else if (etherType == 0x86DD) {
        std::cout << "IPv6";
    }
    else {
        std::cout << "Unknown (0x" << std::hex << etherType << std::dec << ")";
    }

    std::cout << "\n-------------------------------------------------------------------------\n";
}