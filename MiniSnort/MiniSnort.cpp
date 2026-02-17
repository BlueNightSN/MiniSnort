#include <iostream>
#include <pcap.h>
#include "Sniffer.h"
#include"Praser.h"
void PrintInterfaces(const pcap_if_t* alldevs);
const pcap_if_t* UserChoice(const pcap_if_t* alldevs);
void PrintPacket(u_char* user, const pcap_pkthdr* packetHeader, const u_char* packetData);
struct ParsedPacket {
    uint16_t etherType = 0;
    bool hasIPv4 = false;
    IPv4Info ipv4{};
    enum class L4Type{None, TCP, UDP, ICMP, Other} l4Type = L4Type :: None;
    bool hasTcp = false;
    TcpInfo tcp{};
    bool hasUdp = false;
    UdpInfo udp{};
    bool hasIcmp = false;
    IcmpInfo icmp{};
};
bool PacketPipeline(const pcap_pkthdr* packetHeader, const u_char* packetData, Praser& praser, ParsedPacket& outPacket);
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

    ParsedPacket parsed;
    bool ok = PacketPipeline(packetHeader, packetData, *praser, parsed);
    if (!ok) {
        std::cout << "\nParse failed\n";
        std::cout << "-------------------------------------------------------------------------\n";
        return;
    }

    std::cout << " EtherType: ";

    if (parsed.etherType == 0x0800) {
        std::cout << "IPv4";

        if (!parsed.hasIPv4) {
            std::cout << "\nBad/Truncated IPv4 header\n";
            std::cout << "-------------------------------------------------------------------------\n";
            return;
        }

        std::cout << "\nIPv4 Src: ";
        PrintIPv4(parsed.ipv4.srcIP);
        std::cout << " Dst: ";
        PrintIPv4(parsed.ipv4.dstIP);
        std::cout << " Protocol: " << int(parsed.ipv4.protocol);

        if (parsed.l4Type == ParsedPacket::L4Type::TCP && parsed.hasTcp) {
            std::cout << "\nTCP SrcPort: " << parsed.tcp.srcPort
                << " DstPort: " << parsed.tcp.dstPort
                << " Flags: 0x" << std::hex << int(parsed.tcp.flags) << std::dec
                << " HeaderLen: " << int(parsed.tcp.headerLength)
                << " PayloadOffset: " << parsed.tcp.payloadOffset;
        }
        else if (parsed.l4Type == ParsedPacket::L4Type::UDP && parsed.hasUdp) {
            std::cout << "\nUDP SrcPort: " << parsed.udp.srcPort
                << " DstPort: " << parsed.udp.dstPort
                << " Length: " << parsed.udp.length
                << " HeaderLen: " << int(parsed.udp.headerLength)
                << " PayloadOffset: " << parsed.udp.payloadOffset;
        }
        else if (parsed.l4Type == ParsedPacket::L4Type::ICMP && parsed.hasIcmp) {
            std::cout << "\nICMP Type: " << int(parsed.icmp.type)
                << " Code: " << int(parsed.icmp.code)
                << " Checksum: 0x" << std::hex << parsed.icmp.checksum << std::dec
                << " HeaderLen: " << int(parsed.icmp.headerLength)
                << " PayloadOffset: " << parsed.icmp.payloadOffset;
        }
        else if (parsed.l4Type == ParsedPacket::L4Type::Other) {
            std::cout << "\nUnsupported IPv4 L4 protocol: " << int(parsed.ipv4.protocol);
        }
    }
    else if (parsed.etherType == 0x0806) {
        std::cout << "ARP";
    }
    else if (parsed.etherType == 0x86DD) {
        std::cout << "IPv6";
    }
    else {
        std::cout << "Unknown (0x" << std::hex << parsed.etherType << std::dec << ")";
    }

    std::cout << "\n-------------------------------------------------------------------------\n";
}
bool PacketPipeline(const pcap_pkthdr* packetHeader, const u_char* packetData, Praser& praser, ParsedPacket& outPacket) {
    //safety check + ether type check
    if (!praser.CheckLimit(packetHeader, 0, 14)) return false;
    outPacket.etherType = praser.EtherType(packetData);
    if (outPacket.etherType != 0x0800) return true;
    int l3Offset = 14;
    if (!praser.ReadIPv4Info(packetHeader, packetData, l3Offset, outPacket.ipv4))
        return false;

    outPacket.hasIPv4 = true;
    //if IPv4 read the right protocol
    if (outPacket.ipv4.protocol == 6) {
        if (!praser.ReadTCPInfo(packetHeader, packetData, outPacket.ipv4.l4Offset, outPacket.tcp))
            return false;

        outPacket.l4Type = ParsedPacket::L4Type::TCP;
        outPacket.hasTcp = true;
    }
    else if (outPacket.ipv4.protocol == 17) {
        if (!praser.ReadUDPInfo(packetHeader, packetData, outPacket.ipv4.l4Offset, outPacket.udp))
            return false;

        outPacket.l4Type = ParsedPacket::L4Type::UDP;
        outPacket.hasUdp = true;
    }
    else if (outPacket.ipv4.protocol == 1) {
        if (!praser.ReadICMPInfo(packetHeader, packetData, outPacket.ipv4.l4Offset, outPacket.icmp))
            return false;

        outPacket.l4Type = ParsedPacket::L4Type::ICMP;
        outPacket.hasIcmp = true;
    }
    else {
        outPacket.l4Type = ParsedPacket::L4Type::Other;
    }
    return true;

}