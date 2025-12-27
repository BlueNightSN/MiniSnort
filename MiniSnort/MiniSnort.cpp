#include <iostream>
#include <pcap.h>
#include "Sniffer.h"
#include"Praser.h"
void PrintInterfaces(const pcap_if_t* alldevs);
const pcap_if_t* UserChoice(const pcap_if_t* alldevs);
void PrintPacket(u_char* user, const pcap_pkthdr* packetHeader, const u_char* packetData);
void EtherType(const u_char* packetData);
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
    std::cout << "Packet length: " << packetHeader->len << " TimeStamp: " << packetHeader->ts.tv_sec <<" EtherType: ";
    if (!praser->CheckLimit(packetHeader, 0, 14)) {
        std::cout << "Packet too small for Ethernet header\n";
        return;
    }
    uint16_t etherType = praser->EtherType(packetData);

    std::cout << "EtherType: ";
    if (etherType == 0x0800) {
        std::cout << "IPv4";
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