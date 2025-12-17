#include "Sniffer.h"
Sniffer::Sniffer()
    : alldevs(nullptr), errbuf{}
{
}
bool Sniffer::DiscoverInterfaces() {
    if (alldevs) {
        return true;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return false;
    }

    return true;
}
const pcap_if_t* Sniffer::GetInterfaces() const {
    return alldevs;
}

Sniffer::~Sniffer() {
    if (alldevs) {
        pcap_freealldevs(alldevs);
    }
}