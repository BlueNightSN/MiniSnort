#pragma once
#include<pcap.h>
class Sniffer{
private:
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
public:
	Sniffer();
	bool DiscoverInterfaces();
	const pcap_if_t* GetInterfaces() const;
	~Sniffer();

};
