#pragma once
#include<pcap.h>
struct IPv4info {
	uint8_t protocol;
	uint8_t headerLenght;
	uint32_t srcIP;
	uint32_t dstIP;
	int offset;

};
class Praser {
public:
	//check how long is the packet and if can read from start point
	bool CheckLimit(const pcap_pkthdr* packetHeader,int start,int AmountToRead);
	//return the source mac address
	const u_char* SourceMAC(const u_char* packetData);
	//return the destination mac address
	const u_char* DestMAC(const u_char* packetData);
	//return value of the EtherType like IPv4 and such
	uint16_t EtherType(const u_char* packetData);
	
};
