#pragma once
#include<pcap.h>
struct IPv4Info {
	uint8_t protocol;
	uint8_t headerLength;
	uint32_t srcIP;
	uint32_t dstIP;
	int l4Offset;

};
struct TcpInfo {
	uint16_t srcPort;
	uint16_t dstPort;
	uint8_t flags;
	uint8_t headerLength;
	int payloadOffset;
};
struct UdpInfo {
	uint16_t srcPort;
	uint16_t dstPort;
	uint8_t headerLength;
	int payloadOffset;
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
	//IPv4info
	bool ReadIPv4Info(const pcap_pkthdr* packetHeader, const u_char* packetData, int l3Offset, IPv4Info& outInfo);
	//TCPinfo
	bool ReadTCPInfo(const pcap_pkthdr* packetHeader, const u_char* packetData, int l4Offset, TcpInfo& outInfo);

};
