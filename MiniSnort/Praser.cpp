#include"Praser.h"
//packetHeader= how many bytes i have , start = where i start to read from, Amount = how many i need to read
bool Praser::CheckLimit(const pcap_pkthdr* packetHeader, int start,int AmountToRead) {
    if (!packetHeader) return false;
	if (start < 0 || AmountToRead < 0 || start > (packetHeader->caplen - AmountToRead) || AmountToRead > packetHeader->caplen ) return false;
	else return true;
}
const u_char* Praser::SourceMAC(const u_char* packetData) {
	return packetData+6;
}
const u_char* Praser::DestMAC(const u_char* packetData) {
	return packetData + 0;
}
uint16_t Praser::EtherType(const u_char* packetData) {
	//combine packetdata [12] and [13] to find the exact ethernet type
	//changed their types to unsigned to make sure i stay unsigned
	return (uint16_t(packetData[12]) << 8) | uint16_t(packetData[13]);
} 
bool Praser::ReadIPv4Info(const pcap_pkthdr* packetHeader,const u_char* packetData,int l3Offset,IPv4Info& outInfo)
{
    // Minimum IPv4 header is 20 bytes
    if (!CheckLimit(packetHeader, l3Offset, 20))
        return false;

    // First byte: Version (high 4 bits) | IHL (low 4 bits)
    uint8_t versionIhl = packetData[l3Offset];
    uint8_t ihl = versionIhl & 0x0F;        // IHL in 32-bit words
    uint8_t headerLength = ihl * 4;          // convert to bytes

    // IPv4 header must be at least 20 bytes
    if (headerLength < 20)
        return false;

    // Make sure the full IPv4 header is inside the captured packet
    if (!CheckLimit(packetHeader, l3Offset, headerLength))
        return false;

    // Protocol field (1 byte)
    uint8_t protocol = packetData[l3Offset + 9];

    // Source IP (4 bytes)
    uint32_t srcIP =
        (uint32_t(packetData[l3Offset + 12]) << 24) |
        (uint32_t(packetData[l3Offset + 13]) << 16) |
        (uint32_t(packetData[l3Offset + 14]) << 8) |
        (uint32_t(packetData[l3Offset + 15]));

    // Destination IP (4 bytes)
    uint32_t dstIP =
        (uint32_t(packetData[l3Offset + 16]) << 24) |
        (uint32_t(packetData[l3Offset + 17]) << 16) |
        (uint32_t(packetData[l3Offset + 18]) << 8) |
        (uint32_t(packetData[l3Offset + 19]));

    // Fill output struct
    outInfo.protocol = protocol;
    outInfo.headerLength = headerLength;
    outInfo.srcIP = srcIP;
    outInfo.dstIP = dstIP;
    outInfo.l4Offset = l3Offset + headerLength;

    return true;
}
bool Praser::ReadTCPInfo(const pcap_pkthdr* packetHeader, const u_char* packetData, int l4Offset, TcpInfo& outInfo)
{
    //check for minimum TCP header
    if (!CheckLimit(packetHeader, l4Offset, 20))
        return false;

    // SourcePort (2 byte)
    uint16_t SourcePort = (uint16_t(packetData[l4Offset + 0]) << 8) |uint16_t(packetData[l4Offset + 1]);

    // DestinationPort (2 bytes)
    uint16_t DstPort = (uint16_t(packetData[l4Offset + 2]) << 8) | uint16_t(packetData[l4Offset + 3]);
    //flags
    uint8_t Flags = uint8_t(packetData[l4Offset + 13]);
    // HeaderLength 
    uint8_t headerLength = ((packetData[l4Offset + 12] >> 4) & 0x0F) * 4;
    if (headerLength < 20) return false;
    if (!CheckLimit(packetHeader, l4Offset, 20))
        return false;
    //PayloadOffset
    int PayloadOffset = l4Offset + headerLength;

    // Fill output struct
    outInfo.srcPort = SourcePort;
    outInfo.dstPort = DstPort;
    outInfo.flags = Flags;
    outInfo.headerLength = headerLength;
    outInfo.payloadOffset = PayloadOffset;
    

    return true;
}
