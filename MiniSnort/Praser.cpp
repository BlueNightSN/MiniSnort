#include"Praser.h"
//packetHeader= how many bytes i have , start = where i start to read from, Amount = how many i need to read
bool Praser::CheckLimit(const pcap_pkthdr* packetHeader, int start,int AmountToRead) {
	if (start > (packetHeader->caplen - AmountToRead) || start < 0 || AmountToRead < 0) return false;
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