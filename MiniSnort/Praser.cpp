#include"Praser.h"
Praser::Praser()
{
}
//packetHeader= how many bytes i have , start = where i start to read from, Amount = how many i need to read
bool CheckLimit(const pcap_pkthdr* packetHeader, int start,int AmountToRead) {
	if (start > (packetHeader->caplen - AmountToRead) || start < 0 || AmountToRead < 0) return false;
	else return true;
}