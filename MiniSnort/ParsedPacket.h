#pragma once
#include <cstdint>
#include "Praser.h"
struct ParsedPacket 
{
    uint16_t etherType = 0;
    bool hasIPv4 = false;
    IPv4Info ipv4{};
    enum class L4Type { None, TCP, UDP, ICMP, Other } l4Type = L4Type::None;
    bool hasTcp = false;
    TcpInfo tcp{};
    bool hasUdp = false;
    UdpInfo udp{};
    bool hasIcmp = false;
    IcmpInfo icmp{};
};
