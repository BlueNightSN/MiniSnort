#include "Engine.h"

#include <iostream>
#include <vector>
#include <memory>
#include <cstdint>
#include "Praser.h"
#include "Guard.h"
#include "ParsedPacket.h"
#include "IPv4ArrivedRule.h"
// ----------------- local helper -----------------
static void PrintIPv4(uint32_t ip)
{
    std::cout
        << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
}
// -----------------------------------------------
Engine::Engine() = default;
Engine::~Engine() 
{
    Stop();
    CloseDevice();

    delete m_praser;
    m_praser = nullptr;
    delete m_guard;
    m_guard = nullptr;
}
bool Engine::Init(const std::string& deviceName) {
    m_stop = false;
    if (!OpenDevice(deviceName))
    {
        return false;
    }

    // Keep the same objects you had in main()
    m_praser = new Praser();
    m_guard = new Guard();

    // Keep same rule setup you had
    m_guard->AddRule(std::make_unique<IPv4ArrivedRule>());

    return true;
}
void Engine::Run() {
    if (!m_handle || !m_praser || !m_guard)
    {
        std::cout << "Engine not initialized.\n";
        return;
    }

    // You had 10 packets in pcap_loop(handle, 10, ...).
    // Here: same idea, we’ll process 10 packets to match behavior.
    int packetsToProcess = 10;

    while (!m_stop && packetsToProcess > 0)
    {
        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;

        if (!CaptureOne(header, data))
        {
            // timeout or error - just continue like your callback-based flow
            continue;
        }

        std::cout << "\n-------------------------------------------------------------------------\n";
        std::cout << "Packet len: " << header->len
            << " caplen: " << header->caplen
            << " TimeStamp: " << header->ts.tv_sec;

        ParsedPacket parsed{};
        bool ok = ParsePacket(header, data, parsed);
        if (!ok)
        {
            std::cout << "\nParse failed\n";
            std::cout << "-------------------------------------------------------------------------\n";
            packetsToProcess--;
            continue;
        }

        std::cout << " EtherType: ";

        if (parsed.etherType == 0x0800)
        {
            std::cout << "IPv4";

            if (!parsed.hasIPv4)
            {
                std::cout << "\nBad/Truncated IPv4 header\n";
                std::cout << "-------------------------------------------------------------------------\n";
                packetsToProcess--;
                continue;
            }

            std::cout << "\nIPv4 Src: ";
            PrintIPv4(parsed.ipv4.srcIP);
            std::cout << " Dst: ";
            PrintIPv4(parsed.ipv4.dstIP);
            std::cout << " Protocol: " << int(parsed.ipv4.protocol);

            if (parsed.l4Type == ParsedPacket::L4Type::TCP && parsed.hasTcp)
            {
                std::cout << "\nTCP SrcPort: " << parsed.tcp.srcPort
                    << " DstPort: " << parsed.tcp.dstPort
                    << " Flags: 0x" << std::hex << int(parsed.tcp.flags) << std::dec
                    << " HeaderLen: " << int(parsed.tcp.headerLength)
                    << " PayloadOffset: " << parsed.tcp.payloadOffset;
            }
            else if (parsed.l4Type == ParsedPacket::L4Type::UDP && parsed.hasUdp)
            {
                std::cout << "\nUDP SrcPort: " << parsed.udp.srcPort
                    << " DstPort: " << parsed.udp.dstPort
                    << " Length: " << parsed.udp.length
                    << " HeaderLen: " << int(parsed.udp.headerLength)
                    << " PayloadOffset: " << parsed.udp.payloadOffset;
            }
            else if (parsed.l4Type == ParsedPacket::L4Type::ICMP && parsed.hasIcmp)
            {
                std::cout << "\nICMP Type: " << int(parsed.icmp.type)
                    << " Code: " << int(parsed.icmp.code)
                    << " Checksum: 0x" << std::hex << parsed.icmp.checksum << std::dec
                    << " HeaderLen: " << int(parsed.icmp.headerLength)
                    << " PayloadOffset: " << parsed.icmp.payloadOffset;
            }
            else if (parsed.l4Type == ParsedPacket::L4Type::Other)
            {
                std::cout << "\nUnsupported IPv4 L4 protocol: " << int(parsed.ipv4.protocol);
            }
        }
        else if (parsed.etherType == 0x0806)
        {
            std::cout << "ARP";
        }
        else if (parsed.etherType == 0x86DD)
        {
            std::cout << "IPv6";
        }
        else
        {
            std::cout << "Unknown (0x" << std::hex << parsed.etherType << std::dec << ")";
        }

        // Guard + alerts
        CheckRulesAndReport(parsed);

        std::cout << "\n-------------------------------------------------------------------------\n";

        packetsToProcess--;
    }
}
void Engine::Stop() {
    m_stop = true;
}
bool Engine::OpenDevice(const std::string& deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    m_handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (m_handle == nullptr)
    {
        std::cout << errbuf << "\n";
        return false;
    }
    return true;
}
void Engine::CloseDevice() {
    if (m_handle != nullptr)
    {
        pcap_close(m_handle);
        m_handle = nullptr;
    }
}
bool Engine::CaptureOne(pcap_pkthdr*& outHeader, const u_char*& outData){
    // pcap_next_ex returns:
    //  1 = packet read
    //  0 = timeout
    // -1 = error
    // -2 = EOF
    int res = pcap_next_ex(m_handle, &outHeader, &outData);
    return (res == 1);
}
bool Engine::ParsePacket(const pcap_pkthdr* header, const u_char* data, ParsedPacket& outPacket) {
    // This is my PacketPipeline logic, moved into Engine, unchanged in behavior.

    if (!m_praser->CheckLimit(header, 0, 14))
        return false;

    outPacket.etherType = m_praser->EtherType(data);

    if (outPacket.etherType != 0x0800)
        return true;

    int l3Offset = 14;
    if (!m_praser->ReadIPv4Info(header, data, l3Offset, outPacket.ipv4))
        return false;

    outPacket.hasIPv4 = true;

    if (outPacket.ipv4.protocol == 6)
    {
        if (!m_praser->ReadTCPInfo(header, data, outPacket.ipv4.l4Offset, outPacket.tcp))
            return false;

        outPacket.l4Type = ParsedPacket::L4Type::TCP;
        outPacket.hasTcp = true;
    }
    else if (outPacket.ipv4.protocol == 17)
    {
        if (!m_praser->ReadUDPInfo(header, data, outPacket.ipv4.l4Offset, outPacket.udp))
            return false;

        outPacket.l4Type = ParsedPacket::L4Type::UDP;
        outPacket.hasUdp = true;
    }
    else if (outPacket.ipv4.protocol == 1)
    {
        if (!m_praser->ReadICMPInfo(header, data, outPacket.ipv4.l4Offset, outPacket.icmp))
            return false;

        outPacket.l4Type = ParsedPacket::L4Type::ICMP;
        outPacket.hasIcmp = true;
    }
    else
    {
        outPacket.l4Type = ParsedPacket::L4Type::Other;
    }

    return true;
}
void Engine::CheckRulesAndReport(const ParsedPacket& packet) {
    std::vector<Alert> alerts = m_guard->Inspect(packet);
    for (const Alert& a : alerts)
    {
        std::cout << "\n[ALERT] " << int(a.severity) << " | " << a.ruleName << " | " << a.message;
    }
}