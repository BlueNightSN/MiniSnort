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
    if (m_producerThread.joinable())
        m_producerThread.join();

    if (m_consumerThread.joinable())
        m_consumerThread.join();
    CloseDevice();

    delete m_praser;
    m_praser = nullptr;
    delete m_guard;
    m_guard = nullptr;
}
bool Engine::Init(const std::string& deviceName) {
    m_stop.store(false);
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

    m_stop.store(false);

    m_producerThread = std::thread(&Engine::ProducerLoop, this);
    m_consumerThread = std::thread(&Engine::ConsumerLoop, this);

    if (m_producerThread.joinable())
        m_producerThread.join();

    if (m_consumerThread.joinable())
        m_consumerThread.join();
}
void Engine::Stop() {
    m_stop.store(true);
    m_cv.notify_all();
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
void Engine::ProducerLoop()
{
    // Match your old behavior: process 10 packets (like pcap_loop(handle, 10, ...))
    int packetsToProcess = 10;

    while (!m_stop.load() && packetsToProcess > 0)
    {
        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;

        if (!CaptureOne(header, data))
        {
            // timeout or capture error -> just continue trying
            continue;
        }

        ParsedPacket parsed{};
        bool ok = ParsePacket(header, data, parsed);

        // Even if parsing fails, we still counted a captured packet in the old code (pcap_loop)
        packetsToProcess--;

        if (!ok)
        {
            // Optional: you can log parse failure here, but keep it minimal for threaded v1
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_queue.push(std::move(parsed));
        }

        m_cv.notify_one();
    }

    // Tell consumer "no more packets will arrive"
    m_stop.store(true);
    m_cv.notify_all();
}
void Engine::ConsumerLoop()
{
    while (true)
    {
        ParsedPacket pkt{};

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            // Wake when there's data OR we are stopping
            m_cv.wait(lock, [this]()
                {
                    return m_stop.load() || !m_queue.empty();
                });

            // If stopping and nothing left to process -> exit cleanly
            if (m_stop.load() && m_queue.empty())
            {
                break;
            }

            pkt = std::move(m_queue.front());
            m_queue.pop();
        }

        // IMPORTANT: do rule evaluation OUTSIDE the lock
        CheckRulesAndReport(pkt);
    }
}