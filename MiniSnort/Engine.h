#pragma once
#include <string>
#include <pcap.h>
class Praser;
class Guard;
struct ParsedPacket;

class Engine
{
public:
	Engine();
	~Engine();
	//anti engine duplication
		//delete copy constructor
	Engine(const Engine&) = delete;
		//delete copy assignment operator
	Engine& operator=(const Engine&) = delete;

	bool Init(const std::string& deviceName);
	void Run();
	void Stop();
private:
	//opening the device to read
	bool OpenDevice(const std::string& deviceName);
	void CloseDevice();
	//flow of the program capture->prase->check with rules
	bool CaptureOne(pcap_pkthdr*& outHeader, const u_char*& outData);
	bool ParsePacket(const pcap_pkthdr* header, const u_char* data, ParsedPacket& outPacket);
	void CheckRulesAndReport(const ParsedPacket& packet);
	//varibales
	pcap_t* m_handle = nullptr;
	bool m_stop = false;
	Praser* m_praser = nullptr;
	Guard* m_guard = nullptr;
};

