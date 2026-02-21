#include <iostream>
#include "Sniffer.h"
#include "Engine.h"
void PrintInterfaces(const pcap_if_t* alldevs);
const pcap_if_t* UserChoice(const pcap_if_t* alldevs);

int main()
{
    Sniffer sniffer;

    if (!sniffer.DiscoverInterfaces())
    {
        std::cout << "Could not find network intefaces check if npcap installed or premissions";
        return 1;
    }

    const pcap_if_t* alldevs = sniffer.GetInterfaces();
    PrintInterfaces(alldevs);

    const pcap_if_t* chosen = UserChoice(alldevs);
    if (chosen == nullptr)
    {
        std::cout << "Noting was choosen exiting the progam";
        return 0;
    }

    Engine engine;
    if (!engine.Init(chosen->name))
    {
        std::cout << "Engine init failed.\n";
        return 1;
    }

    engine.Run();
    return 0;
}
void PrintInterfaces(const pcap_if_t* alldevs) {
    int i = 0;
    for (const pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << " [" << i++ << "] "
            << (d->name ? d->name : "NoName");

        if (d->description) {
            std::cout << " - " << d->description;
        }

        std::cout << "\n";
    }
}
const pcap_if_t* UserChoice(const pcap_if_t* alldevs) {
    const pcap_if_t* c = alldevs;
    const pcap_if_t* d = nullptr;
    int count = 0;
    for (d = alldevs; d != nullptr; d = d->next) {
        count++;
    }
    int choice;
    std::cout << "Please choose network interface: ";
    std::cin >> choice;
    if (choice >= count || choice < 0) {
        std::cout << "Not a possible choice\n";
        return nullptr;
    }
    for (; choice > 0; choice--) {
        c = c->next;
    }
    std::cout << "\n The Choosen Device is: " << (c->description ? c->description : c->name) << "\n";

    return c;
}
