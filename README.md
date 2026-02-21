MiniSnort

MiniSnort is a modular intrusion detection system (IDS) prototype written in modern C++ (C++17), built to demonstrate systems-level programming, packet parsing, and extensible detection architecture.

The project focuses on clean design, memory safety, and separation of concerns while working directly with raw packets using Npcap.

Architecture Overview

MiniSnort follows a layered design inspired by real-world IDS engines:

Sniffer → Parser → Guard → Alert Output

1. Sniffer

Uses Npcap (pcap_open_live)

Captures raw packets from a selected network interface

Feeds packets into the processing pipeline

2. Parser (Praser)

Safely decodes:

Ethernet

IPv4

TCP

UDP

ICMP

Performs strict bounds checking to prevent invalid memory access

Produces a structured ParsedPacket object

3. Guard (Rule Engine)

Evaluates parsed packets against modular detection rules

Uses polymorphism via an IRule interface

Returns structured Alert objects

4. Alert Output

Displays alerts separately from packet parsing logic

Clean separation between detection and presentation

Rule Engine Design

MiniSnort implements a modular detection engine using a polymorphic rule interface:

class IRule
{
public:
    virtual ~IRule() = default;
    virtual const std::string& Name() const = 0;
    virtual std::optional<Alert> Evaluate(const ParsedPacket& packet) const = 0;
};


Rules are registered dynamically:

guard.AddRule(std::make_unique<SomeRule>());


Each rule:

Inspects a parsed packet

Returns either an Alert or std::nullopt

Is completely independent from other rules

The Guard class manages rule ownership using std::unique_ptr and evaluates them for every packet:

std::vector<Alert> alerts = guard.Inspect(parsedPacket);


This design allows:

Easy addition of new rules

No modification to the Guard engine when adding rules

Clean separation between parsing and detection

Extensibility toward stateful or multi-threaded detection

ParsedPacket Structure

All packet information is stored in a dedicated ParsedPacket structure:

EtherType

IPv4 header

TCP / UDP / ICMP info

Layer 4 type tracking

Presence flags for each protocol

This allows Guard rules to operate on structured, validated data instead of raw buffers.

Example Rule

An initial validation rule (IPv4ArrivedRule) was implemented to verify end-to-end integration.

It generates an alert whenever an IPv4 packet is detected:

Packet Capture → Parse → Guard → Alert


This confirms that the full IDS pipeline is operational.

Design Goals

Modern C++ (C++17)

No global state

RAII-based ownership (std::unique_ptr)

Strict bounds checking during parsing

Clean module separation

Memory-safe design

Extensible rule engine

Prepared for future:

Stateful detection

Multi-threading

Alert isolation / separate console

Configurable rules

Why This Project

MiniSnort is built as a systems-programming portfolio project to demonstrate:

Low-level networking knowledge

Packet structure understanding (Ethernet / IPv4 / TCP / UDP / ICMP)

Modular architecture design

Polymorphism and interface-based design

Safe memory management

IDS-style detection logic

This is not a wrapper around existing IDS tools — it is a ground-up implementation focused on architectural clarity and extensibility.

Future Improvements

Planned enhancements include:

TCP anomaly detection (NULL scan / XMAS scan)

Suspicious port detection

Stateful scan detection

Multi-threaded processing

Dedicated alert console via IPC

Configurable rule parameters

IPv6 parsing support

MiniSnort is evolving toward a clean, extensible IDS prototype suitable for systems and security engineering roles.
