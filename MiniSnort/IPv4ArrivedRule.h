#pragma once
#include "Guard.h"
#include "ParsedPacket.h"

class IPv4ArrivedRule : public IRule
{
public:
    const std::string& Name() const override
    {
        return m_name;
    }

    std::optional<Alert> Evaluate(const ParsedPacket& packet) const override
    {
        if (packet.etherType == 0x0800 && packet.hasIPv4)
        {
            Alert a;
            a.severity = Severity::Info;
            a.ruleName = m_name;
            a.message = "IPv4 packet detected";
            return a;
        }

        return std::nullopt;
    }

private:
    std::string m_name = "IPv4ArrivedRule";
};