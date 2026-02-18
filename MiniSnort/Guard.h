#pragma once
#include <string>
#include <optional>
enum class Severity {Info,Low,Medium,High};
struct Alert {
	Severity severity;
	std::string ruleName;
	std::string message;
};
struct ParsedPacket;
class IRule {
public:
	virtual ~IRule() = default;
	virtual std::optional<Alert> Evaluate(const ParsedPacket& packet) const = 0;
};
class Guard
{
	
};