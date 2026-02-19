#pragma once
#include <string>
#include <optional>
#include <vector>
#include <memory>
#include <cstddef>
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
	//for pretty display and order
	virtual const std::string& Name() const = 0;
	//return alert if rule triggered
	virtual std::optional<Alert> Evaluate(const ParsedPacket& packet) const = 0;
};
class Guard
{
private:
	std::vector<std::unique_ptr<IRule>> My_Rules;
public:
	void AddRule(std::unique_ptr<IRule> rule);
	bool RemoveRuleByIndex(std::size_t index); // 0 based index
	std::vector<Alert> Inspect(const ParsedPacket& packet) const;
	std::size_t RuleCount() const;
	
};