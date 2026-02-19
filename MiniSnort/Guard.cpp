#include "Guard.h"

void Guard::AddRule(std::unique_ptr<IRule> rule) {
	if (!rule) return; //checking if rule is empty
	My_Rules.push_back(std::move(rule)); //adding the rule
}
bool Guard::RemoveRuleByIndex(std::size_t index) {
	//true = removed , false = invalid index
	if (index >= My_Rules.size()) return false; //boundry check
	//destroy unique pointer delete the object and shift elements left
	My_Rules.erase(My_Rules.begin() + static_cast<std::ptrdiff_t>(index));
	return true;
}
std::vector<Alert> Guard::Inspect(const ParsedPacket& packet) const {
	std::vector <Alert> alerts;
	for (const auto& rule : My_Rules) {
		if (!rule) continue;
		std::optional<Alert> alert = rule->Evaluate(packet);
		if (alert) {
			alerts.push_back(*alert);
		}
	}
	return alerts;
}
std::size_t Guard::RuleCount() const {
	
	return My_Rules.size();
}