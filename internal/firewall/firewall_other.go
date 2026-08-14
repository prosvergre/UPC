//go:build !windows

// Package firewall на платформах, отличных от Windows, ничего не
// делает — там нет единого API для файрвола вроде netsh, и в рамках
// этого проекта (Windows GUI + Raspberry Pi CLI) для Linux это не
// запрашивалось.
package firewall

// EnsureInboundRule на не-Windows платформах — no-op, всегда успех.
func EnsureInboundRule(ruleName string, startPort, endPort int) error {
	return nil
}

// RemoveInboundRule на не-Windows платформах — no-op, всегда успех.
func RemoveInboundRule(ruleName string) error {
	return nil
}
