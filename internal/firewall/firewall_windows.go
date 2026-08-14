//go:build windows

// Package firewall управляет входящим правилом Windows Firewall для
// диапазона локальных SOCKS5-портов через netsh advfirewall — чтобы
// клиенты из локальной сети могли подключаться, не открывая вручную
// "Панель управления брандмауэром" и не плодя по правилу на каждый порт.
//
// Требует прав администратора: если процесс запущен без повышенных
// прав, netsh вернёт ошибку — мы её пробрасываем наверх, чтобы GUI мог
// показать понятное сообщение вместо тихого "ничего не произошло".
package firewall

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/text/encoding/charmap"
)

// hideWindowAttr — флаги для exec.Cmd, чтобы netsh не мигал консольным
// окном поверх нашего GUI.
var hideWindowAttr = &syscall.SysProcAttr{HideWindow: true}

// decodeConsoleOutput переводит вывод netsh из кодировки консоли Windows
// (для русской локали это обычно OEM cp866, а не UTF-8) в нормальный
// UTF-8 текст — без этого сообщения об ошибках превращались в мойбейк
// вроде "�� ���� �ࠢ��� �� ᮮ⢥������� 㪠������".
func decodeConsoleOutput(b []byte) string {
	decoded, err := charmap.CodePage866.NewDecoder().Bytes(b)
	if err != nil {
		return string(b) // не удалось раскодировать — отдаём как есть, лучше так, чем ничего
	}
	return string(decoded)
}

// isNoRulesFoundMessage проверяет, означает ли вывод netsh "правило не
// найдено" — а не настоящую ошибку выполнения команды. netsh выводит
// это сообщение на языке локали Windows, поэтому проверяем и
// английский, и русский варианты (при необходимости легко добавить ещё).
func isNoRulesFoundMessage(text string) bool {
	lower := strings.ToLower(text)
	if strings.Contains(lower, "no rules match") {
		return true
	}
	if strings.Contains(lower, "не найдено") && strings.Contains(lower, "правил") {
		return true
	}
	return false
}

// EnsureInboundRule создаёт (или обновляет, если диапазон изменился)
// одно входящее правило TCP для указанного диапазона портов. Если
// правило с таким именем уже существует с тем же диапазоном — ничего
// не делает.
func EnsureInboundRule(ruleName string, startPort, endPort int) error {
	if startPort <= 0 || endPort < startPort {
		return fmt.Errorf("некорректный диапазон портов: %d-%d", startPort, endPort)
	}
	portRange := fmt.Sprintf("%d-%d", startPort, endPort)

	exists, currentRange, err := ruleInfo(ruleName)
	if err != nil {
		return fmt.Errorf("проверка существующего правила: %w", err)
	}
	if exists && currentRange == portRange {
		return nil // уже настроено ровно на этот диапазон, ничего делать не нужно
	}
	if exists {
		if err := RemoveInboundRule(ruleName); err != nil {
			return fmt.Errorf("удаление устаревшего правила перед пересозданием: %w", err)
		}
	}

	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=in",
		"action=allow",
		"protocol=TCP",
		fmt.Sprintf("localport=%s", portRange),
	)
	cmd.SysProcAttr = hideWindowAttr
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh advfirewall add rule: %w (вывод: %s) — возможно, нужны права администратора", err, strings.TrimSpace(decodeConsoleOutput(out)))
	}
	return nil
}

// RemoveInboundRule удаляет правило по имени (если оно существует).
func RemoveInboundRule(ruleName string) error {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName))
	cmd.SysProcAttr = hideWindowAttr
	out, err := cmd.CombinedOutput()
	if err != nil {
		decodedOut := decodeConsoleOutput(out)
		if isNoRulesFoundMessage(decodedOut) {
			return nil
		}
		return fmt.Errorf("netsh advfirewall delete rule: %w (вывод: %s)", err, strings.TrimSpace(decodedOut))
	}
	return nil
}

// ruleInfo проверяет, существует ли правило, и если да — какой у него
// диапазон портов (в формате "start-end"), разбирая вывод
// `netsh advfirewall firewall show rule name=... verbose`.
func ruleInfo(ruleName string) (exists bool, portRange string, err error) {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule",
		fmt.Sprintf("name=%s", ruleName), "verbose")
	cmd.SysProcAttr = hideWindowAttr
	out, err := cmd.CombinedOutput()
	text := decodeConsoleOutput(out)
	if err != nil {
		if isNoRulesFoundMessage(text) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("%w (вывод: %s)", err, strings.TrimSpace(text))
	}
	if isNoRulesFoundMessage(text) {
		return false, "", nil
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "localport:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return true, strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return true, "", nil // правило нашлось, но формат вывода не распознали — считаем "есть, диапазон неизвестен"
}
