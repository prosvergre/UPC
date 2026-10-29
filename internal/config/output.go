// Package config сохраняет список серверов в файл: ссылками по одной в строке
// (.txt — удобно импортировать в другие клиенты) или JSON (полная модель).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"proxycheck/internal/node"
)

// Write пишет серверы в path. Для .txt — по одной исходной ссылке в строке,
// иначе — JSON-массив с полной моделью серверов.
func Write(path string, nodes []node.Node) error {
	if strings.EqualFold(filepath.Ext(path), ".txt") {
		var b strings.Builder
		for _, n := range nodes {
			if n.Raw != "" {
				b.WriteString(n.Raw)
				b.WriteByte('\n')
			}
		}
		return os.WriteFile(path, []byte(b.String()), 0o644)
	}
	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
