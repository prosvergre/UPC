package checker_test

import (
	"testing"
	"time"

	"proxycheck/internal/checker"
	"proxycheck/internal/ssuri"
)

// Полная протокольная проверка DeepVerifyAll (успех/неверный пароль)
// уже сделана на уровне internal/ssclient/verify_test.go — там доступ
// к параметризованному target (нужен для теста без реального
// интернета). Здесь, на уровне checker, достаточно проверить механику
// worker pool: правильный порядок результатов и что заведомо
// недоступные сервера корректно и быстро (без зависаний) дают
// Alive=false с понятной ошибкой.
func TestDeepVerifyAllMechanics(t *testing.T) {
	servers := []ssuri.Server{
		{Host: "127.0.0.1", Port: 1, Method: "aes-256-gcm", Password: "x"},
		{Host: "127.0.0.1", Port: 2, Method: "aes-256-gcm", Password: "y"},
	}
	opts := checker.Options{Concurrency: 2, Timeout: 500 * time.Millisecond}

	results := checker.DeepVerifyAll(servers, opts, nil)
	if len(results) != 2 {
		t.Fatalf("ожидалось 2 результата, получено %d", len(results))
	}
	for i, r := range results {
		if r.Alive {
			t.Errorf("результат %d: ожидался Alive=false (недоступный сервер), получили true", i)
		}
		if r.Server.ID() != servers[i].ID() {
			t.Errorf("результат %d: порядок результатов не совпадает со входом", i)
		}
	}
}
