// Package settings хранит и загружает пользовательские настройки GUI
// между запусками программы — отдельно от proxies.json (который это
// просто экспорт для shadowsocks-rust). Файл settings.json лежит рядом
// с исполняемым файлом.
//
// Каждый "профиль" — это один сервер, которому назначен свой локальный
// порт; при следующем запуске программы включённые (Enabled) профили
// автоматически поднимаются как рабочие прокси.
package settings

import (
	"encoding/json"
	"os"
	"path/filepath"

	"proxycheck/internal/node"
)

// Profile — один сохранённый сервер-профиль.
type Profile struct {
	ID                int       `json:"id"`
	Server            node.Node `json:"server"`
	LocalPort         int       `json:"local_port"`          // желаемый порт (может быть переназначен при занятости)
	Enabled           bool      `json:"enabled"`             // поднимать ли прокси автоматически при старте программы
	HealthIntervalSec int       `json:"health_interval_sec"` // 0 = использовать значение по умолчанию
}

// Settings — корневая структура файла настроек.
type Settings struct {
	Profiles []Profile `json:"profiles"`

	// LastScanServers — полный список серверов из последнего скана
	// (и живых, и мёртвых на момент скана) — чтобы при следующем
	// запуске сразу показать таблицу, не дожидаясь нового скана.
	LastScanServers []ScanRow `json:"last_scan_servers"`

	NextProfileID int `json:"next_profile_id"`

	// DefaultHealthIntervalSec — интервал health-проверки по умолчанию
	// для профилей, у которых HealthIntervalSec == 0.
	DefaultHealthIntervalSec int `json:"default_health_interval_sec"`

	// StartPort — стартовый локальный порт для новых прокси (по
	// умолчанию 1080). Настраивается в GUI.
	StartPort int `json:"start_port"`

	// StartMinimized — если true, GUI при следующем запуске сразу
	// сворачивается в трей вместо показа окна (настраивается галочкой
	// в самом GUI, не только флагом командной строки).
	StartMinimized bool `json:"start_minimized"`

	// DetectExitIP — определять выходящий IP-адрес для каждого живого
	// сервера (дополнительный лёгкий запрос после глубокой проверки).
	DetectExitIP bool `json:"detect_exit_ip"`

	// Bookmarks — избранные сервера с комментариями (отдельная вкладка).
	Bookmarks []Bookmark `json:"bookmarks"`

	// LocalDNSEnabled — поднимать локальный DNS-резолвер (UDP:53),
	// резолвящий через один из запущенных прокси.
	LocalDNSEnabled bool `json:"local_dns_enabled"`

	// WebListen — адрес веб-интерфейса (по умолчанию 127.0.0.1:8080).
	// WebPasswordHash — bcrypt-хеш пароля; обязателен для нелокального адреса.
	WebListen       string `json:"web_listen,omitempty"`
	WebPasswordHash string `json:"web_password_hash,omitempty"`
}

// Bookmark — избранный сервер с комментарием пользователя. Хранится
// отдельно от LastScanServers/Profiles — закладки переживают любые
// сканы и не теряются, даже если сервер перестал появляться в
// источниках.
type Bookmark struct {
	Server  node.Node `json:"server"`
	Comment string    `json:"comment"`
}

// ScanRow — сохранённая строка результата скана (сервер + был ли жив
// + задержка на момент сохранения — это снимок, не гарантия текущего
// состояния; при следующем запуске рекомендуется точечно
// перепроверить хотя бы Enabled-профили).
type ScanRow struct {
	Server          node.Node `json:"server"`
	Alive           bool      `json:"alive"`            // оставлено для обратной совместимости со старыми settings.json
	Status          string    `json:"status,omitempty"` // "alive" / "dead" / "died" / "" (неизвестно) — полная версия Alive, с учётом "умер"
	LatencyMs       int64     `json:"latency_ms"`
	Selected        bool      `json:"selected"`
	ExitIP          string    `json:"exit_ip,omitempty"`
	ExitIPAttempted bool      `json:"exit_ip_attempted,omitempty"`

	// SpeedMbps/UlSpeedMbps — последний замеренный результат скорости
	// (скачивание/отдача). Done=true значит замер удался (Mbps валиден);
	// Attempted=true значит попытка вообще была (нужно для различения
	// "не мерили ни разу" от "мерили, но не получилось" в интерфейсе).
	// При загрузке восстанавливаем оба состояния, чтобы после
	// перезапуска не приходилось мерить заново.
	SpeedMbps        float64 `json:"speed_mbps,omitempty"`
	SpeedDone        bool    `json:"speed_done,omitempty"`
	SpeedAttempted   bool    `json:"speed_attempted,omitempty"`
	UlSpeedMbps      float64 `json:"ul_speed_mbps,omitempty"`
	UlSpeedDone      bool    `json:"ul_speed_done,omitempty"`
	UlSpeedAttempted bool    `json:"ul_speed_attempted,omitempty"`
	Pinned           bool    `json:"pinned,omitempty"` // добавлен вручную: не удаляется при проверке
}

// DefaultPath возвращает путь к settings.json рядом с исполняемым
// файлом программы (а не в текущей рабочей директории — так поведение
// предсказуемо независимо от того, откуда программу запустили).
func DefaultPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "settings.json" // резервный вариант — рабочая директория
	}
	dir := filepath.Dir(exe)
	return filepath.Join(dir, "settings.json")
}

// Load читает настройки из path. Если файла нет — возвращает пустые
// Settings и nil-ошибку (это штатная ситуация при первом запуске).
func Load(path string) (Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Settings{DefaultHealthIntervalSec: 20, StartPort: 1080}, nil
		}
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, err
	}
	if s.DefaultHealthIntervalSec <= 0 {
		s.DefaultHealthIntervalSec = 20
	}
	if s.StartPort <= 0 {
		s.StartPort = 1080
	}
	return s, nil
}

// Save записывает настройки в path (человекочитаемый JSON с отступами).
func Save(path string, s Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path) // атомарная замена — не оставит битый файл при сбое
}
