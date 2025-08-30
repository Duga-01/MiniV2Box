package config

import (
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

type RealitySettings struct {
	Server    string   `json:"server"`
	Port      int      `json:"port"`
	SNI       string   `json:"sni"`
	ALPN      []string `json:"alpn"`       // например ["h2","http/1.1"]
	PublicKey string   `json:"public_key"` // REALITY pub
	ShortID   string   `json:"short_id"`   // hex до 16
	Flow      string   `json:"flow"`       // xtls-rprx-vision
	UserID    string   `json:"user_id"`    // UUID
}

type ShadowsocksSettings struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type Profile struct {
	Name          string               `json:"name"`
	Protocol      string               `json:"protocol"` // "vless-reality" | "shadowsocks"
	Reality       *RealitySettings     `json:"reality,omitempty"`
	Shadowsocks   *ShadowsocksSettings `json:"shadowsocks,omitempty"`
	SplitApps     []string             `json:"split_tunnel_apps"` // process_name/app
	UseMesh       bool                 `json:"use_mesh"`
	CNAMEEndpoint string               `json:"cname_endpoint,omitempty"`
	TLSALPN       []string             `json:"tls_alpn"`
	TLSServerName string               `json:"tls_server_name,omitempty"`
	Active        bool                 `json:"is_active"`
}

type RotationPolicy struct {
	ShortIDIntervalSec int64   `json:"short_id_interval_sec"`
	LastRotated        float64 `json:"last_rotated"`
}

type AppConfig struct {
	Profiles    []Profile      `json:"profiles"`
	Rotation    RotationPolicy `json:"rotation"`
	LogsDir     string         `json:"logs_dir"`
	Version     string         `json:"version"`
	StunServers []string       `json:"stun_servers"`
	SignalURL   string         `json:"signal_url"`
	E2EEnabled  bool           `json:"e2e_enabled"`
}

var (
	cfgPath string
	mu      sync.Mutex
	hexRe   = regexp.MustCompile(`^[0-9a-fA-F]{1,16}$`)
)

func Init(path string) { cfgPath = path }

func Default(base string) AppConfig {
	return AppConfig{
		Profiles: []Profile{
			{
				Name:     "Default",
				Protocol: "vless-reality",
				Reality:  &RealitySettings{Port: 443, ALPN: []string{"h2", "http/1.1"}, Flow: "xtls-rprx-vision"},
				TLSALPN:  []string{"h2", "http/1.1"},
				Active:   true,
				UseMesh:  true,
			},
		},
		Rotation:    RotationPolicy{ShortIDIntervalSec: 3600, LastRotated: 0},
		LogsDir:     filepath.Join(base, "logs"),
		Version:     "1.0.0",
		StunServers: []string{"stun:stun.l.google.com:19302"},
		SignalURL:   "http://127.0.0.1:8787",
		E2EEnabled:  true,
	}
}

func Load(baseDir string) (AppConfig, error) {
	mu.Lock()
	defer mu.Unlock()
	if cfgPath == "" {
		cfgPath = filepath.Join(baseDir, "config.json")
	}
	_ = os.MkdirAll(baseDir, 0o755)
	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		cfg := Default(baseDir)
		if err := Save(cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return AppConfig{}, err
	}
	var cfg AppConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return AppConfig{}, err
	}
	// Нормализация ALPN
	for i := range cfg.Profiles {
		if len(cfg.Profiles[i].TLSALPN) == 0 {
			cfg.Profiles[i].TLSALPN = []string{"h2", "http/1.1"}
		}
		if cfg.Profiles[i].Reality != nil && len(cfg.Profiles[i].Reality.ALPN) == 0 {
			cfg.Profiles[i].Reality.ALPN = []string{"h2", "http/1.1"}
		}
	}
	return cfg, nil
}

func Save(cfg AppConfig) error {
	mu.Lock()
	defer mu.Unlock()
	if cfgPath == "" {
		return errors.New("config path not initialized")
	}
	tmp := cfgPath + ".tmp"
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cfgPath)
}

func ActiveProfile(cfg AppConfig) *Profile {
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Active {
			return &cfg.Profiles[i]
		}
	}
	if len(cfg.Profiles) == 0 {
		return nil
	}
	return &cfg.Profiles
}

func MaybeRotateShortID(cfg *AppConfig, pool []string) bool {
	now := time.Now().Unix()
	if now-int64(cfg.Rotation.LastRotated) < cfg.Rotation.ShortIDIntervalSec {
		return false
	}
	changed := false
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		if p.Protocol == "vless-reality" && p.Reality != nil && len(pool) > 0 {
			for tries := 0; tries < 5; tries++ {
				sid := pool[rand.Intn(len(pool))]
				if hexRe.MatchString(sid) && sid != p.Reality.ShortID {
					p.Reality.ShortID = sid
					changed = true
					break
				}
			}
		}
	}
	cfg.Rotation.LastRotated = float64(now)
	return changed
}
