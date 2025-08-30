package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"minivpn/internal/config"
)

// Менеджер ядра sing-box: формирует корректный JSON и запускает внешний бинарь.
type SingBoxEngine struct {
	Bin     string
	RunDir  string
	CfgPath string
	LogPath string

	cmd *exec.Cmd
	mu  sync.Mutex
}

func New(runBase string) *SingBoxEngine {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		bin = "sing-box"
	}
	runDir := filepath.Join(runBase, "run")
	return &SingBoxEngine{
		Bin:     bin,
		RunDir:  runDir,
		CfgPath: filepath.Join(runDir, "singbox.json"),
		LogPath: filepath.Join(runDir, "singbox.log"),
	}
}

func (e *SingBoxEngine) StartWithProfile(p *config.Profile) error {
	cfg, err := e.renderConfig(p)
	if err != nil {
		return err
	}
	if err := e.atomicWrite(e.CfgPath, cfg); err != nil {
		return err
	}
	return e.start()
}

func (e *SingBoxEngine) ReloadProfile(p *config.Profile) error {
	cfg, err := e.renderConfig(p)
	if err != nil {
		return err
	}
	if err := e.atomicWrite(e.CfgPath, cfg); err != nil {
		return err
	}
	if err := e.stop(5 * time.Second); err != nil {
		return err
	}
	return e.start()
}

func (e *SingBoxEngine) Stop() error {
	return e.stop(5 * time.Second)
}

func (e *SingBoxEngine) start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cmd != nil && e.cmd.Process != nil {
		return nil
	}
	if _, err := exec.LookPath(e.Bin); err != nil {
		return fmt.Errorf("sing-box not found: %w", err)
	}
	_ = os.MkdirAll(e.RunDir, 0o755)
	logf, err := os.OpenFile(e.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(e.Bin, "run", "-c", e.CfgPath)
	cmd.Stdout = logf
	cmd.Stderr = logf
	if runtime.GOOS == "windows" {
		// опционально: скрыть окно
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	e.cmd = cmd
	return nil
}

func (e *SingBoxEngine) stop(timeout time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cmd == nil || e.cmd.Process == nil {
		return nil
	}
	_ = e.cmd.Process.Signal(os.Interrupt)
	t0 := time.Now()
	for time.Since(t0) < timeout {
		if e.cmd.ProcessState != nil && e.cmd.ProcessState.Exited() {
			e.cmd = nil
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = e.cmd.Process.Kill()
	e.cmd = nil
	return nil
}

func (e *SingBoxEngine) atomicWrite(path string, data []byte) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Генерация конфига sing-box с правильным синтаксисом TUN/REALITY/selector/правил.
func (e *SingBoxEngine) renderConfig(p *config.Profile) ([]byte, error) {
	if p == nil {
		return nil, errors.New("profile is nil")
	}
	var outbounds []map[string]any
	var chain []string

	// VLESS + REALITY
	if p.Protocol == "vless-reality" && p.Reality != nil {
		host := p.Reality.Server
		if p.CNAMEEndpoint != "" {
			host = p.CNAMEEndpoint
		}
		vless := map[string]any{
			"type":            "vless",
			"tag":             "vless-primary",
			"server":          host,
			"server_port":     p.Reality.Port,
			"uuid":            p.Reality.UserID,
			"flow":            p.Reality.Flow,
			"packet_encoding": "xudp",
			"transport":       map[string]any{"type": "tcp"},
			"tls": map[string]any{
				"enabled":     true,
				"server_name": coalesce(p.TLSServerName, p.Reality.SNI, host),
				"alpn":        nonEmpty(p.TLSALPN, []string{"h2", "http/1.1"}),
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": p.Reality.PublicKey,
					"short_id":   p.Reality.ShortID,
				},
			},
		}
		outbounds = append(outbounds, vless)
		chain = append(chain, "vless-primary")
	}

	// Shadowsocks (fallback)
	if p.Shadowsocks != nil && p.Shadowsocks.Server != "" {
		ss := map[string]any{
			"type":        "shadowsocks",
			"tag":         "ss-fallback",
			"server":      p.Shadowsocks.Server,
			"server_port": p.Shadowsocks.Port,
			"method":      p.Shadowsocks.Method,
			"password":    p.Shadowsocks.Password,
		}
		outbounds = append(outbounds, ss)
		chain = append(chain, "ss-fallback")
	}

	// Mesh локальные хопы — будет слушать Python demon как SOCKS
	if p.UseMesh {
		outbounds = append(outbounds,
			map[string]any{"type": "socks", "tag": "mesh-hop-1", "server": "127.0.0.1", "server_port": 28080},
			map[string]any{"type": "socks", "tag": "mesh-hop-2", "server": "127.0.0.1", "server_port": 28081},
		)
		chain = append(chain, "mesh-hop-1", "mesh-hop-2")
	}

	// Selector цепочка (управление через Clash API в будущем)
	if len(chain) == 0 {
		chain = []string{"direct"}
	}
	outbounds = append(outbounds, map[string]any{
		"type": "selector", "tag": "auto-chain",
		"default": chain, "outbounds": chain,
		"interrupt_exist_connections": false,
	})

	cfg := map[string]any{
		"log": map[string]any{"level": "info"},
		"dns": map[string]any{"servers": []any{"https://1.1.1.1/dns-query"}},
		"inbounds": []any{
			// Важно: в непривилегированном режиме адреса/MTU не задаются автоматически [10]
			map[string]any{
				"type": "tun", "tag": "tun-in",
				"interface_name": "minivpn0",
				"address":        []any{"10.10.0.2/24"},
				"mtu":            9000,
				"auto_route":     true,
				"strict_route":   true,
			},
			map[string]any{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10808, "sniff": false},
			map[string]any{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 10809},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules":                 buildRules(p.SplitApps),
		},
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildRules(apps []string) []map[string]any {
	// Правильный синтаксис process_name/process_path для headless rule [20]
	rules := []map[string]any{
		{"protocol": "dns", "outbound": "direct"},
		{"ip_cidr": []any{"10.0.0.0/8", "192.168.0.0/16"}, "outbound": "direct"},
	}
	if len(apps) > 0 {
		rules = append([]map[string]any{
			{"process_name": apps, "outbound": "auto-chain"},
		}, rules...)
	}
	return rules
}

func coalesce(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
func nonEmpty(v []string, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}
