package gui

import (
	"context"
	"path/filepath"

	"minivpn/internal/config"
	"minivpn/internal/engine"
	"minivpn/internal/mesh"
)

// App — слой между GUI и движком: загрузка/сохранение конфигов, запуск/останов ядра и mesh демона.
type App struct {
	ctx    context.Context
	base   string
	cfg    config.AppConfig
	engine *engine.SingBoxEngine
	mesh   *mesh.Runner
}

func NewApp() *App { return &App{} }

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.base = "." // можно заменить на пользовательский каталог
	config.Init(filepath.Join(a.base, "app"))
	cfg, _ := config.Load(filepath.Join(a.base, "app"))
	a.cfg = cfg
	a.engine = engine.New(filepath.Join(a.base, "app"))
	a.mesh = mesh.NewRunner(filepath.Join(a.base, "app"), "")
}

func (a *App) Shutdown(ctx context.Context) { _ = a.engine.Stop(); _ = a.mesh.Stop() }

func (a *App) GetConfig() (config.AppConfig, error) { return a.cfg, nil }

func (a *App) SaveConfig(cfg config.AppConfig) error {
	a.cfg = cfg
	return config.Save(cfg)
}

func (a *App) Connect() error {
	p := config.ActiveProfile(a.cfg)
	if p == nil {
		return nil
	}
	// Запускаем mesh, если включён
	if p.UseMesh {
		stunCSV := "stun:stun.l.google.com:19302"
		if len(a.cfg.StunServers) > 0 {
			stunCSV = a.cfg.StunServers
		}
		_ = a.mesh.Start(stunCSV, a.cfg.SignalURL, 28080)
	}
	// Запускаем sing-box
	return a.engine.StartWithProfile(p)
}

func (a *App) Disconnect() error {
	_ = a.engine.Stop()
	_ = a.mesh.Stop()
	return nil
}

func (a *App) ApplyProfileAndReload(p config.Profile) error {
	// обновляем профиль и мягко перезапускаем sing-box
	for i := range a.cfg.Profiles {
		if a.cfg.Profiles[i].Name == p.Name {
			a.cfg.Profiles[i] = p
			break
		}
	}
	_ = config.Save(a.cfg)
	if p.UseMesh {
		stunCSV := "stun:stun.l.google.com:19302"
		if len(a.cfg.StunServers) > 0 {
			stunCSV = a.cfg.StunServers
		}
		_ = a.mesh.Start(stunCSV, a.cfg.SignalURL, 28080)
	} else {
		_ = a.mesh.Stop()
	}
	return a.engine.ReloadProfile(&p)
}
