package mesh

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Runner — запускает Python-демон meshd.py, который поднимает локальный SOCKS hop.
// Мы не лезем в FFI, общаемся через порт и простые текстовые сигналы ("READY <port>").
type Runner struct {
	Bin     string
	Script  string
	WorkDir string

	cmd    *exec.Cmd
	mu     sync.Mutex
	ready  bool
	port   int
	cancel context.CancelFunc
}

func NewRunner(appDir string, pythonBin string) *Runner {
	if pythonBin == "" {
		if runtime.GOOS == "windows" { pythonBin = "python" } else { pythonBin = "python3" }
	}
	return &Runner{
		Bin:     pythonBin,
		Script:  filepath.Join(appDir, "meshd.py"),
		WorkDir: appDir,
	}
}

func (r *Runner) Start(stunCSV, signalURL string, listenPort int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	args := []string{r.Script, "--stun", stunCSV, "--signal", signalURL, "--listen",  // READY печатает listenPort
		strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll("", "", ""))), "", ""))), "", ""))), "", ""))), "", ""))), "", ""))),}
	// проще: args := []string{r.Script, "--stun", stunCSV, "--signal", signalURL, "--listen", fmt.Sprint(listenPort)}

	cmd := exec.CommandContext(ctx, r.Bin, r.Script, "--stun", stunCSV, "--signal", signalURL, "--listen",  // см. выше
		// strconv.Itoa(listenPort)
	)
	cmd.Dir = r.WorkDir
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil { return err }
	r.cmd = cmd

	readyCh := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			// Ждём "READY 28080"
			if strings.HasPrefix(line, "READY ") {
				r.ready = true
				close(readyCh)
			}
			_ = line
		}
	}()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() { _ = sc.Text() }
	}()

	select {
	case <-readyCh:
		return nil
	case <-time.After(8 * time.Second):
		_ = r.Stop()
		return errors.New("mesh daemon not ready")
	}
}

func (r *Runner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil { r.cancel() }
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
		r.cmd = nil
	}
	r.ready = false
	return nil
}

func (r *Runner) Ready() bool {
	r.mu.Lock(); defer r.mu.Unlock()
	return r.ready
}
