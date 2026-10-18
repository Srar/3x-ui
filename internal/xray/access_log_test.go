package xray

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
)

const liveAccess = "2026/10/10 12:00:00.123456 from tcp:192.0.2.1:123 accepted tcp:example.com:443 [in -> out] email: alice"

func TestAccessOutputSplitLinesAndDNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	var diagnostics bytes.Buffer
	w := &accessOutput{path: path, diagnostics: &diagnostics}
	_, _ = w.Write([]byte(liveAccess[:40]))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("partial line was written")
	}
	dns := "2026/10/10 12:00:00.123456 local got answer: example.com -> [192.0.2.5] 1ms"
	_, _ = w.Write([]byte(liveAccess[40:] + "\r\n" + dns + "\n2026/10/10 12:00:00.123456 [Warning] diagnostic\n"))
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != liveAccess+"\n"+dns+"\n" {
		t.Fatalf("local log: %s", got)
	}
	if !strings.Contains(diagnostics.String(), "diagnostic") || strings.Contains(diagnostics.String(), "accepted") {
		t.Fatalf("wrong diagnostic output: %s", diagnostics.String())
	}
}

func TestAccessOutputConcurrentCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	w := &accessOutput{path: path, diagnostics: &bytes.Buffer{}}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				_, _ = w.Write([]byte(liveAccess + "\n"))
			}
		})
	}
	wg.Go(func() {
		for range 100 {
			AccessLogFileMu.Lock()
			_ = os.Truncate(path, 0)
			AccessLogFileMu.Unlock()
		}
	})
	wg.Wait()
	_, _ = w.Write([]byte(liveAccess + "\n"))
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line != liveAccess {
			t.Fatalf("torn line: %q", line)
		}
	}
}

func TestCaptureConfigRequiresRestartAndPreservesPath(t *testing.T) {
	original := json_util.RawMessage(`{"access":"/tmp/access.log","loglevel":"warning","maskAddress":"half"}`)
	a := &Config{LogConfig: original}
	b := *a
	b.AccessLogCapture = true
	if a.Equals(&b) {
		t.Fatal("capture switch considered equal")
	}
	if _, hot := ComputeHotDiff(a, &b); hot {
		t.Fatal("capture switch allowed hot apply")
	}
	data, err := b.runtimeJSON()
	if err != nil {
		t.Fatal(err)
	}
	var runtime map[string]any
	if err = json.Unmarshal(data, &runtime); err != nil {
		t.Fatal(err)
	}
	log := runtime["log"].(map[string]any)
	if log["access"] != "" || log["maskAddress"] != "half" {
		t.Fatalf("wrong runtime config: %v", log)
	}
	if b.accessFile() != "/tmp/access.log" || !bytes.Equal(b.LogConfig, original) {
		t.Fatal("original path mutated")
	}
	if _, ok := runtime["AccessLogCapture"]; ok {
		t.Fatal("panel metadata leaked")
	}
	p := newTestProcess(&b, "test.json")
	if p.config.AccessLogCapture {
		t.Fatal("test process captures access events")
	}
}

func TestAccessPathReportsCapturedLocalFile(t *testing.T) {
	old := capturedAccessLogPath()
	defer setCapturePath(old)
	setCapturePath("/tmp/panel-access.log")
	path, err := GetAccessLogPath()
	if err != nil || path != "/tmp/panel-access.log" {
		t.Fatalf("path = %q, %v", path, err)
	}
	// Invalid output must not poison the next record or allocate without limit.
	w := &accessOutput{path: filepath.Join(t.TempDir(), "access.log"), diagnostics: &bytes.Buffer{}}
	_, _ = w.Write([]byte(strings.Repeat("x", maxOutputLine+1) + "\n" + liveAccess + "\n"))
	contents, err := os.ReadFile(w.path)
	if err != nil || string(contents) != liveAccess+"\n" {
		t.Fatalf("recovery failed: %s %v", contents, err)
	}
}

func TestParseAccessEntryMissingAndRejected(t *testing.T) {
	entry := accesslog.Parse("2026/10/10 12:00:00.123456 from tcp:192.0.2.1:123 rejected tcp:example.com:443")
	if entry.DateTime == nil || entry.ToAddress != "tcp:example.com:443" || entry.Email != "" {
		t.Fatalf("wrong rejection: %+v", entry)
	}
}

// This uses the same optional binary convention as the other Xray API tests.
func TestAccessOutputLiveXray(t *testing.T) {
	for _, mode := range []struct {
		name      string
		localFile bool
	}{{"local-file-and-syslog", true}, {"syslog-only", false}} {
		t.Run(mode.name, func(t *testing.T) { testAccessOutputLiveXray(t, mode.localFile) })
	}
}

func testAccessOutputLiveXray(t *testing.T, localFile bool) {
	binary := os.Getenv("XRAY_E2E_BINARY")
	if binary == "" {
		t.Skip("set XRAY_E2E_BINARY to run live access-log delivery")
	}
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	accesslog.Configure(accesslog.Config{Enabled: true, Protocol: "udp", Host: "127.0.0.1", Port: receiver.LocalAddr().(*net.UDPAddr).Port})
	defer accesslog.Configure(accesslog.DefaultConfig())
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := freePort(t)
	dir := t.TempDir()
	t.Chdir(dir)
	logPath := filepath.Join(dir, "access.log")
	localPath := logPath
	if !localFile {
		localPath = "none"
	}
	logConfig, err := json.Marshal(map[string]any{"access": localPath, "loglevel": "warning"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{AccessLogCapture: true, LogConfig: json_util.RawMessage(logConfig)}
	inbound, _ := json.Marshal([]map[string]any{{"listen": "127.0.0.1", "port": port, "protocol": "tunnel", "tag": "in", "settings": map[string]any{"rewriteAddress": "127.0.0.1", "rewritePort": target.Addr().(*net.TCPAddr).Port, "allowedNetwork": "tcp"}}})
	outbound := json_util.RawMessage(`[{"protocol":"freedom","tag":"out"}]`)
	// Config's inbound type is already the shape consumed by the process.
	if err = json.Unmarshal(inbound, &cfg.InboundConfigs); err != nil {
		t.Fatal(err)
	}
	cfg.OutboundConfigs = outbound
	data, err := cfg.runtimeJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &accessOutput{path: cfg.accessFile(), diagnostics: NewLogWriter()}
	cmd := exec.Command(binary, "-c", path)
	cmd.Stdout = writer
	cmd.Stderr = NewLogWriter()
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	waitForPort(t, port)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = receiver.SetReadDeadline(time.Now().Add(5 * time.Second))
	packet := make([]byte, 65535)
	n, _, err := receiver.ReadFrom(packet)
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.IndexByte(packet[:n], '{')
	if start < 0 {
		t.Fatal("missing syslog JSON")
	}
	var entry accesslog.Entry
	if err = json.Unmarshal(packet[start:n], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Inbound != "in" || entry.Outbound != "out" || !strings.Contains(entry.ToAddress, strconv.Itoa(target.Addr().(*net.TCPAddr).Port)) {
		t.Fatalf("unexpected live event: %+v", entry)
	}
	if localFile {
		deadline := time.Now().Add(time.Second)
		for {
			local, err := os.ReadFile(logPath)
			if err == nil && strings.Contains(string(local), entry.Raw) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("live record not in local log: %s, %v", local, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	} else {
		writer.mu.Lock()
		fileWarning := !writer.lastFileWarning.IsZero()
		writer.mu.Unlock()
		if fileWarning {
			t.Fatal("disabled local file caused a write warning")
		}
		for _, path := range []string{logPath, "none"} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("syslog-only mode created %s: %v", path, err)
			}
		}
	}
	// Rebinding the sender models a panel-only restart while Xray and its writer
	// continue running; the next event must go to the replacement destination.
	replacement, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	accesslog.Configure(accesslog.Config{Enabled: true, Protocol: "udp", Host: "127.0.0.1", Port: replacement.LocalAddr().(*net.UDPAddr).Port})
	conn, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = replacement.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err = replacement.ReadFrom(packet); err != nil {
		t.Fatalf("replacement sender missed live record: %v", err)
	}
}

func TestAccessOutputDeliversWhenLocalFileFails(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	accesslog.Configure(accesslog.Config{Enabled: true, Protocol: "udp", Host: "127.0.0.1", Port: receiver.LocalAddr().(*net.UDPAddr).Port})
	defer accesslog.Configure(accesslog.DefaultConfig())
	w := &accessOutput{path: filepath.Join(t.TempDir(), "missing", "access.log"), diagnostics: &bytes.Buffer{}}
	_, _ = w.Write([]byte(liveAccess + "\n"))
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	packet := make([]byte, 65535)
	n, _, err := receiver.ReadFrom(packet)
	if err != nil {
		t.Fatalf("local file failure suppressed syslog: %v", err)
	}
	start := bytes.IndexByte(packet[:n], '{')
	if start < 0 {
		t.Fatal("missing JSON")
	}
	var entry accesslog.Entry
	if err := json.Unmarshal(packet[start:n], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Raw != liveAccess {
		t.Fatalf("wrong record: %+v", entry)
	}
}

func TestCaptureConfigWithoutLocalFile(t *testing.T) {
	for _, log := range []json_util.RawMessage{nil, json_util.RawMessage(`null`), json_util.RawMessage(`{}`), json_util.RawMessage(`{"access":"none","loglevel":"warning"}`), json_util.RawMessage(`{"access":""}`)} {
		cfg := &Config{AccessLogCapture: true, LogConfig: log}
		data, err := cfg.runtimeJSON()
		if err != nil {
			t.Fatal(err)
		}
		var runtime struct {
			Log struct {
				Access string `json:"access"`
			} `json:"log"`
		}
		if err := json.Unmarshal(data, &runtime); err != nil {
			t.Fatal(err)
		}
		if runtime.Log.Access != "" || cfg.accessFile() != "none" {
			t.Fatalf("unexpected syslog-only config: %s", data)
		}
	}
	old := capturedAccessLogPath()
	defer setCapturePath(old)
	setCapturePath("none")
	path, err := GetAccessLogPath()
	if err != nil || path != "none" {
		t.Fatalf("local access logs still enabled: %q %v", path, err)
	}
}
