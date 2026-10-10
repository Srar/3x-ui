package xray

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// AccessLogFileMu serializes panel-owned access-log appends and truncation.
var AccessLogFileMu sync.Mutex
var capturePath struct {
	sync.RWMutex
	path string
}

func setCapturePath(path string) { capturePath.Lock(); capturePath.path = path; capturePath.Unlock() }
func capturedAccessLogPath() string {
	capturePath.RLock()
	defer capturePath.RUnlock()
	return capturePath.path
}

// runtimeJSON preserves the configured file path in the panel's snapshot while
// making the child emit access records to stdout. No panel fields reach Xray.
func (c *Config) runtimeJSON() ([]byte, error) {
	snapshot := *c
	if c.AccessLogCapture {
		var log map[string]any
		if len(c.LogConfig) != 0 {
			if err := json.Unmarshal(c.LogConfig, &log); err != nil {
				return nil, err
			}
		}
		if log == nil {
			log = make(map[string]any)
		}
		log["access"] = ""
		data, err := json.Marshal(log)
		if err != nil {
			return nil, err
		}
		snapshot.LogConfig = data
	}
	return json.MarshalIndent(&snapshot, "", "  ")
}
func (c *Config) accessFile() string {
	var log struct {
		Access string `json:"access"`
	}
	_ = json.Unmarshal(c.LogConfig, &log)
	path := strings.TrimSpace(log.Access)
	if path == "" || strings.EqualFold(path, "none") {
		return "none"
	}
	return path
}

// accessOutput only consumes stdout. Stderr retains its separate diagnostic
// writer so partially written stdout records cannot mix with stderr bytes.
type accessOutput struct {
	mu              sync.Mutex
	pending         []byte
	discarding      bool
	path            string
	diagnostics     io.Writer
	lastFileWarning time.Time
}

const maxOutputLine = 256 << 10

func (w *accessOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := len(data)
	var diagnostics []byte
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		part := data
		if i >= 0 {
			part = data[:i]
		}
		if !w.discarding {
			if len(w.pending)+len(part) > maxOutputLine {
				w.pending = nil
				w.discarding = true
				logger.Warning("Xray stdout line exceeded access-log limit")
			} else {
				w.pending = append(w.pending, part...)
			}
		}
		if i < 0 {
			break
		}
		if !w.discarding {
			line := strings.TrimSuffix(string(w.pending), "\r")
			if !w.line(line) {
				diagnostics = append(diagnostics, line...)
				diagnostics = append(diagnostics, '\n')
			}
		}
		w.pending = nil
		w.discarding = false
		data = data[i+1:]
	}
	// Keep diagnostic batches together so the existing crash writer receives
	// the stack trace along with its panic line, rather than isolated lines.
	if len(diagnostics) != 0 {
		_, _ = w.diagnostics.Write(diagnostics)
	}
	return total, nil
}
func (w *accessOutput) line(line string) bool {
	fields := strings.Fields(line)
	// Xray emits timestamp + AccessMessage ("from ... accepted/rejected ...")
	// or DNSLog ("server got answer:/cache HIT:/cache OPTIMISTE: ...").
	isAccess := len(fields) >= 3 && fields[2] == "from"
	isDNS := len(fields) >= 5 && (strings.HasPrefix(strings.Join(fields[3:5], " "), "got answer:") || strings.HasPrefix(strings.Join(fields[3:5], " "), "cache HIT:") || strings.HasPrefix(strings.Join(fields[3:5], " "), "cache OPTIMISTE:"))
	if !isAccess && !isDNS {
		return false
	}
	// Enqueue before disk I/O: a local filesystem failure cannot suppress syslog.
	if isAccess {
		accesslog.Publish(line)
	}
	if strings.TrimSpace(w.path) == "" || strings.EqualFold(strings.TrimSpace(w.path), "none") {
		return true
	}
	AccessLogFileMu.Lock()
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.WriteString(line + "\n")
		_ = f.Close()
	}
	AccessLogFileMu.Unlock()
	if err != nil && time.Since(w.lastFileWarning) >= time.Minute {
		w.lastFileWarning = time.Now()
		logger.Warning("Failed to append Xray access log:", err)
	}
	return true
}
