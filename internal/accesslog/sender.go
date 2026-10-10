package accesslog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// Config is panel-owned configuration, never part of the Xray JSON template.
type Config struct {
	Enabled  bool   `json:"enabled"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

func DefaultConfig() Config { return Config{Protocol: "udp", Port: 514} }
func (c *Config) Validate() error {
	c.Host = strings.TrimSpace(c.Host)
	if c.Protocol != "udp" && c.Protocol != "tcp" {
		return errors.New("syslog protocol must be udp or tcp")
	}
	if !c.Enabled {
		return nil
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("syslog port must be between 1 and 65535")
	}
	if c.Host == "" {
		return errors.New("syslog receiver host is required")
	}
	if strings.ContainsAny(c.Host, " \t\r\n/[]") {
		return errors.New("syslog host must be a hostname or IP address without a port")
	}
	if strings.Contains(c.Host, ":") && net.ParseIP(c.Host) == nil {
		return errors.New("invalid syslog IPv6 address")
	}
	return nil
}

const maxMessages = 4096
const maxQueueBytes = 32 << 20
const maxMessageBytes = 60 << 10

type sender struct {
	config      Config
	mu          sync.Mutex
	queue       [][]byte
	bytes       int
	wake        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	host        string
	lastWarning time.Time
}

var manager struct {
	sync.RWMutex
	current *sender
}

// Configure replaces the sender without retaining the old destination's queue.
func Configure(c Config) {
	manager.Lock()
	old := manager.current
	if old != nil && old.config == c {
		manager.Unlock()
		return
	}
	manager.current = nil
	if c.Enabled {
		ctx, cancel := context.WithCancel(context.Background())
		hostname, _ := os.Hostname()
		hostname = headerToken(hostname, 255)
		s := &sender{config: c, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1), host: hostname}
		manager.current = s
		go s.run()
	}
	manager.Unlock()
	if old != nil {
		old.cancel()
		<-old.done
	}
}

// Stop gives queued messages a bounded chance to drain, then releases the sender.
func Stop() {
	manager.Lock()
	s := manager.current
	manager.current = nil
	manager.Unlock()
	if s == nil {
		return
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		empty := len(s.queue) == 0
		s.mu.Unlock()
		if empty {
			break
		}
		select {
		case <-deadline.C:
			s.cancel()
			<-s.done
			return
		case <-ticker.C:
		}
	}
	s.cancel()
	<-s.done
}

// Publish never waits for the network. The queue retains the current failed head.
func Publish(line string) {
	if strings.Contains(line, "api -> api") {
		return
	}
	manager.RLock()
	s := manager.current
	if s != nil {
		s.enqueue(line)
	}
	manager.RUnlock()
}
func headerToken(v string, max int) string {
	v = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return '_'
		}
		return r
	}, v)
	if v == "" {
		return "-"
	}
	if len(v) > max {
		return v[:max]
	}
	return v
}
func (s *sender) enqueue(line string) {
	entry := Parse(line)
	body, err := json.Marshal(entry)
	if err != nil {
		return
	}
	timestamp := "-"
	if entry.DateTime != nil {
		timestamp = entry.DateTime.Format("2006-01-02T15:04:05.999999Z07:00")
	}
	msg := []byte(fmt.Sprintf("<134>1 %s %s 3x-ui %d access - %s", timestamp, s.host, os.Getpid(), body))
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(msg) > maxMessageBytes || len(s.queue) >= maxMessages || s.bytes+len(msg) > maxQueueBytes {
		s.warnLocked("access syslog message dropped: message or queue limit exceeded")
		return
	}
	s.queue = append(s.queue, msg)
	s.bytes += len(msg)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *sender) warnLocked(message string) {
	if time.Since(s.lastWarning) >= time.Minute {
		s.lastWarning = time.Now()
		logger.Warning(message)
	}
}
func (s *sender) run() {
	defer close(s.done)
	var conn net.Conn
	var stopClose func() bool
	defer func() {
		if stopClose != nil {
			stopClose()
		}
		if conn != nil {
			_ = conn.Close()
		}
	}()
	backoff := time.Second
	for {
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		var msg []byte
		if len(s.queue) > 0 {
			msg = s.queue[0]
		}
		s.mu.Unlock()
		if msg == nil {
			select {
			case <-s.ctx.Done():
				return
			case <-s.wake:
			}
			continue
		}
		var err error
		if conn == nil {
			conn, err = (&net.Dialer{Timeout: 2 * time.Second}).DialContext(s.ctx, s.config.Protocol, net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port)))
			if err == nil {
				current := conn
				stopClose = context.AfterFunc(s.ctx, func() { _ = current.Close() })
			}
		}
		if err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			frame := msg
			if s.config.Protocol == "tcp" {
				frame = append([]byte(strconv.Itoa(len(msg))+" "), msg...)
			}
			var n int
			n, err = conn.Write(frame)
			if err == nil && n != len(frame) {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			if stopClose != nil {
				stopClose()
				stopClose = nil
			}
			if conn != nil {
				_ = conn.Close()
				conn = nil
			}
			s.mu.Lock()
			s.warnLocked("access syslog delivery failed: " + err.Error())
			s.mu.Unlock()
			timer := time.NewTimer(backoff)
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		s.mu.Lock()
		s.bytes -= len(s.queue[0])
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.mu.Unlock()
		backoff = time.Second
	}
}
