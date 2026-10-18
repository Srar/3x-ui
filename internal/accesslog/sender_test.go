package accesslog

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testLine = "2026/10/10 12:00:00.123456 from tcp:192.0.2.1:123 accepted tcp:example.com:443 [in -> out] email: alice"

func verifyMessage(t *testing.T, msg []byte) {
	t.Helper()
	if !strings.HasPrefix(string(msg), "<134>1 ") || !strings.Contains(string(msg), " 3x-ui ") || !strings.Contains(string(msg), " access - ") {
		t.Fatalf("invalid header: %s", msg)
	}
	start := strings.IndexByte(string(msg), '{')
	if start < 0 {
		t.Fatal("missing JSON")
	}
	var e Entry
	if err := json.Unmarshal(msg[start:], &e); err != nil {
		t.Fatal(err)
	}
	if e.DateTime == nil || e.FromAddress != "tcp:192.0.2.1:123" || e.ToAddress != "tcp:example.com:443" || e.Inbound != "in" || e.Outbound != "out" || e.Email != "alice" || !strings.HasPrefix(e.Raw, testLine) {
		t.Fatalf("wrong fields: %+v", e)
	}
}

func TestUDPDeliveryAndDisable(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	Configure(Config{Enabled: true, Protocol: "udp", Host: "127.0.0.1", Port: receiver.LocalAddr().(*net.UDPAddr).Port})
	defer Configure(DefaultConfig())
	Publish(testLine)
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	verifyMessage(t, buf[:n])
	Configure(DefaultConfig())
	Publish(testLine)
	_ = receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err = receiver.ReadFrom(buf); err == nil {
		t.Fatal("disabled sender delivered a message")
	}
}

func readFrame(t *testing.T, r *bufio.Reader) []byte {
	t.Helper()
	prefix, err := r.ReadString(' ')
	if err != nil {
		t.Fatal(err)
	}
	length, err := strconv.Atoi(strings.TrimSpace(prefix))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, length)
	if _, err = io.ReadFull(r, frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestTCPFramesUseByteLengths(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	Configure(Config{Enabled: true, Protocol: "tcp", Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port})
	defer Configure(DefaultConfig())
	Publish(testLine + " 中文")
	Publish(testLine)
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)
	verifyMessage(t, readFrame(t, r))
	verifyMessage(t, readFrame(t, r))
}

func TestQueueLimitsAndMalformedRecords(t *testing.T) {
	s := &sender{wake: make(chan struct{}, 1), host: "host"}
	s.enqueue(strings.Repeat("x", maxMessageBytes))
	if len(s.queue) != 0 {
		t.Fatal("oversized message enqueued")
	}
	for range maxMessages {
		s.enqueue("truncated")
	}
	s.enqueue(testLine)
	if len(s.queue) != maxMessages {
		t.Fatal("message limit exceeded")
	}
	var entry Entry
	start := strings.IndexByte(string(s.queue[0]), '{')
	if err := json.Unmarshal(s.queue[0][start:], &entry); err != nil {
		t.Fatal(err)
	}
	if entry.DateTime != nil || entry.Raw != "truncated" {
		t.Fatal("malformed record changed")
	}
	s.queue = nil
	s.bytes = maxQueueBytes
	s.enqueue(testLine)
	if len(s.queue) != 0 {
		t.Fatal("byte limit exceeded")
	}
}

func TestRetryRetainsHeadAndCancellation(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	_ = reserved.Close()
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithCancel(context.Background())
	s := &sender{config: Config{Enabled: true, Protocol: "tcp", Host: "127.0.0.1", Port: p}, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{}), host: "host"}
	s.enqueue(testLine)
	go s.run()
	defer func() { cancel(); <-s.done }()
	// The first connection fails, but the queued record remains for the retry.
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	retained := len(s.queue)
	s.mu.Unlock()
	if retained != 1 {
		t.Fatal("failed head discarded")
	}
	receiver, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	_ = receiver.(*net.TCPListener).SetDeadline(time.Now().Add(4 * time.Second))
	conn, err := receiver.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	verifyMessage(t, readFrame(t, bufio.NewReader(conn)))
}

func TestConfigValidation(t *testing.T) {
	for _, host := range []string{"syslog.example.com", "192.0.2.1", "2001:db8::1"} {
		c := DefaultConfig()
		c.Enabled = true
		c.Host = host
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	for _, host := range []string{"", "host:514", "[::1]", "host/path", "host\nother"} {
		c := DefaultConfig()
		c.Enabled = true
		c.Host = host
		if c.Validate() == nil {
			t.Errorf("accepted invalid host %q", host)
		}
	}
}
