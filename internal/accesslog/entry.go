// Package accesslog receives live Xray access records and forwards them to syslog.
package accesslog

import (
	"regexp"
	"strings"
	"time"
)

var detourPattern = regexp.MustCompile(`\[([^\[\]]+) (?:->|>>) ([^\[\]]+)\]`)

// Entry contains only fields available in an Xray access-log line.
type Entry struct {
	DateTime    *time.Time `json:"DateTime"`
	FromAddress string     `json:"FromAddress"`
	ToAddress   string     `json:"ToAddress"`
	Inbound     string     `json:"Inbound"`
	Outbound    string     `json:"Outbound"`
	Email       string     `json:"Email"`
	Raw         string     `json:"Raw"`
}

// Parse tolerates truncated records and preserves their original text.
func Parse(line string) Entry {
	e := Entry{Raw: line}
	p := strings.Fields(line)
	if len(p) >= 2 {
		if t, err := time.ParseInLocation("2006/01/02 15:04:05.999999", p[0]+" "+p[1], time.Local); err == nil {
			t = t.UTC()
			e.DateTime = &t
		}
	}
	for i, v := range p {
		switch {
		case v == "from" && i+1 < len(p):
			e.FromAddress = strings.TrimLeft(p[i+1], "/")
		case (v == "accepted" || v == "rejected") && i+1 < len(p):
			e.ToAddress = strings.TrimLeft(p[i+1], "/")
		case v == "email:" && i+1 < len(p):
			e.Email = p[i+1]
		}
	}
	// Masked addresses and rejection reasons can also contain brackets; only
	// the actual detour separator identifies inbound and outbound tags.
	if tags := detourPattern.FindStringSubmatch(line); len(tags) == 3 {
		e.Inbound = tags[1]
		e.Outbound = tags[2]
	}
	return e
}
