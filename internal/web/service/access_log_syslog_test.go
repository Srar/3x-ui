package service

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestSaveXraySettingsSyslogAndLegacyClient(t *testing.T) {
	setupSettingTestDB(t)
	s := &XraySettingService{}
	template := `{"log":{"access":"./access.log","loglevel":"warning"},"inbounds":[],"outbounds":[]}`
	c := accesslog.Config{Enabled: true, Protocol: "tcp", Host: " 2001:db8::1 ", Port: 1514}
	saved, err := s.SaveXraySettings(template, "https://test.example", &c)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Host != "2001:db8::1" {
		t.Fatal("host not normalized")
	}
	actual, err := s.GetAccessLogSyslog()
	if err != nil || actual != saved {
		t.Fatalf("config = %+v, %v", actual, err)
	}
	preserved, err := s.SaveXraySettings(template, "https://changed.example", nil)
	if err != nil || preserved != saved {
		t.Fatalf("legacy save = %+v, %v", preserved, err)
	}
	// A validation error must not partially replace either template or test URL.
	if _, err = s.SaveXraySettings(strings.Replace(template, "warning", "none", 1), "https://invalid.example", nil); err == nil {
		t.Fatal("disabled log level accepted")
	}
	url, err := s.GetXrayOutboundTestUrl()
	if err != nil || url != "https://changed.example" {
		t.Fatalf("partial save: %s %v", url, err)
	}
	disabled := saved
	disabled.Enabled = false
	if _, err = s.SaveXraySettings(strings.Replace(template, "./access.log", "none", 1), url, &disabled); err != nil {
		t.Fatal(err)
	}
}

func TestSaveXraySettingsTransactionRollback(t *testing.T) {
	setupSettingTestDB(t)
	s := &XraySettingService{}
	template := `{"log":{"access":"./access.log","loglevel":"warning"},"outbounds":[]}`
	if _, err := s.SaveXraySettings(template, "https://before.example", nil); err != nil {
		t.Fatal(err)
	}
	// Force the final setting write to fail after the preceding page writes.
	db := database.GetDB()
	if err := db.Exec(`CREATE TRIGGER reject_syslog BEFORE UPDATE ON settings WHEN NEW.key = 'accessLogSyslog' BEGIN SELECT RAISE(ABORT, 'test write failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	c := accesslog.DefaultConfig()
	c.Host = "receiver.example"
	if _, err := s.SaveXraySettings(strings.Replace(template, "warning", "info", 1), "https://after.example", &c); err == nil {
		t.Fatal("expected transaction error")
	}
	var st model.Setting
	if err := db.Where("key = ?", "xrayOutboundTestUrl").First(&st).Error; err != nil {
		t.Fatal(err)
	}
	if st.Value != "https://before.example" {
		t.Fatal("transaction was not rolled back")
	}
}

func TestValidateSyslogLogConfiguration(t *testing.T) {
	c := accesslog.Config{Enabled: true, Protocol: "udp", Host: "host", Port: 514}
	for _, template := range []string{`{}`, `{"log":null}`, `{"log":{}}`, `{"log":{"access":"none"}}`, `{"log":{"access":"","loglevel":"warning"}}`} {
		if err := validateAccessLogSyslogTemplate(template, c); err != nil {
			t.Fatalf("rejected optional local log %s: %v", template, err)
		}
	}
	for _, template := range []string{`{"log":{"loglevel":"none"}}`, `{"log":{"access":"./access.log","loglevel":"NoNe"}}`} {
		if validateAccessLogSyslogTemplate(template, c) == nil {
			t.Fatalf("accepted disabled log level %s", template)
		}
	}
}

func TestSaveXraySettingsSyslogWithoutLocalFile(t *testing.T) {
	setupSettingTestDB(t)
	s := &XraySettingService{}
	c := accesslog.Config{Enabled: true, Protocol: "udp", Host: "receiver.example", Port: 514}
	for _, template := range []string{`{}`, `{"log":null}`, `{"log":{"access":"none","loglevel":"warning"}}`, `{"log":{"access":"","loglevel":"warning"}}`} {
		saved, err := s.SaveXraySettings(template, "https://test.example", &c)
		if err != nil || saved != c {
			t.Fatalf("syslog-only save: %+v, %v", saved, err)
		}
	}
}
