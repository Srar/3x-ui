package service

import (
	"encoding/json"
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const accessLogSyslogKey = "accessLogSyslog"

func (s *SettingService) GetAccessLogSyslog() (accesslog.Config, error) {
	c := accesslog.DefaultConfig()
	raw, err := s.getString(accessLogSyslogKey)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal([]byte(raw), &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func validateAccessLogSyslogTemplate(template string, c accesslog.Config) error {
	if !c.Enabled {
		return nil
	}
	var cfg struct {
		Log struct {
			Level string `json:"loglevel"`
		} `json:"log"`
	}
	if err := json.Unmarshal([]byte(template), &cfg); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Log.Level), "none") {
		return errors.New("syslog requires Xray log level other than none")
	}
	return nil
}

// SaveXraySettings stores the entire page atomically; a missing syslog field
// preserves the saved configuration for older clients.
func (s *XraySettingService) SaveXraySettings(template, testURL string, supplied *accesslog.Config) (accesslog.Config, error) {
	c := accesslog.DefaultConfig()
	var err error
	if supplied != nil {
		c = *supplied
	} else {
		c, err = s.GetAccessLogSyslog()
		if err != nil {
			return c, err
		}
	}
	if err = c.Validate(); err != nil {
		return c, err
	}
	prepared, err := s.prepareXraySetting(template)
	if err != nil {
		return c, err
	}
	if err = validateAccessLogSyslogTemplate(prepared, c); err != nil {
		return c, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	if testURL == "" {
		testURL = "https://www.google.com/generate_204"
	}
	testURL, err = SanitizeHTTPURL(testURL)
	if err != nil {
		return c, err
	}
	err = database.GetDB().Transaction(func(tx *gorm.DB) error {
		for _, value := range []model.Setting{
			{Key: "xrayTemplateConfig", Value: prepared},
			{Key: "xrayOutboundTestUrl", Value: testURL},
			{Key: accessLogSyslogKey, Value: string(raw)},
		} {
			var existing model.Setting
			err := tx.Where("key = ?", value.Key).First(&existing).Error
			if database.IsNotFound(err) {
				if err = tx.Create(&value).Error; err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else {
				if err = tx.Model(&model.Setting{}).Where("key = ?", value.Key).Update("value", value.Value).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
	return c, err
}
