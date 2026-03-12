package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the configuration values for flagrep
type Config struct {
	Recursive        bool     `json:"recursive"`
	IgnoreCase       bool     `json:"ignore_case"`
	Workers          int      `json:"workers"`
	Depth            int      `json:"depth"`
	MaxBytes         int64    `json:"max_bytes"`
	Verbose          bool     `json:"verbose"`
	Context          int      `json:"context"`
	BeforeContext    int      `json:"before_context"`
	AfterContext     int      `json:"after_context"`
	UseRegex         bool     `json:"use_regex"`
	JSONOutput       bool     `json:"json_output"`
	ExcludeDirs      []string `json:"exclude_dirs"`
	EntropyThreshold float64  `json:"entropy_threshold"`
	MagicFilter      []string `json:"magic_filter"`
	TUIMode          bool     `json:"tui_mode"`
	InspectMode      bool     `json:"inspect_mode"`
	InspectStrings   int      `json:"inspect_strings"`
	InspectUnicode   int      `json:"inspect_unicode_strings"`
	InspectHeatmap   bool     `json:"inspect_heatmap"`
	YaraRuleFile     string   `json:"yara_rule_file"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Recursive:        false,
		Workers:          10,
		Depth:            2,
		MaxBytes:         32 << 20,
		BeforeContext:    10,
		AfterContext:     30,
		ExcludeDirs:      []string{".git", "node_modules", "__pycache__", ".venv", "venv"},
		EntropyThreshold: 0,
		MagicFilter:      nil,
		InspectStrings:   5,
		InspectUnicode:   3,
	}
}

// LoadConfig loads the configuration from standard locations
func LoadConfig() (*Config, error) {
	config := DefaultConfig()

	path := FindConfigFile()
	if path == "" {
		return config, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("could not open config file: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return config, fmt.Errorf("could not decode config file: %w", err)
	}

	return config, nil
}

// FindConfigFile looks for a config file in standard locations
func FindConfigFile() string {
	if _, err := os.Stat(".flagreprc"); err == nil {
		return ".flagreprc"
	}
	if _, err := os.Stat(".flagrep.json"); err == nil {
		return ".flagrep.json"
	}

	home, err := os.UserHomeDir()
	if err == nil {
		paths := []string{
			filepath.Join(home, ".flagreprc"),
			filepath.Join(home, ".flagrep.json"),
			filepath.Join(home, ".config", "flagrep", "config.json"),
		}

		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	return ""
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// CreateSampleConfig creates a sample configuration file
func CreateSampleConfig(path string) error {
	config := DefaultConfig()
	config.ExcludeDirs = append(config.ExcludeDirs, "dist", "build")

	return SaveConfig(config, path)
}
