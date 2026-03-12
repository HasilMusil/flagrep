package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFromLocalFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flagrep_config_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalWD)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	config := DefaultConfig()
	config.MaxBytes = 2048
	config.InspectMode = true
	config.InspectStrings = 7
	config.YaraRuleFile = "rules.json"

	if err := SaveConfig(config, ".flagrep.json"); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.MaxBytes != 2048 {
		t.Fatalf("expected MaxBytes 2048, got %d", loaded.MaxBytes)
	}
	if !loaded.InspectMode {
		t.Fatal("expected InspectMode to be true")
	}
	if loaded.InspectStrings != 7 {
		t.Fatalf("expected InspectStrings 7, got %d", loaded.InspectStrings)
	}
	if loaded.YaraRuleFile != "rules.json" {
		t.Fatalf("expected YaraRuleFile rules.json, got %q", loaded.YaraRuleFile)
	}
}

func TestCreateSampleConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flagrep_sample_config_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "sample.json")
	if err := CreateSampleConfig(path); err != nil {
		t.Fatalf("CreateSampleConfig failed: %v", err)
	}

	loaded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read sample config: %v", err)
	}

	if len(loaded) == 0 {
		t.Fatal("expected sample config to be non-empty")
	}
}
