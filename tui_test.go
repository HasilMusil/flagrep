package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOpenExportFileRefusesOverwrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flagrep_tui_export_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "results.txt")
	if err := os.WriteFile(path, []byte("existing"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := openExportFile(path); err == nil {
		t.Fatal("expected openExportFile to refuse overwriting an existing file")
	}
}

func TestParseCommandLineSupportsQuotedEditorPath(t *testing.T) {
	parts, err := parseCommandLine(`"/tmp/My Editor" --wait --reuse-window`)
	if err != nil {
		t.Fatalf("parseCommandLine failed: %v", err)
	}

	want := []string{"/tmp/My Editor", "--wait", "--reuse-window"}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("unexpected parsed parts: got %#v want %#v", parts, want)
	}
}

func TestParseCommandLineRejectsUnterminatedQuote(t *testing.T) {
	if _, err := parseCommandLine(`"/tmp/My Editor --wait`); err == nil {
		t.Fatal("expected unterminated quote to return an error")
	}
}
