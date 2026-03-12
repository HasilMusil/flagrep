package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSearcher(t *testing.T) {
	// create temp dir
	tmpDir, err := os.MkdirTemp("", "encodedgrep_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// plain
	plainFile := filepath.Join(tmpDir, "plain.txt")
	err = os.WriteFile(plainFile, []byte("This is a secret message"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// base64
	b64File := filepath.Join(tmpDir, "b64.txt")
	encoded := base64.StdEncoding.EncodeToString([]byte("This is a secret message"))
	err = os.WriteFile(b64File, []byte(encoded), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// plain test
	searcher, err := NewSearcher([]string{plainFile}, "secret", false, false, false, 1, 2, 20, 20, false, false, nil, 0, nil, 0, false)
	if err != nil {
		t.Fatalf("NewSearcher failed: %v", err)
	}
	err = searcher.Run()
	if err != nil {
		t.Errorf("Searcher failed on plain text: %v", err)
	}

	// base64 test
	searcher, err = NewSearcher([]string{b64File}, "secret", false, false, false, 1, 2, 20, 20, false, false, nil, 0, nil, 0, false)
	if err != nil {
		t.Fatalf("NewSearcher failed: %v", err)
	}
	err = searcher.Run()
	if err != nil {
		t.Errorf("Searcher failed on base64 text: %v", err)
	}
}

func TestSearcherHonorsMaxBytes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flagrep_maxbytes_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := []byte("secret secret secret secret secret")
	file := filepath.Join(tmpDir, "large.txt")
	if err := os.WriteFile(file, content, 0644); err != nil {
		t.Fatal(err)
	}

	searcher, err := NewSearcher([]string{file}, "secret", false, false, false, 1, 1, 5, 5, false, false, nil, 0, nil, 8, true)
	if err != nil {
		t.Fatalf("NewSearcher failed: %v", err)
	}

	if err := searcher.Run(); err != nil {
		t.Fatalf("Searcher failed: %v", err)
	}

	if searcher.MatchCollector == nil {
		t.Fatal("expected match collector in TUI mode")
	}

	if len(searcher.MatchCollector.Matches) != 0 {
		t.Fatalf("expected no matches when file exceeds max-bytes, got %d", len(searcher.MatchCollector.Matches))
	}
}

func TestDecoders(t *testing.T) {
	decoders := getDecoders()

	// Test Reverse
	rev, _ := decoders["reverse"]("hello")
	if rev != "olleh" {
		t.Errorf("Reverse decoder failed: expected olleh, got %s", rev)
	}

	// Test Base64
	b64, _ := decoders["base64"]("aGVsbG8=")
	if b64 != "hello" {
		t.Errorf("Base64 decoder failed: expected hello, got %s", b64)
	}

	// Test ROT13
	rot, _ := decoders["rot13"]("uryyb")
	if rot != "hello" {
		t.Errorf("ROT13 decoder failed: expected hello, got %s", rot)
	}

	// Test XOR brute-force
	// The decoder should score all keys and choose the most plausible plaintext.
	// Test with a longer sentence XOR'd with 0x55 to ensure it prefers the real key.
	plaintext := "This is a secret message for testing XOR decoder"
	key := byte(0x55)
	xorBytes := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		xorBytes[i] = plaintext[i] ^ key
	}
	xorInput := string(xorBytes)
	xorResult, err := decoders["xor_bruteforce"](xorInput)
	if err != nil {
		t.Errorf("XOR decoder failed: %v", err)
	}
	if xorResult != plaintext {
		t.Errorf("XOR decoder got %q, want %q", xorResult, plaintext)
	}
}

func TestEntropyCalculation(t *testing.T) {
	// Low entropy - repeated characters
	lowEntropy := CalculateEntropyString("AAAAAAAAAAAAAAAA")
	if lowEntropy != 0 {
		t.Errorf("Expected entropy 0 for repeated chars, got %.2f", lowEntropy)
	}

	// Higher entropy - mixed text
	text := "Hello, World! This is a test message with some variety."
	textEntropy := CalculateEntropyString(text)
	if textEntropy < 3.0 || textEntropy > 5.0 {
		t.Errorf("Expected text entropy between 3.0-5.0, got %.2f", textEntropy)
	}

	// Empty input
	emptyEntropy := CalculateEntropyString("")
	if emptyEntropy != 0 {
		t.Errorf("Expected entropy 0 for empty string, got %.2f", emptyEntropy)
	}
}

func TestMagicBytesDetection(t *testing.T) {
	// Test ELF detection
	elfBytes := []byte{0x7F, 'E', 'L', 'F', 0x01, 0x02}
	if detected := DetectMagic(elfBytes); detected != "ELF" {
		t.Errorf("Expected ELF, got %s", detected)
	}

	// Test PNG detection
	pngBytes := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if detected := DetectMagic(pngBytes); detected != "PNG" {
		t.Errorf("Expected PNG, got %s", detected)
	}

	// Test unknown
	unknownBytes := []byte{0x00, 0x01, 0x02, 0x03}
	if detected := DetectMagic(unknownBytes); detected != "unknown" {
		t.Errorf("Expected unknown, got %s", detected)
	}

	// Test magic filter matching
	if !MatchesMagicFilter(elfBytes, []string{"ELF", "MZ"}) {
		t.Error("Expected ELF to match filter")
	}
	if MatchesMagicFilter(elfBytes, []string{"PNG", "PDF"}) {
		t.Error("Expected ELF to NOT match PNG/PDF filter")
	}
	if !MatchesMagicFilter(elfBytes, nil) {
		t.Error("Expected empty filter to match all")
	}
}
