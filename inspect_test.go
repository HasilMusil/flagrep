package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeContentIntegratesHeaderHashesStringsAndYARA(t *testing.T) {
	data := make([]byte, 64)
	copy(data[:4], []byte{0x7F, 'E', 'L', 'F'})
	data[4] = 2
	data[5] = 1
	data[18] = 0x3E
	data[19] = 0x00
	data = append(data, []byte("flag{demo}\x00HELLO_WORLD\x00")...)

	rule := YaraRule{
		Name:      "flag-rule",
		Condition: "any",
		Strings: []YaraString{
			{ID: "$a", Pattern: "flag{demo}"},
		},
	}
	if err := CompileYaraRule(&rule); err != nil {
		t.Fatalf("CompileYaraRule failed: %v", err)
	}

	analysis, err := AnalyzeContent("sample.bin", data, InspectOptions{
		StringsLimit:        2,
		UnicodeStringsLimit: 0,
		ShowHeatmap:         true,
		YaraRules:           []YaraRule{rule},
	})
	if err != nil {
		t.Fatalf("AnalyzeContent failed: %v", err)
	}

	if analysis.Magic != "ELF" {
		t.Fatalf("expected ELF magic, got %q", analysis.Magic)
	}
	if analysis.Header == nil || analysis.Header.Type != "ELF" {
		t.Fatalf("expected ELF header, got %#v", analysis.Header)
	}
	if analysis.Hashes == nil || analysis.Hashes.SHA256 == "" {
		t.Fatal("expected hashes to be populated")
	}
	if len(analysis.ASCIIStrings) == 0 {
		t.Fatal("expected extracted ASCII strings")
	}
	if len(analysis.YaraMatches) != 1 {
		t.Fatalf("expected 1 YARA match, got %d", len(analysis.YaraMatches))
	}
	if !strings.Contains(FormatFileAnalysis(analysis), "SHA256:") {
		t.Fatal("expected formatted analysis to include SHA256")
	}
	if analysis.Heatmap == "" {
		t.Fatal("expected heatmap output")
	}
}

func TestLoadYaraRulesFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flagrep_yara_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "rules.json")
	content := `[
		{
			"Name": "demo-rule",
			"Description": "demo",
			"Condition": "any",
			"Strings": [
				{"ID": "$a", "Pattern": "flag", "IsRegex": false, "IsHex": false, "NoCase": true}
			]
		}
	]`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadYaraRulesFile(path)
	if err != nil {
		t.Fatalf("LoadYaraRulesFile failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	match := MatchYaraRule([]byte("FLAG"), &rules[0])
	if match == nil {
		t.Fatal("expected YARA rule to match input")
	}
}

func TestCompileYaraRuleRejectsEmptyPatterns(t *testing.T) {
	tests := []YaraRule{
		{
			Name:      "empty-plain",
			Condition: "any",
			Strings:   []YaraString{{ID: "$a", Pattern: ""}},
		},
		{
			Name:      "empty-hex",
			Condition: "any",
			Strings:   []YaraString{{ID: "$b", Pattern: "   ", IsHex: true}},
		},
		{
			Name:      "empty-regex",
			Condition: "any",
			Strings:   []YaraString{{ID: "$c", Pattern: "", IsRegex: true}},
		},
	}

	for _, rule := range tests {
		rule := rule
		t.Run(rule.Name, func(t *testing.T) {
			if err := CompileYaraRule(&rule); err == nil {
				t.Fatalf("expected CompileYaraRule to fail for %s", rule.Name)
			}
		})
	}
}

func TestMatchYaraRuleCapsOffsetsAndMarksTruncated(t *testing.T) {
	rule := YaraRule{
		Name:      "many-matches",
		Condition: "any",
		Strings:   []YaraString{{ID: "$a", Pattern: "A"}},
	}
	if err := CompileYaraRule(&rule); err != nil {
		t.Fatalf("CompileYaraRule failed: %v", err)
	}

	data := bytes.Repeat([]byte("A"), maxYaraMatchesPerString+50)
	match := MatchYaraRule(data, &rule)
	if match == nil {
		t.Fatal("expected YARA rule to match input")
	}

	offsets := match.Matches["$a"]
	if len(offsets) != maxYaraMatchesPerString {
		t.Fatalf("expected %d capped offsets, got %d", maxYaraMatchesPerString, len(offsets))
	}
	if !match.Truncated["$a"] {
		t.Fatal("expected truncated flag for capped matches")
	}
}
