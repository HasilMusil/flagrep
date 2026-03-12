package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type InspectOptions struct {
	Recursive           bool
	ExcludedDirs        []string
	Concurrency         int
	Verbose             bool
	MaxBytes            int64
	StringsLimit        int
	UnicodeStringsLimit int
	ShowHeatmap         bool
	YaraRules           []YaraRule
}

type FileAnalysis struct {
	File                string
	Size                int
	Magic               string
	Entropy             float64
	Hashes              *FileHashes
	Header              *FileHeader
	ASCIIStrings        []ExtractedString
	TotalASCIIStrings   int
	UnicodeStrings      []ExtractedString
	TotalUnicodeStrings int
	Heatmap             string
	YaraMatches         []YaraMatch
}

type Inspector struct {
	Paths    []string
	Options  InspectOptions
	printMu  sync.Mutex
	statusMu sync.Mutex
}

func NewInspector(paths []string, options InspectOptions) *Inspector {
	return &Inspector{
		Paths:   paths,
		Options: options,
	}
}

func LoadYaraRulesFile(path string) ([]YaraRule, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read YARA rule file %s: %w", path, err)
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	var rules []YaraRule
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("could not decode YARA rule file %s: %w", path, err)
		}
	} else {
		var rule YaraRule
		if err := json.Unmarshal(data, &rule); err != nil {
			return nil, fmt.Errorf("could not decode YARA rule file %s: %w", path, err)
		}
		rules = []YaraRule{rule}
	}

	for i := range rules {
		if strings.TrimSpace(rules[i].Condition) == "" {
			rules[i].Condition = "any"
		}
		if err := CompileYaraRule(&rules[i]); err != nil {
			return nil, err
		}
	}

	return rules, nil
}

func AnalyzeContent(path string, data []byte, options InspectOptions) (*FileAnalysis, error) {
	analysis := &FileAnalysis{
		File:    path,
		Size:    len(data),
		Magic:   DetectMagic(data),
		Entropy: CalculateEntropy(data),
		Hashes:  CalculateHashesFromBytes(data),
	}

	if header, err := ParseFileHeader(data); err == nil {
		analysis.Header = header
	}

	asciiStrings := ExtractStrings(data, 4)
	analysis.TotalASCIIStrings = len(asciiStrings)
	analysis.ASCIIStrings = limitExtractedStrings(asciiStrings, options.StringsLimit)

	unicodeStrings := ExtractUnicodeStrings(data, 4)
	analysis.TotalUnicodeStrings = len(unicodeStrings)
	analysis.UnicodeStrings = limitExtractedStrings(unicodeStrings, options.UnicodeStringsLimit)

	if options.ShowHeatmap {
		analysis.Heatmap = RenderEntropyHeatmap(data, 64)
	}

	for _, rule := range options.YaraRules {
		if match := MatchYaraRule(data, &rule); match != nil {
			match.File = path
			analysis.YaraMatches = append(analysis.YaraMatches, *match)
		}
	}

	return analysis, nil
}

func FormatFileAnalysis(analysis *FileAnalysis) string {
	var result strings.Builder

	fmt.Fprintf(&result, "[ANALYZE] File: %s\n", analysis.File)
	fmt.Fprintf(&result, "Size: %d bytes\n", analysis.Size)
	fmt.Fprintf(&result, "Magic: %s\n", analysis.Magic)
	fmt.Fprintf(&result, "Entropy: %.2f\n", analysis.Entropy)
	if analysis.Hashes != nil {
		fmt.Fprintf(&result, "MD5: %s\n", analysis.Hashes.MD5)
		fmt.Fprintf(&result, "SHA256: %s\n", analysis.Hashes.SHA256)
	}

	if analysis.Header != nil {
		result.WriteString("\nHeader:\n")
		for _, line := range strings.Split(strings.TrimRight(FormatHeader(analysis.Header), "\n"), "\n") {
			fmt.Fprintf(&result, "  %s\n", line)
		}
	}

	if len(analysis.YaraMatches) > 0 {
		result.WriteString("\nYARA Matches:\n")
		for _, match := range analysis.YaraMatches {
			fmt.Fprintf(&result, "  - %s\n", match.Rule)
			for id, offsets := range match.Matches {
				label := ""
				if match.Truncated != nil && match.Truncated[id] {
					label = " (truncated)"
				}
				fmt.Fprintf(&result, "    %s: %v%s\n", id, offsets, label)
			}
		}
	}

	if analysis.TotalASCIIStrings > 0 {
		fmt.Fprintf(&result, "\nASCII Strings (showing %d of %d):\n", len(analysis.ASCIIStrings), analysis.TotalASCIIStrings)
		for _, extracted := range analysis.ASCIIStrings {
			fmt.Fprintf(&result, "  [%d] %s\n", extracted.Offset, truncate(escapeNewlines(extracted.Value), 120))
		}
	}

	if analysis.TotalUnicodeStrings > 0 {
		fmt.Fprintf(&result, "\nUnicode Strings (showing %d of %d):\n", len(analysis.UnicodeStrings), analysis.TotalUnicodeStrings)
		for _, extracted := range analysis.UnicodeStrings {
			fmt.Fprintf(&result, "  [%d] %s\n", extracted.Offset, truncate(escapeNewlines(extracted.Value), 120))
		}
	}

	if analysis.Heatmap != "" {
		result.WriteString("\n")
		result.WriteString(strings.TrimRight(analysis.Heatmap, "\n"))
		result.WriteString("\n")
	}

	result.WriteString("\n")
	return result.String()
}

func (i *Inspector) Run() error {
	fileChan := make(chan string)
	var wg sync.WaitGroup

	workerCount := i.Options.Concurrency
	if workerCount < 1 {
		workerCount = 1
	}

	for n := 0; n < workerCount; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				i.inspectFile(path)
			}
		}()
	}

	if len(i.Paths) == 0 {
		content, err := readAllWithLimit(os.Stdin, i.Options.MaxBytes)
		if err != nil {
			close(fileChan)
			wg.Wait()
			return err
		}
		analysis, err := AnalyzeContent("(stdin)", content, i.Options)
		if err != nil {
			close(fileChan)
			wg.Wait()
			return err
		}
		fmt.Print(FormatFileAnalysis(analysis))
		close(fileChan)
		wg.Wait()
		return nil
	}

	stdinConsumed := false
	for _, path := range i.Paths {
		if path == "-" {
			if stdinConsumed {
				i.logVerbose("Skipping duplicate stdin marker\n")
				continue
			}
			stdinConsumed = true

			content, err := readAllWithLimit(os.Stdin, i.Options.MaxBytes)
			if err != nil {
				fmt.Printf("Error reading stdin: %v\n", err)
				continue
			}
			analysis, err := AnalyzeContent("(stdin)", content, i.Options)
			if err != nil {
				fmt.Printf("Error analyzing stdin: %v\n", err)
				continue
			}
			fmt.Print(FormatFileAnalysis(analysis))
			continue
		}

		if err := i.walk(path, fileChan); err != nil {
			fmt.Printf("Error walking path %s: %v\n", path, err)
		}
	}

	close(fileChan)
	wg.Wait()
	return nil
}

func (i *Inspector) walk(root string, fileChan chan<- string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		if i.Options.MaxBytes > 0 && info.Size() > i.Options.MaxBytes {
			i.logVerbose("Skipping %s (size %d > max-bytes %d)\n", root, info.Size(), i.Options.MaxBytes)
			return nil
		}
		fileChan <- root
		return nil
	}

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			i.logVerbose("Error accessing path %q: %v\n", path, err)
			return nil
		}

		if info.IsDir() {
			base := filepath.Base(path)
			for _, excluded := range i.Options.ExcludedDirs {
				if base == excluded {
					i.logVerbose("Skipping excluded directory: %s\n", path)
					return filepath.SkipDir
				}
			}
			if !i.Options.Recursive && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		if i.Options.MaxBytes > 0 && info.Size() > i.Options.MaxBytes {
			i.logVerbose("Skipping %s (size %d > max-bytes %d)\n", path, info.Size(), i.Options.MaxBytes)
			return nil
		}

		fileChan <- path
		return nil
	})
}

func (i *Inspector) inspectFile(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		i.logVerbose("Error reading file %s: %v\n", path, err)
		return
	}

	analysis, err := AnalyzeContent(path, content, i.Options)
	if err != nil {
		i.logVerbose("Error analyzing file %s: %v\n", path, err)
		return
	}

	i.printMu.Lock()
	defer i.printMu.Unlock()
	fmt.Print(FormatFileAnalysis(analysis))
}

func (i *Inspector) logVerbose(format string, args ...any) {
	if !i.Options.Verbose {
		return
	}

	i.statusMu.Lock()
	defer i.statusMu.Unlock()
	fmt.Printf(format, args...)
}

func limitExtractedStrings(items []ExtractedString, limit int) []ExtractedString {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}
