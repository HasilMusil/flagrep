package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Searcher struct {
	Paths            []string
	Pattern          string
	Recursive        bool
	CaseSensitive    bool
	Concurrency      int
	Depth            int
	Verbose          bool
	DecoderEntries   []DecoderEntry
	Decoders         map[string]DecoderFunc
	Regexp           *regexp.Regexp
	ContextBefore    int
	ContextAfter     int
	ExcludedDirs     []string
	JsonOutput       bool
	EntropyThreshold float64
	MagicTypes       []string
	MaxInputBytes    int64
	TUIMode          bool
	MatchCollector   *MatchCollector
}

func NewSearcher(paths []string, pattern string, recursive, caseSensitive, isRegex bool, concurrency, depth, contextBefore, contextAfter int, verbose, jsonOutput bool, excludedDirs []string, entropyThreshold float64, magicTypes []string, maxInputBytes int64, tuiMode bool) (*Searcher, error) {
	var regexPattern string
	if isRegex {
		regexPattern = pattern
	} else {
		regexPattern = regexp.QuoteMeta(pattern)
	}

	if !caseSensitive {
		regexPattern = "(?i)" + regexPattern
	}

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}

	var collector *MatchCollector
	if tuiMode {
		collector = NewMatchCollector()
	}

	decoderEntries := getDecoderEntries()

	return &Searcher{
		Paths:            paths,
		Pattern:          pattern,
		Recursive:        recursive,
		CaseSensitive:    caseSensitive,
		Concurrency:      concurrency,
		Depth:            depth,
		ContextBefore:    contextBefore,
		ContextAfter:     contextAfter,
		Verbose:          verbose,
		DecoderEntries:   decoderEntries,
		Decoders:         getDecoders(),
		Regexp:           re,
		ExcludedDirs:     excludedDirs,
		JsonOutput:       jsonOutput,
		EntropyThreshold: entropyThreshold,
		MagicTypes:       magicTypes,
		MaxInputBytes:    maxInputBytes,
		TUIMode:          tuiMode,
		MatchCollector:   collector,
	}, nil
}

func (s *Searcher) Run() error {
	fileChan := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < s.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				s.processFile(path)
			}
		}()
	}

	// Handle stdin input - process in main goroutine but still use searchBFS
	// (stdin cannot be parallelized as it's a single stream)
	if len(s.Paths) == 0 {
		content, err := readAllWithLimit(os.Stdin, s.MaxInputBytes)
		if err != nil {
			close(fileChan)
			wg.Wait()
			return err
		}
		// Use a set to track already-matched content to avoid duplicates
		seen := make(map[string]bool)
		s.searchBFSWithDedup(string(content), "(stdin)", seen)
		close(fileChan)
		wg.Wait()
		return nil
	}

	stdinConsumed := false
	for _, path := range s.Paths {
		if path == "-" {
			if stdinConsumed {
				if s.Verbose {
					fmt.Printf("Skipping duplicate stdin marker\n")
				}
				continue
			}
			stdinConsumed = true

			content, err := readAllWithLimit(os.Stdin, s.MaxInputBytes)
			if err != nil {
				fmt.Printf("Error reading stdin: %v\n", err)
				continue
			}
			seen := make(map[string]bool)
			s.searchBFSWithDedup(string(content), "(stdin)", seen)
			continue
		}

		err := s.walk(path, fileChan)
		if err != nil {
			fmt.Printf("Error walking path %s: %v\n", path, err)
		}
	}

	close(fileChan)
	wg.Wait()

	return nil
}

func (s *Searcher) walk(root string, fileChan chan<- string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		if s.MaxInputBytes > 0 && info.Size() > s.MaxInputBytes {
			if s.Verbose {
				fmt.Printf("Skipping %s (size %d > max-bytes %d)\n", root, info.Size(), s.MaxInputBytes)
			}
			return nil
		}
		fileChan <- root
		return nil
	}

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if s.Verbose {
				fmt.Printf("Error accessing path %q: %v\n", path, err)
			}
			return nil
		}

		if info.IsDir() {
			base := filepath.Base(path)
			for _, excluded := range s.ExcludedDirs {
				if base == excluded {
					if s.Verbose {
						fmt.Printf("Skipping excluded directory: %s\n", path)
					}
					return filepath.SkipDir
				}
			}
			if !s.Recursive && path != root {
				return filepath.SkipDir
			}
		} else {
			if s.MaxInputBytes > 0 && info.Size() > s.MaxInputBytes {
				if s.Verbose {
					fmt.Printf("Skipping %s (size %d > max-bytes %d)\n", path, info.Size(), s.MaxInputBytes)
				}
				return nil
			}
			fileChan <- path
		}
		return nil
	})
}

func (s *Searcher) processFile(path string) {
	if s.MaxInputBytes > 0 {
		if info, err := os.Stat(path); err == nil && info.Size() > s.MaxInputBytes {
			if s.Verbose {
				fmt.Printf("Skipping %s (size %d > max-bytes %d)\n", path, info.Size(), s.MaxInputBytes)
			}
			return
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		if s.Verbose {
			fmt.Printf("Error reading file %s: %v\n", path, err)
		}
		return
	}

	if len(s.MagicTypes) > 0 {
		if !MatchesMagicFilter(content, s.MagicTypes) {
			detected := DetectMagic(content)
			if s.Verbose {
				fmt.Printf("Skipping %s (magic: %s, filter: %v)\n", path, detected, s.MagicTypes)
			}
			return
		}
		if s.Verbose {
			fmt.Printf("Processing %s (magic: %s)\n", path, DetectMagic(content))
		}
	}

	if s.EntropyThreshold > 0 {
		entropy := CalculateEntropy(content)
		if entropy < s.EntropyThreshold {
			if s.Verbose {
				fmt.Printf("Skipping %s (entropy %.2f < threshold %.2f)\n", path, entropy, s.EntropyThreshold)
			}
			return
		}
		if s.Verbose {
			fmt.Printf("Processing %s (entropy %.2f >= threshold %.2f)\n", path, entropy, s.EntropyThreshold)
		}
	}

	s.searchBFS(string(content), path)
}

type searchState struct {
	content         string
	appliedDecoders []string
	depth           int
}

const maxBFSQueueSize = 10000 // Prevent unbounded memory growth

func (s *Searcher) searchBFS(initialContent, path string) {
	seen := make(map[string]bool)
	s.searchBFSWithDedup(initialContent, path, seen)
}

func (s *Searcher) searchBFSWithDedup(initialContent, path string, seen map[string]bool) {
	if s.MaxInputBytes > 0 && int64(len(initialContent)) > s.MaxInputBytes {
		if s.Verbose {
			fmt.Printf("Skipping %s (content size %d > max-bytes %d)\n", path, len(initialContent), s.MaxInputBytes)
		}
		return
	}

	queue := []searchState{
		{
			content:         initialContent,
			appliedDecoders: []string{},
			depth:           0,
		},
	}

	for len(queue) > 0 {
		// Prevent unbounded memory growth
		if len(queue) > maxBFSQueueSize {
			if s.Verbose {
				fmt.Printf("Warning: BFS queue limit reached for %s, stopping exploration\n", path)
			}
			break
		}

		currentState := queue[0]
		queue = queue[1:]

		// Skip if we've already seen this content
		if seen[currentState.content] {
			continue
		}
		seen[currentState.content] = true

		if s.matches(currentState.content) {
			s.printMatch(path, currentState.appliedDecoders, currentState.content)
		}

		if currentState.depth >= s.Depth {
			continue
		}

		for _, entry := range s.DecoderEntries {
			decoded, err := entry.Func(currentState.content)
			if err == nil && decoded != "" && decoded != currentState.content {
				if s.MaxInputBytes > 0 && int64(len(decoded)) > s.MaxInputBytes {
					if s.Verbose {
						fmt.Printf("Skipping decoder %s for %s (decoded size %d > max-bytes %d)\n", entry.Name, path, len(decoded), s.MaxInputBytes)
					}
					continue
				}

				// Skip if already visited
				if seen[decoded] {
					continue
				}

				newApplied := make([]string, len(currentState.appliedDecoders))
				copy(newApplied, currentState.appliedDecoders)
				newApplied = append(newApplied, entry.Name)

				queue = append(queue, searchState{
					content:         decoded,
					appliedDecoders: newApplied,
					depth:           currentState.depth + 1,
				})
			}
		}
	}
}

func (s *Searcher) matches(content string) bool {
	return s.Regexp.MatchString(content)
}

func (s *Searcher) printMatch(path string, decoders []string, content string) {
	decoderStr := "None"
	if len(decoders) > 0 {
		decoderStr = strings.Join(decoders, " -> ")
	}

	const maxMatchesPerFile = 5
	matches := s.Regexp.FindAllStringIndex(content, maxMatchesPerFile+1)

	for i, loc := range matches {
		if i >= maxMatchesPerFile {
			if !s.JsonOutput && !s.TUIMode {
				fmt.Printf("[MATCH] File: %s | Decoders: %s | ... and more matches ...\n", path, decoderStr)
			}
			break
		}

		matchIndex := loc[0]
		matchLen := loc[1] - loc[0]

		start := max(matchIndex-s.ContextBefore, 0)
		end := min(matchIndex+matchLen+s.ContextAfter, len(content))

		prefix := content[start:matchIndex]
		match := content[matchIndex : matchIndex+matchLen]
		suffix := content[matchIndex+matchLen : end]
		context := prefix + match + suffix

		if s.TUIMode && s.MatchCollector != nil {
			s.MatchCollector.Add(path, decoders, match, context, matchIndex)
			continue
		}

		if s.JsonOutput {
			output := struct {
				File     string   `json:"file"`
				Decoders []string `json:"decoders"`
				Match    string   `json:"match"`
				Context  string   `json:"context"`
				Offset   int      `json:"offset"`
			}{
				File:     path,
				Decoders: decoders,
				Match:    match,
				Context:  context,
				Offset:   matchIndex,
			}
			jsonBytes, err := json.Marshal(output)
			if err == nil {
				fmt.Println(string(jsonBytes))
			}
		} else {
			prefix = strings.ReplaceAll(prefix, "\n", "\\n")
			prefix = strings.ReplaceAll(prefix, "\r", "\\r")
			match = strings.ReplaceAll(match, "\n", "\\n")
			match = strings.ReplaceAll(match, "\r", "\\r")
			suffix = strings.ReplaceAll(suffix, "\n", "\\n")
			suffix = strings.ReplaceAll(suffix, "\r", "\\r")

			formattedContent := fmt.Sprintf("%s\033[31m%s\033[0m%s", prefix, match, suffix)

			fmt.Printf("[MATCH] File: %s | Decoders: %s | Content: ...%s...\n", path, decoderStr, formattedContent)
		}
	}
}
