package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
)

var version = "1.1.0"

// Default context constants
const (
	defaultBeforeContext = 10
	defaultAfterContext  = 30
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	config, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not load config: %v\n", err)
	}

	recursive := flag.Bool("r", config.Recursive, "Recursively search directories")
	ignoreCase := flag.Bool("i", config.IgnoreCase, "Ignore case")
	workers := flag.Int("workers", config.Workers, "Concurrency limit")
	depth := flag.Int("depth", config.Depth, "Decoder combination depth")
	maxBytes := flag.Int64("max-bytes", config.MaxBytes, "Skip or reject inputs larger than NUM bytes (0 to disable)")
	verbose := flag.Bool("v", config.Verbose, "Verbose output")

	var afterContext, beforeContext int
	flag.IntVar(&afterContext, "A", config.AfterContext, "Print NUM characters of trailing context")
	flag.IntVar(&beforeContext, "B", config.BeforeContext, "Print NUM characters of leading context")
	var context int
	flag.IntVar(&context, "C", config.Context, "Print NUM characters of output context")

	useRegex := flag.Bool("e", config.UseRegex, "Enable regex mode")
	jsonOutput := flag.Bool("json", config.JSONOutput, "Enable JSON output")

	defaultExclude := strings.Join(config.ExcludeDirs, ",")
	excludeDirStr := flag.String("exclude-dir", defaultExclude, "Comma-separated list of directories to exclude")

	entropyThreshold := flag.Float64("entropy-threshold", config.EntropyThreshold, "Only process content with entropy >= threshold (0 to disable)")

	defaultMagic := strings.Join(config.MagicFilter, ",")
	magicFilter := flag.String("magic", defaultMagic, "Comma-separated list of magic types to include (e.g., ELF,MZ,PDF)")

	tuiMode := flag.Bool("tui", config.TUIMode, "Enable interactive TUI mode")
	inspectMode := flag.Bool("inspect", config.InspectMode, "Analyze files instead of searching for a pattern")
	inspectStrings := flag.Int("inspect-strings", config.InspectStrings, "Show up to NUM printable ASCII strings in inspect mode (0 to disable)")
	inspectUnicode := flag.Int("inspect-unicode-strings", config.InspectUnicode, "Show up to NUM UTF-16 strings in inspect mode (0 to disable)")
	inspectHeatmap := flag.Bool("inspect-heatmap", config.InspectHeatmap, "Show an entropy heatmap in inspect mode")
	yaraFile := flag.String("yara-file", config.YaraRuleFile, "JSON file containing YARA-like rules for inspect mode")
	writeConfig := flag.String("write-config", "", "Write a sample config file to PATH and exit")
	showVersion := flag.Bool("version", false, "Show version information")

	cpuProfile := flag.String("cpuprofile", "", "Write CPU profile to file")
	memProfile := flag.String("memprofile", "", "Write memory profile to file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  flagrep [options] PATTERN [FILE...]\n")
		fmt.Fprintf(os.Stderr, "  flagrep [options] PATTERN < stdin\n")
		fmt.Fprintf(os.Stderr, "  flagrep -inspect [options] [FILE...]\n")
		fmt.Fprintf(os.Stderr, "  flagrep -inspect [options] < stdin\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nConfig: loaded from ./.flagreprc, ./.flagrep.json, ~/.flagreprc, ~/.flagrep.json, or ~/.config/flagrep/config.json\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("flagrep version %s\n", version)
		return nil
	}

	if *writeConfig != "" {
		return CreateSampleConfig(*writeConfig)
	}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("could not start CPU profile: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	if *memProfile != "" {
		defer func() {
			f, err := os.Create(*memProfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not create memory profile: %v\n", err)
				return
			}
			defer f.Close()
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "Could not write memory profile: %v\n", err)
			}
		}()
	}

	args := flag.Args()
	if *inspectMode {
		if *tuiMode {
			return fmt.Errorf("-inspect and -tui cannot be used together")
		}

		if len(args) == 0 && !stdinHasData() {
			flag.Usage()
			return fmt.Errorf("inspect mode requires at least one file or piped stdin")
		}
	} else if len(args) < 1 {
		flag.Usage()
		return fmt.Errorf("missing pattern argument")
	}

	var pattern string
	paths := args
	if !*inspectMode {
		pattern = args[0]
		paths = args[1:]
	}

	if context > 0 {
		if afterContext == 0 {
			afterContext = context
		}
		if beforeContext == 0 {
			beforeContext = context
		}
	}
	if afterContext == 0 && beforeContext == 0 && context == 0 && config.AfterContext == 0 && config.BeforeContext == 0 {
		beforeContext = defaultBeforeContext
		afterContext = defaultAfterContext
	}

	caseSensitive := !*ignoreCase

	var excludedDirs []string
	if *excludeDirStr != "" {
		excludedDirs = strings.Split(*excludeDirStr, ",")
		for i := range excludedDirs {
			excludedDirs[i] = strings.TrimSpace(excludedDirs[i])
		}
	}

	var magicTypes []string
	if *magicFilter != "" {
		magicTypes = strings.Split(*magicFilter, ",")
		for i := range magicTypes {
			magicTypes[i] = strings.TrimSpace(strings.ToUpper(magicTypes[i]))
		}
	}

	if *inspectMode {
		yaraRules, err := LoadYaraRulesFile(*yaraFile)
		if err != nil {
			return err
		}

		inspector := NewInspector(paths, InspectOptions{
			Recursive:           *recursive,
			ExcludedDirs:        excludedDirs,
			Concurrency:         *workers,
			Verbose:             *verbose,
			MaxBytes:            *maxBytes,
			StringsLimit:        *inspectStrings,
			UnicodeStringsLimit: *inspectUnicode,
			ShowHeatmap:         *inspectHeatmap,
			YaraRules:           yaraRules,
		})
		return inspector.Run()
	}

	searcher, err := NewSearcher(paths, pattern, *recursive, caseSensitive, *useRegex, *workers, *depth, beforeContext, afterContext, *verbose, *jsonOutput, excludedDirs, *entropyThreshold, magicTypes, *maxBytes, *tuiMode)
	if err != nil {
		return err
	}

	if *verbose {
		fmt.Printf("Starting search for pattern %q (Recursive: %v, Depth: %d)\n", pattern, *recursive, *depth)
	}

	if !*tuiMode {
		fmt.Println("[INFO] Expect false positives")
	}

	err = searcher.Run()
	if err != nil {
		return err
	}

	if *tuiMode && searcher.MatchCollector != nil {
		tui := NewTUI(searcher.MatchCollector.Matches)
		tui.Run()
	}

	return nil
}
