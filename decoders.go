package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type DecoderFunc func(string) (string, error)

type DecoderEntry struct {
	Name string
	Func DecoderFunc
}

// Pre-compiled regex patterns for better performance
// These are compiled once at startup instead of on every decoder call
var (
	base64Pattern      = regexp.MustCompile(`[A-Za-z0-9+/]{8,}={0,2}`)
	pureAlphaPattern   = regexp.MustCompile(`^[A-Za-z]+$`)
	base64URLPattern   = regexp.MustCompile(`[A-Za-z0-9_-]{8,}={0,2}`)
	base32Pattern      = regexp.MustCompile(`[A-Z2-7]{8,}={0,6}`)
	hexSpacesPattern   = regexp.MustCompile(`\b([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+)\b`)
	hexNoSpacesPattern = regexp.MustCompile(`\b([0-9a-fA-F]{6,})\b`)
	hexPrefixPattern   = regexp.MustCompile(`\b((?:0x[0-9a-fA-F]{2}(?:\s+|$))+)\b`)
	binaryOnlyPattern  = regexp.MustCompile(`^[01]+$`)
	binaryPattern      = regexp.MustCompile(`[01]{16,}`)
	octalPattern       = regexp.MustCompile(`\b([0-7]{1,3}(?:\s+[0-7]{1,3})+)\b`)
	morseWordPattern   = regexp.MustCompile(`\s{2,}|/`)
	unicodePattern     = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	hexEscapePattern   = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
)

const (
	maxDecoderCandidateMatches = 4096
	maxPrintableStreamResults  = 128
)

var commonEnglishWords = map[string]float64{
	"the":     3.0,
	"and":     2.5,
	"that":    2.0,
	"this":    2.0,
	"have":    1.5,
	"for":     1.5,
	"with":    1.5,
	"you":     1.5,
	"flag":    3.5,
	"secret":  3.0,
	"message": 2.5,
	"quick":   1.5,
	"brown":   1.0,
	"jumps":   1.0,
	"over":    1.0,
	"lazy":    1.0,
}

var commonEnglishBigrams = []string{
	"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
	"ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
}

func isLikelyTextByte(b byte) bool {
	return (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t'
}

func scoreTextCandidate(input string) float64 {
	data := []byte(input)
	if len(data) == 0 {
		return math.Inf(-1)
	}

	printable := 0
	letters := 0
	vowels := 0
	spaces := 0
	commonLetters := 0
	unusualPrintable := 0

	for _, b := range data {
		if !isLikelyTextByte(b) {
			continue
		}
		printable++

		switch {
		case b >= 'a' && b <= 'z':
			letters++
			if isVowel(rune(b)) {
				vowels++
			}
			if strings.ContainsRune("etaoinshrdlu", rune(b)) {
				commonLetters++
			}
		case b >= 'A' && b <= 'Z':
			letters++
			if isVowel(rune(b)) {
				vowels++
			}
			if strings.ContainsRune("ETAOINSHRDLU", rune(b)) {
				commonLetters++
			}
		case b == ' ' || b == '\n' || b == '\r' || b == '\t':
			spaces++
		case strings.ContainsRune("~^|`\\", rune(b)):
			unusualPrintable++
		}
	}

	printableRatio := float64(printable) / float64(len(data))
	if printableRatio < 0.85 {
		return printableRatio * 2
	}

	score := printableRatio * 4
	if letters > 0 {
		letterRatio := float64(letters) / float64(len(data))
		score += letterRatio * 3

		vowelRatio := float64(vowels) / float64(letters)
		score += 1.5 - math.Abs(vowelRatio-0.38)*4

		commonLetterRatio := float64(commonLetters) / float64(letters)
		score += commonLetterRatio * 2
	} else {
		score -= 2
	}

	spaceRatio := float64(spaces) / float64(len(data))
	if spaces > 0 {
		score += 1.2 - math.Abs(spaceRatio-0.18)*4
	} else {
		score -= 0.25
	}

	if unusualPrintable > 0 {
		score -= float64(unusualPrintable) / float64(len(data)) * 6
	}

	lower := strings.ToLower(input)
	for word, weight := range commonEnglishWords {
		if strings.Contains(lower, word) {
			score += weight
		}
	}

	bigramHits := 0
	for _, bigram := range commonEnglishBigrams {
		bigramHits += strings.Count(lower, bigram)
	}
	score += math.Min(float64(bigramHits)*0.15, 2.5)

	if strings.Contains(lower, "flag{") || strings.Contains(lower, "ctf{") {
		score += 4
	}

	return score
}

// isPrintableBytes checks if byte slice is mostly printable ASCII (≥70%)
func isPrintableBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) >= 0.7
}

func findAllStringIndicesLimited(re *regexp.Regexp, input string, limit int) (matches [][]int, truncated bool) {
	if limit <= 0 {
		return nil, false
	}

	matches = re.FindAllStringIndex(input, limit+1)
	if len(matches) > limit {
		return matches[:limit], true
	}
	return matches, false
}

func getDecoderEntries() []DecoderEntry {
	return []DecoderEntry{
		{Name: "reverse", Func: reverseDecoder},
		{Name: "space_removal", Func: spaceRemovalDecoder},
		{Name: "base64", Func: base64Decoder},
		{Name: "base64_url", Func: base64URLDecoder},
		{Name: "base32", Func: base32Decoder},
		{Name: "hex_with_spaces", Func: hexWithSpacesDecoder},
		{Name: "hex_without_spaces", Func: hexWithoutSpacesDecoder},
		{Name: "hex_with_prefix", Func: hexWithPrefixDecoder},
		{Name: "rot13", Func: rot13Decoder},
		{Name: "rot47", Func: rot47Decoder},
		{Name: "binary", Func: binaryDecoder},
		{Name: "octal", Func: octalDecoder},
		{Name: "url", Func: urlDecoder},
		{Name: "html", Func: htmlEntityDecoder},
		{Name: "xor_bruteforce", Func: xorBruteForceDecoder},
		{Name: "atbash", Func: atbashDecoder},
		{Name: "morse", Func: morseDecoder},
		{Name: "unicode_escape", Func: unicodeEscapeDecoder},
		{Name: "base85", Func: base85Decoder},
		{Name: "caesar", Func: caesarBruteForceDecoder},
	}
}

func getDecoders() map[string]DecoderFunc {
	entries := getDecoderEntries()
	decoders := make(map[string]DecoderFunc, len(entries))
	for _, entry := range entries {
		decoders[entry.Name] = entry.Func
	}
	return decoders
}

// "olleH" -> "Hello"
func reverseDecoder(input string) (string, error) {
	runes := []rune(input)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes), nil
}

// "He llo" -> "Hello"
func spaceRemovalDecoder(input string) (string, error) {
	return strings.ReplaceAll(input, " ", ""), nil
}

// "SGVsbG8=" -> "Hello"
func base64Decoder(input string) (string, error) {
	// Try with newlines/whitespace stripped first (for multi-line base64)
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, input)

	// If the entire input is valid base64 and decodes to printable text, use it
	if data, err := base64.StdEncoding.DecodeString(clean); err == nil {
		if isPrintableBytes(data) {
			return string(data), nil
		}
	}
	// Try unpadded/raw base64
	if data, err := base64.RawStdEncoding.DecodeString(clean); err == nil {
		if isPrintableBytes(data) {
			return string(data), nil
		}
	}

	matches, _ := findAllStringIndicesLimited(base64Pattern, input, maxDecoderCandidateMatches)
	if len(matches) == 0 {
		return "", fmt.Errorf("no base64 found")
	}

	// Use strings.Builder to avoid index mutation bug
	var result strings.Builder
	lastPos := 0
	anyDecoded := false

	for _, match := range matches {
		start, end := match[0], match[1]
		segment := input[start:end]

		// Add text before this match
		result.WriteString(input[lastPos:start])

		// Skip pure alphabetic words (likely regular text)
		if pureAlphaPattern.MatchString(segment) {
			result.WriteString(segment)
			lastPos = end
			continue
		}

		// For very long segments (>1KB), use sliding window to find embedded printable base64
		if len(segment) > 1024 {
			found := findPrintableBase64InStream(segment)
			if found != "" {
				result.WriteString(found)
				anyDecoded = true
			} else {
				result.WriteString(segment) // Keep original if nothing found
			}
			lastPos = end
			continue
		}

		// Validate base64 length (must be multiple of 4 or valid with padding)
		segLen := len(segment)
		if segLen%4 != 0 {
			// Add padding instead of trimming
			padLen := 4 - (segLen % 4)
			segment += strings.Repeat("=", padLen)
		}

		decoded, err := base64.StdEncoding.DecodeString(segment)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(segment)
		}
		if err != nil || !isPrintableBytes(decoded) {
			result.WriteString(input[start:end]) // Keep original
			lastPos = end
			continue
		}

		result.Write(decoded)
		anyDecoded = true
		lastPos = end
	}

	// Add remaining text after last match
	if lastPos < len(input) {
		result.WriteString(input[lastPos:])
	}

	if !anyDecoded {
		return "", fmt.Errorf("no valid base64 decoded")
	}
	return result.String(), nil
}

// findPrintableBase64InStream scans a long base64 stream looking for segments that decode to printable text
func findPrintableBase64InStream(stream string) string {
	// Try various window sizes (common flag lengths)
	windowSizes := []int{12, 16, 20, 24, 28, 32, 36, 40, 48, 64, 80, 100, 128}

	var results []string

	for _, windowSize := range windowSizes {
		// Ensure window is multiple of 4
		windowSize = (windowSize / 4) * 4
		if windowSize < 4 {
			continue
		}

		// Slide through the stream
		for i := 0; i <= len(stream)-windowSize; i += 4 {
			segment := stream[i : i+windowSize]

			decoded, err := base64.StdEncoding.DecodeString(segment)
			if err != nil {
				continue
			}

			// Check if decoded content is mostly printable
			if isPrintableBytes(decoded) {
				decodedStr := string(decoded)
				// Only keep if it has some substance (not just whitespace)
				if len(strings.TrimSpace(decodedStr)) >= 4 {
					results = append(results, decodedStr)
					if len(results) >= maxPrintableStreamResults {
						return strings.Join(results, " | ")
					}
				}
			}
		}
	}

	if len(results) > 0 {
		return strings.Join(results, " | ")
	}
	return ""
}

func base64URLDecoder(input string) (string, error) {
	// Try with newlines/whitespace stripped first (for multi-line base64url)
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, input)
	if data, err := base64.URLEncoding.DecodeString(clean); err == nil {
		if isPrintableBytes(data) {
			return string(data), nil
		}
	}

	matches, _ := findAllStringIndicesLimited(base64URLPattern, input, maxDecoderCandidateMatches)
	if len(matches) == 0 {
		return "", fmt.Errorf("no base64url found")
	}

	// Use strings.Builder to avoid index mutation bug
	var result strings.Builder
	lastPos := 0
	anyDecoded := false

	for _, match := range matches {
		start, end := match[0], match[1]
		segment := input[start:end]

		// Add text before this match
		result.WriteString(input[lastPos:start])

		if pureAlphaPattern.MatchString(segment) {
			result.WriteString(segment)
			lastPos = end
			continue
		}

		// Validate base64url length
		segLen := len(segment)
		if segLen%4 != 0 {
			segLen = (segLen / 4) * 4
			if segLen < 4 {
				result.WriteString(segment)
				lastPos = end
				continue
			}
			segment = segment[:segLen]
		}

		decoded, err := base64.URLEncoding.DecodeString(segment)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(segment)
		}
		if err != nil || !isPrintableBytes(decoded) {
			result.WriteString(input[start:end])
			lastPos = end
			continue
		}

		result.Write(decoded)
		anyDecoded = true
		lastPos = end
	}

	// Add remaining text
	if lastPos < len(input) {
		result.WriteString(input[lastPos:])
	}

	if !anyDecoded {
		return "", fmt.Errorf("no valid base64url decoded")
	}
	return result.String(), nil
}

// "JBSWY3DP" -> "Hello"
func base32Decoder(input string) (string, error) {
	// Strip whitespace/newlines first for multi-line base32
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, input)
	inputUpper := strings.ToUpper(clean)
	if data, err := base32.StdEncoding.DecodeString(inputUpper); err == nil {
		if isPrintableBytes(data) {
			return string(data), nil
		}
	}

	re := base32Pattern
	matches, _ := findAllStringIndicesLimited(re, inputUpper, maxDecoderCandidateMatches)
	if len(matches) == 0 {
		return "", fmt.Errorf("no base32 found")
	}

	// Use a strings.Builder to prevent index nightmares
	// IMPORTANT: Use original 'clean' for non-base32 parts to preserve case
	var result strings.Builder
	lastPos := 0
	anyDecoded := false

	for _, match := range matches {
		start, end := match[0], match[1]

		// Bounds check to prevent slice panic when input/inputUpper lengths differ
		if start > len(inputUpper) || end > len(inputUpper) {
			continue
		}

		// Add the stuff BEFORE the match (from original 'clean' to preserve case)
		if lastPos < len(clean) && start <= len(clean) {
			result.WriteString(clean[lastPos:start])
		}

		segment := inputUpper[start:end]
		decoded, err := base32.StdEncoding.DecodeString(segment)

		if err == nil && isPrintableBytes(decoded) {
			result.Write(decoded)
			anyDecoded = true
		} else {
			// If it didn't decode right, put the original (not uppercased) back
			if start < len(clean) && end <= len(clean) {
				result.WriteString(clean[start:end])
			} else {
				result.WriteString(segment)
			}
		}
		lastPos = end
	}

	// Add the remaining part of the string (from original 'clean')
	if lastPos < len(clean) {
		result.WriteString(clean[lastPos:])
	}

	if !anyDecoded {
		return "", fmt.Errorf("no valid base32 decoded")
	}
	return result.String(), nil
}

// "48 65 6c 6c 6f" -> "Hello"
func hexWithSpacesDecoder(input string) (string, error) {
	return hexSpacesPattern.ReplaceAllStringFunc(input, func(match string) string {
		clean := strings.ReplaceAll(match, " ", "")
		data, err := hex.DecodeString(clean)
		if err != nil {
			return match
		}
		return string(data)
	}), nil
}

// "48656c6c6f" -> "Hello"
func hexWithoutSpacesDecoder(input string) (string, error) {
	return hexNoSpacesPattern.ReplaceAllStringFunc(input, func(match string) string {
		// Ensure even length for hex decoding
		if len(match)%2 != 0 {
			match = match[:len(match)-1]
		}
		if len(match) < 6 {
			return match
		}
		data, err := hex.DecodeString(match)
		if err != nil {
			return match
		}
		// we keep it if decoded content contains mostly printable chars.
		printable := 0
		for _, b := range data {
			if b >= 32 && b <= 126 {
				printable++
			}
		}
		if float64(printable)/float64(len(data)) > 0.8 {
			return string(data)
		}
		return match
	}), nil
}

// "0x48 0x65 0x6c 0x6c 0x6f" -> "Hello"
func hexWithPrefixDecoder(input string) (string, error) {
	return hexPrefixPattern.ReplaceAllStringFunc(input, func(match string) string {
		clean := strings.ReplaceAll(match, "0x", "")
		clean = strings.ReplaceAll(clean, " ", "")
		data, err := hex.DecodeString(clean)
		if err != nil {
			return match
		}
		return string(data)
	}), nil
}

// "Uryyb" -> "Hello"
func rot13Decoder(input string) (string, error) {
	var result strings.Builder
	for _, r := range input {
		if r >= 'a' && r <= 'z' {
			if r >= 'a'+13 {
				result.WriteRune(r - 13)
			} else {
				result.WriteRune(r + 13)
			}
		} else if r >= 'A' && r <= 'Z' {
			if r >= 'A'+13 {
				result.WriteRune(r - 13)
			} else {
				result.WriteRune(r + 13)
			}
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}

// "w6==@" -> "Hello"
func rot47Decoder(input string) (string, error) {
	var result strings.Builder
	for _, r := range input {
		if r >= '!' && r <= '~' {
			result.WriteRune(33 + ((r + 14) % 94))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}

// "01000001" -> "A"
func binaryDecoder(input string) (string, error) {
	clean := strings.ReplaceAll(input, " ", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")
	if len(clean)%8 == 0 && binaryOnlyPattern.MatchString(clean) {
		var sb strings.Builder
		valid := true
		for i := 0; i < len(clean); i += 8 {
			val, err := strconv.ParseInt(clean[i:i+8], 2, 64)
			if err != nil {
				valid = false
				break
			}
			sb.WriteByte(byte(val))
		}
		if valid && isPrintableBytes([]byte(sb.String())) {
			return sb.String(), nil
		}
	}

	// Fall back to finding embedded binary segments (min 16 bits = 2 chars)
	matches, _ := findAllStringIndicesLimited(binaryPattern, input, maxDecoderCandidateMatches)
	if len(matches) == 0 {
		return "", fmt.Errorf("no binary found")
	}

	result := input
	anyDecoded := false

	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][0], matches[i][1]
		segment := input[start:end]

		// Trim to multiple of 8
		truncLen := (len(segment) / 8) * 8
		if truncLen < 16 {
			continue
		}
		segment = segment[:truncLen]

		var sb strings.Builder
		valid := true
		for j := 0; j < len(segment); j += 8 {
			val, err := strconv.ParseInt(segment[j:j+8], 2, 64)
			if err != nil {
				valid = false
				break
			}
			sb.WriteByte(byte(val))
		}
		if !valid || !isPrintableBytes([]byte(sb.String())) {
			continue
		}

		result = result[:start] + sb.String() + result[start+truncLen:]
		anyDecoded = true
	}

	if !anyDecoded {
		return "", fmt.Errorf("no valid binary decoded")
	}
	return result, nil
}

// "101" -> "A"
func octalDecoder(input string) (string, error) {
	// Find sequences of space-separated octal values (e.g., "110 145 154 154 157")
	matches, _ := findAllStringIndicesLimited(octalPattern, input, maxDecoderCandidateMatches)

	if len(matches) == 0 {
		parts := strings.Fields(input)
		if len(parts) == 0 {
			return "", fmt.Errorf("no octal found")
		}
		var sb strings.Builder
		for _, part := range parts {
			if len(part) > 3 {
				return "", fmt.Errorf("invalid octal chunk")
			}
			val, err := strconv.ParseInt(part, 8, 64)
			if err != nil {
				return "", err
			}
			sb.WriteByte(byte(val))
		}
		if isPrintableBytes([]byte(sb.String())) {
			return sb.String(), nil
		}
		return "", fmt.Errorf("octal not printable")
	}

	result := input
	anyDecoded := false

	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][0], matches[i][1]
		segment := input[start:end]
		parts := strings.Fields(segment)

		var sb strings.Builder
		valid := true
		for _, part := range parts {
			val, err := strconv.ParseInt(part, 8, 64)
			if err != nil || val > 255 {
				valid = false
				break
			}
			sb.WriteByte(byte(val))
		}
		if !valid || !isPrintableBytes([]byte(sb.String())) {
			continue
		}

		result = result[:start] + sb.String() + result[end:]
		anyDecoded = true
	}

	if !anyDecoded {
		return "", fmt.Errorf("no valid octal decoded")
	}
	return result, nil
}

// "%20" -> " "
func urlDecoder(input string) (string, error) {
	return url.QueryUnescape(input)
}

// "&lt;" -> "<"
func htmlEntityDecoder(input string) (string, error) {
	return html.UnescapeString(input), nil
}

// XOR brute-force decoder: tries all single-byte XOR keys (0x01-0xFF)
// Scores every candidate and returns the most text-like result.
func xorBruteForceDecoder(input string) (string, error) {
	data := []byte(input)
	if len(data) == 0 {
		return "", fmt.Errorf("empty input")
	}

	bestScore := math.Inf(-1)
	bestResult := ""

	for key := byte(1); key != 0; key++ { // 1-255
		decoded := make([]byte, len(data))

		for i, b := range data {
			decoded[i] = b ^ key
		}

		score := scoreTextCandidate(string(decoded))
		if score > bestScore {
			bestScore = score
			bestResult = string(decoded)
		}
	}

	if bestScore >= 5.0 {
		return bestResult, nil
	}

	return "", fmt.Errorf("no valid XOR key found")
}

// Atbash cipher: A↔Z, B↔Y, etc.
func atbashDecoder(input string) (string, error) {
	var result strings.Builder
	for _, r := range input {
		if r >= 'a' && r <= 'z' {
			result.WriteRune('z' - (r - 'a'))
		} else if r >= 'A' && r <= 'Z' {
			result.WriteRune('Z' - (r - 'A'))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}

// Morse code decoder
var morseToChar = map[string]rune{
	".-": 'A', "-...": 'B', "-.-.": 'C', "-..": 'D', ".": 'E',
	"..-.": 'F', "--.": 'G', "....": 'H', "..": 'I', ".---": 'J',
	"-.-": 'K', ".-..": 'L', "--": 'M', "-.": 'N', "---": 'O',
	".--.": 'P', "--.-": 'Q', ".-.": 'R', "...": 'S', "-": 'T',
	"..-": 'U', "...-": 'V', ".--": 'W', "-..-": 'X', "-.--": 'Y',
	"--..": 'Z', "-----": '0', ".----": '1', "..---": '2', "...--": '3',
	"....-": '4', ".....": '5', "-....": '6', "--...": '7', "---..": '8',
	"----.": '9', ".-.-.-": '.', "--..--": ',', "..--..": '?',
}

func morseDecoder(input string) (string, error) {
	// Split by word separator (multiple spaces or /)
	words := morseWordPattern.Split(input, -1)
	var result strings.Builder

	for i, word := range words {
		if i > 0 {
			result.WriteRune(' ')
		}
		// Split letters by single space
		letters := strings.Fields(word)
		for _, letter := range letters {
			if ch, ok := morseToChar[letter]; ok {
				result.WriteRune(ch)
			}
		}
	}

	decoded := result.String()
	if decoded == "" {
		return "", fmt.Errorf("no morse code found")
	}
	return decoded, nil
}

func unicodeEscapeDecoder(input string) (string, error) {
	result := unicodePattern.ReplaceAllStringFunc(input, func(match string) string {
		code, err := strconv.ParseInt(match[2:], 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})

	result = hexEscapePattern.ReplaceAllStringFunc(result, func(match string) string {
		code, err := strconv.ParseInt(match[2:], 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})

	if result == input {
		return "", fmt.Errorf("no unicode escapes found")
	}
	return result, nil
}

// Base85/Ascii85 decoder
func base85Decoder(input string) (string, error) {
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "<~") && strings.HasSuffix(s, "~>") {
		s = s[2 : len(s)-2]
	}

	s = strings.ReplaceAll(s, "z", "!!!!!")

	if len(s) == 0 {
		return "", fmt.Errorf("empty base85 input")
	}

	for _, c := range s {
		if (c < '!' || c > 'u') && c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			return "", fmt.Errorf("invalid base85 character: %c", c)
		}
	}

	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)

	if len(s) == 0 {
		return "", fmt.Errorf("empty base85 input after cleanup")
	}

	var result []byte
	for len(s) > 0 {
		chunkLen := 5
		if len(s) < 5 {
			chunkLen = len(s)
		}
		chunk := s[:chunkLen]
		s = s[chunkLen:]

		// Pad with 'u' (84) if needed
		padded := chunk + strings.Repeat("u", 5-chunkLen)

		var value uint32
		for _, c := range padded {
			if c < '!' || c > 'u' {
				return "", fmt.Errorf("invalid base85 character: %c", c)
			}
			// Check for overflow before multiplication
			if value > (math.MaxUint32-uint32(c-'!'))/85 {
				return "", fmt.Errorf("base85 overflow detected")
			}
			value = value*85 + uint32(c-'!')
		}

		numBytes := chunkLen - 1
		if numBytes < 1 {
			numBytes = 1
		}
		if numBytes > 4 {
			numBytes = 4
		}

		decoded := []byte{
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
		result = append(result, decoded[:numBytes]...)
	}

	if len(result) == 0 {
		return "", fmt.Errorf("no base85 data decoded")
	}

	printable := 0
	for _, b := range result {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	if float64(printable)/float64(len(result)) < 0.5 {
		return "", fmt.Errorf("decoded base85 not printable")
	}

	return string(result), nil
}

func caesarBruteForceDecoder(input string) (string, error) {
	inputScore := scoreTextCandidate(input)
	bestResult := ""
	bestScore := math.Inf(-1)
	hasLetters := false

	for shift := 1; shift < 26; shift++ {
		var result strings.Builder
		shiftHasLetters := false

		for _, r := range input {
			// Rotate letters
			if r >= 'a' && r <= 'z' {
				hasLetters = true
				shiftHasLetters = true
				shifted := 'a' + (r-'a'-rune(shift)+26)%26
				result.WriteRune(shifted)
			} else if r >= 'A' && r <= 'Z' {
				hasLetters = true
				shiftHasLetters = true
				shifted := 'A' + (r-'A'-rune(shift)+26)%26
				result.WriteRune(shifted)
			} else {
				result.WriteRune(r)
			}
		}

		if !shiftHasLetters {
			continue
		}

		decoded := result.String()
		score := scoreTextCandidate(decoded)
		if score > bestScore {
			bestScore = score
			bestResult = decoded
		}
	}

	if !hasLetters {
		return "", nil
	}

	if bestScore >= 8.0 && bestScore > inputScore+1.0 {
		return bestResult, nil
	}

	return "", fmt.Errorf("no valid caesar shift found")
}

func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	}
	return false
}
