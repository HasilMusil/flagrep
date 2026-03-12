package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestDecodersTable(t *testing.T) {
	decoders := getDecoders()

	tests := []struct {
		name    string
		decoder string
		input   string
		want    string
		wantErr bool
	}{
		{"Reverse", "reverse", "olleH", "Hello", false},
		{"SpaceRemoval", "space_removal", "H e l l o", "Hello", false},
		{"Base64", "base64", "SGVsbG8=", "Hello", false},
		{"Base64URL", "base64_url", "SGVsbG8=", "Hello", false},
		{"Base32", "base32", "JBSWY3DP", "Hello", false},
		{"HexWithSpaces", "hex_with_spaces", "48 65 6c 6c 6f", "Hello", false},
		{"HexWithoutSpaces", "hex_without_spaces", "48656c6c6f", "Hello", false},
		{"HexWithPrefix", "hex_with_prefix", "0x48 0x65 0x6c 0x6c 0x6f", "Hello", false},
		{"Rot13", "rot13", "Uryyb", "Hello", false},
		{"Rot47", "rot47", "w6==@", "Hello", false},
		{"Binary", "binary", "01001000", "H", false},
		{"Octal", "octal", "110 145 154 154 157", "Hello", false},
		{"URL", "url", "%48%65%6c%6c%6f", "Hello", false},
		{"HTML", "html", "&lt;", "<", false},
		{"Atbash", "atbash", "Svool", "Hello", false},
		{"Morse", "morse", ".... . .-.. .-.. ---", "HELLO", false},
		{"Unicode", "unicode_escape", "\\u0048\\u0065\\u006c\\u006c\\u006f", "Hello", false},
		// Missing Padding Case (Should be fixed)
		{"Base64 Missing Padding", "base64", "SGVsbG8", "Hello", false},
		// Error cases
		{"Base64 Invalid", "base64", "InvalidBase64!", "", true},
		{"Binary Invalid", "binary", "12345678", "", true},
		{"Octal Invalid", "octal", "999", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoderFunc, ok := decoders[tt.decoder]
			if !ok {
				t.Fatalf("Decoder %s not found", tt.decoder)
			}
			got, err := decoderFunc(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decoder %s error = %v, wantErr %v", tt.decoder, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Decoder %s = %q, want %q", tt.decoder, got, tt.want)
			}
		})
	}
}

func TestDecoderEntriesOrder(t *testing.T) {
	entries := getDecoderEntries()
	got := make([]string, len(entries))
	for i, entry := range entries {
		got[i] = entry.Name
	}

	want := []string{
		"reverse",
		"space_removal",
		"base64",
		"base64_url",
		"base32",
		"hex_with_spaces",
		"hex_without_spaces",
		"hex_with_prefix",
		"rot13",
		"rot47",
		"binary",
		"octal",
		"url",
		"html",
		"xor_bruteforce",
		"atbash",
		"morse",
		"unicode_escape",
		"base85",
		"caesar",
	}

	if len(got) != len(want) {
		t.Fatalf("got %d decoders, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decoder order mismatch at %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestFindAllStringIndicesLimitedCapsMatches(t *testing.T) {
	re := regexp.MustCompile(`A+`)
	input := strings.Repeat("AAAA ", maxDecoderCandidateMatches+25)

	matches, truncated := findAllStringIndicesLimited(re, input, maxDecoderCandidateMatches)
	if len(matches) != maxDecoderCandidateMatches {
		t.Fatalf("expected %d matches, got %d", maxDecoderCandidateMatches, len(matches))
	}
	if !truncated {
		t.Fatal("expected truncated=true when matches exceed the cap")
	}
}

func FuzzReverse(f *testing.F) {
	f.Add("Hello")
	f.Add("World")
	f.Fuzz(func(t *testing.T, orig string) {
		rev, _ := reverseDecoder(orig)
		doubleRev, _ := reverseDecoder(rev)
		if orig != doubleRev {
			t.Errorf("Double reverse failed: %q -> %q -> %q", orig, rev, doubleRev)
		}
	})
}

func FuzzBase64(f *testing.F) {
	f.Add("SGVsbG8=")
	f.Add("VGhpcyBpcyBhIHRlc3Q=")
	f.Fuzz(func(t *testing.T, input string) {
		// Just ensure it doesn't panic
		base64Decoder(input)
	})
}

func FuzzRot13(f *testing.F) {
	f.Add("Hello")
	f.Fuzz(func(t *testing.T, orig string) {
		rot, _ := rot13Decoder(orig)
		doubleRot, _ := rot13Decoder(rot)
		if orig != doubleRot {
			t.Errorf("Double ROT13 failed: %q -> %q -> %q", orig, rot, doubleRot)
		}
	})
}

func BenchmarkDecoders(b *testing.B) {
	decoders := getDecoders()
	input := "SGVsbG8gV29ybGQh This is a benchmark string for decoders."

	b.Run("Base64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decoders["base64"](input)
		}
	})

	b.Run("Rot13", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decoders["rot13"](input)
		}
	})

	b.Run("Reverse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decoders["reverse"](input)
		}
	})
}

func TestCaesarDecoder(t *testing.T) {
	// Use a longer sentence to ensure vowel/space heuristic works reliably
	want := "The quick brown fox jumps over the lazy dog"
	// Shift by 1 -> "Uif rvjdl cspxo gpy kvnqt pwfs uif mbaz eph"
	input := "Uif rvjdl cspxo gpy kvnqt pwfs uif mbaz eph"

	decoded, err := caesarBruteForceDecoder(input)
	if err != nil {
		t.Fatalf("Caesar decoder failed: %v", err)
	}

	if decoded != want {
		t.Errorf("Caesar decoder got %q, want %q", decoded, want)
	}

	// Shift by 13 (ROT13) -> "Gur dhvpx oebja sbk whzcf bire gur ynml qbt"
	input2 := "Gur dhvpx oebja sbk whzcf bire gur ynml qbt"
	decoded2, err := caesarBruteForceDecoder(input2)
	if err != nil {
		t.Fatalf("Caesar decoder failed for shift 13: %v", err)
	}
	if decoded2 != want {
		t.Errorf("Caesar decoder shift 13 got %q, want %q", decoded2, want)
	}
}
