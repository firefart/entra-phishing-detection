package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAcceptLanguage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []LanguageTag
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "single language",
			input: "en-US",
			expected: []LanguageTag{
				{Language: "en-US", Quality: 1.0},
			},
		},
		{
			name:  "multiple languages no quality",
			input: "en-US, fr, es",
			expected: []LanguageTag{
				{Language: "en-US", Quality: 1.0},
				{Language: "fr", Quality: 1.0},
				{Language: "es", Quality: 1.0},
			},
		},
		{
			name:  "languages with quality values",
			input: "da, en-gb;q=0.8, en;q=0.7",
			expected: []LanguageTag{
				{Language: "da", Quality: 1.0},
				{Language: "en-gb", Quality: 0.8},
				{Language: "en", Quality: 0.7},
			},
		},
		{
			name:  "complex example with mixed quality",
			input: "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
			expected: []LanguageTag{
				{Language: "fr-CH", Quality: 1.0},
				{Language: "fr", Quality: 0.9},
				{Language: "en", Quality: 0.8},
				{Language: "de", Quality: 0.7},
				{Language: "*", Quality: 0.5},
			},
		},
		{
			name:  "languages with zero quality (should be filtered)",
			input: "en-US;q=0.8, fr;q=0, es;q=0.7",
			expected: []LanguageTag{
				{Language: "en-US", Quality: 0.8},
				{Language: "es", Quality: 0.7},
			},
		},
		{
			name:  "whitespace handling",
			input: " en-US ; q=0.8 , fr ; q=0.9 , es ",
			expected: []LanguageTag{
				{Language: "es", Quality: 1.0},
				{Language: "fr", Quality: 0.9},
				{Language: "en-US", Quality: 0.8},
			},
		},
		{
			name:  "invalid quality values (should default to 1.0)",
			input: "en-US;q=invalid, fr;q=1.5, es;q=-0.1",
			expected: []LanguageTag{
				{Language: "en-US", Quality: 1.0},
			},
		},
		{
			name:  "quality value with three decimal places",
			input: "en;q=0.800, fr;q=0.900",
			expected: []LanguageTag{
				{Language: "fr", Quality: 0.9},
				{Language: "en", Quality: 0.8},
			},
		},
		{
			name:  "same quality values maintain order",
			input: "en-US;q=0.8, fr;q=0.8, es;q=0.8",
			expected: []LanguageTag{
				{Language: "en-US", Quality: 0.8},
				{Language: "fr", Quality: 0.8},
				{Language: "es", Quality: 0.8},
			},
		},
		{
			name:  "empty entries are ignored",
			input: "en-US, , fr, ,",
			expected: []LanguageTag{
				{Language: "en-US", Quality: 1.0},
				{Language: "fr", Quality: 1.0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseAcceptLanguage(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetLanguages(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "single language",
			input:    "en-US",
			expected: []string{"en-US"},
		},
		{
			name:     "multiple languages with quality",
			input:    "da, en-gb;q=0.8, en;q=0.7",
			expected: []string{"da", "en-gb", "en"},
		},
		{
			name:     "languages sorted by quality",
			input:    "en;q=0.7, fr;q=0.9, de;q=0.8",
			expected: []string{"fr", "de", "en"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetLanguages(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPreferredLanguage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single language",
			input:    "en-US",
			expected: "en-US",
		},
		{
			name:     "multiple languages with quality",
			input:    "da, en-gb;q=0.8, en;q=0.7",
			expected: "da",
		},
		{
			name:     "languages with different quality values",
			input:    "en;q=0.7, fr;q=0.9, de;q=0.8",
			expected: "fr",
		},
		{
			name:     "all languages with zero quality",
			input:    "en;q=0, fr;q=0",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPreferredLanguage(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestAcceptLanguageRealWorldExamples(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Chrome browser",
			input:    "en-US,en;q=0.9,es;q=0.8",
			expected: []string{"en-US", "en", "es"},
		},
		{
			name:     "Firefox browser",
			input:    "en-US,en;q=0.5",
			expected: []string{"en-US", "en"},
		},
		{
			name:     "Safari browser",
			input:    "en-US,en;q=0.9",
			expected: []string{"en-US", "en"},
		},
		{
			name:     "Complex European example",
			input:    "de-AT,de;q=0.9,en;q=0.8,en-US;q=0.7,fr;q=0.6",
			expected: []string{"de-AT", "de", "en", "en-US", "fr"},
		},
		{
			name:     "With wildcard",
			input:    "en-US,en;q=0.8,*;q=0.1",
			expected: []string{"en-US", "en", "*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetLanguages(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}
