package utils

import (
	"sort"
	"strconv"
	"strings"
)

// LanguageTag represents a language tag with its quality value
type LanguageTag struct {
	// Language is the language code (e.g., "en-US", "fr", "es-ES")
	Language string
	// Quality is the quality value (0.0 to 1.0), defaults to 1.0 if not specified
	Quality float64
}

// ParseAcceptLanguage parses the Accept-Language header and returns languages
// sorted by their quality values in descending order.
//
// Example input: "da, en-gb;q=0.8, en;q=0.7"
// Returns: [LanguageTag{Language: "da", Quality: 1.0}, LanguageTag{Language: "en-gb", Quality: 0.8}, LanguageTag{Language: "en", Quality: 0.7}]
func ParseAcceptLanguage(acceptLanguage string) []LanguageTag {
	if acceptLanguage == "" {
		return nil
	}

	// Split by comma to get individual language entries
	entries := strings.Split(acceptLanguage, ",")
	var languageTags []LanguageTag

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		var language string
		quality := 1.0 // Default quality value

		// Check if the entry contains a quality value
		if strings.Contains(entry, ";") {
			parts := strings.SplitN(entry, ";", 2)
			language = strings.TrimSpace(parts[0])

			// Parse quality value
			qPart := strings.TrimSpace(parts[1])
			if after, ok := strings.CutPrefix(qPart, "q="); ok {
				qValue := after
				if parsedQ, err := strconv.ParseFloat(qValue, 64); err == nil {
					// Ensure quality is between 0.0 and 1.0
					if parsedQ >= 0.0 && parsedQ <= 1.0 {
						quality = parsedQ
					} else {
						// Quality value out of range, skip this entry
						continue
					}
				} else {
					// Invalid quality value (not a number), default to 1.0
					quality = 1.0
				}
			} else {
				// Invalid quality format (no q=), default to 1.0
				quality = 1.0
			}
		} else {
			language = entry
		}

		// Skip empty languages or invalid quality values
		if language != "" && quality > 0.0 {
			languageTags = append(languageTags, LanguageTag{
				Language: language,
				Quality:  quality,
			})
		}
	}

	// Sort by quality value in descending order (highest quality first)
	sort.Slice(languageTags, func(i, j int) bool {
		// First sort by quality (descending)
		if languageTags[i].Quality != languageTags[j].Quality {
			return languageTags[i].Quality > languageTags[j].Quality
		}
		// If quality is the same, maintain original order (stable sort)
		return i < j
	})

	return languageTags
}

// GetLanguages returns just the language codes from ParseAcceptLanguage
// in order of preference (highest quality first)
func GetLanguages(acceptLanguage string) []string {
	tags := ParseAcceptLanguage(acceptLanguage)
	languages := make([]string, len(tags))
	for i, tag := range tags {
		languages[i] = tag.Language
	}
	return languages
}

// GetPreferredLanguage returns the most preferred language from the Accept-Language header
// Returns empty string if no valid language is found
func GetPreferredLanguage(acceptLanguage string) string {
	tags := ParseAcceptLanguage(acceptLanguage)
	if len(tags) > 0 {
		return tags[0].Language
	}
	return ""
}
