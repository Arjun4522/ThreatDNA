package threatdnacore

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// TechniqueExtractor handles rule-based technique extraction
type TechniqueExtractor struct {
	techniques  map[string]AttackTechnique
	patterns    map[string]*regexp.Regexp
	iocPatterns map[string]*regexp.Regexp
}

// NewTechniqueExtractor creates a new technique extractor
func NewTechniqueExtractor(attackData map[string]AttackTechnique) *TechniqueExtractor {
	log.Println("🔧 Initializing technique patterns...")
	
	extractor := &TechniqueExtractor{
		techniques:  attackData,
		patterns:    make(map[string]*regexp.Regexp),
		iocPatterns: make(map[string]*regexp.Regexp),
	}

	// Build optimized regex patterns
	patternCount := 0
	for id, technique := range attackData {
		patterns := []string{
			regexp.QuoteMeta(technique.Name),
			fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(id)),
		}
		
		// Add only high-value keywords
		for _, keyword := range technique.Keywords {
			if len(keyword) > 4 { // Only longer keywords
				patterns = append(patterns, fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(keyword)))
			}
		}

		if len(patterns) > 0 {
			pattern := strings.Join(patterns, "|")
			if compiled, err := regexp.Compile("(?i)" + pattern); err == nil {
				extractor.patterns[id] = compiled
				patternCount++
			}
		}
	}

	// Optimized IOC patterns
	extractor.iocPatterns["ip"] = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	extractor.iocPatterns["domain"] = regexp.MustCompile(`\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,30}[a-zA-Z0-9])?(\.[a-zA-Z]{2,10})+\b`)
	extractor.iocPatterns["hash"] = regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)

	log.Printf("✅ Created %d technique patterns", patternCount)
	return extractor
}

// ExtractTTPs with performance optimization
func (e *TechniqueExtractor) ExtractTTPs(text string) []TTP {
	var ttps []TTP
	seen := make(map[string]bool)

	// Limit text processing for performance
	if len(text) > 50000 {
		text = text[:50000] + "..."
	}

	for techniqueID, pattern := range e.patterns {
		matches := pattern.FindAllStringIndex(text, 3) // Limit to 3 matches per technique
		if len(matches) > 0 {
			if !seen[techniqueID] {
				confidence := calculateConfidence(len(matches), text, techniqueID)
				context := extractContext(text, matches[0][0], matches[0][1], 40)
				
				tactic := ""
				if technique, exists := e.techniques[techniqueID]; exists && len(technique.Tactics) > 0 {
					tactic = technique.Tactics[0]
				}
				
				ttps = append(ttps, TTP{
					TechniqueID: techniqueID,
					Confidence:  confidence,
					Context:     context,
					Tactic:      tactic,
				})
				
				seen[techniqueID] = true
			}
		}
	}

	return ttps
}

// ExtractIOCs with limits
func (e *TechniqueExtractor) ExtractIOCs(text string) []IOC {
	var iocs []IOC
	seen := make(map[string]bool)

	for iocType, pattern := range e.iocPatterns {
		matches := pattern.FindAllString(text, 20) // Limit IOCs per type
		for _, match := range matches {
			key := fmt.Sprintf("%s:%s", iocType, match)
			if !seen[key] && isValidIOC(iocType, match) {
				context := extractIOCContext(text, match, 25)
				iocs = append(iocs, IOC{
					Type:    iocType,
					Value:   match,
					Context: context,
				})
				seen[key] = true
			}
		}
	}

	return iocs
}

// Helper functions (simplified for performance)
func calculateConfidence(matchCount int, text, techniqueID string) float64 {
	baseConfidence := 0.4
	freqBonus := float64(matchCount) * 0.15
	if freqBonus > 0.3 {
		freqBonus = 0.3
	}
	
	if strings.Contains(strings.ToUpper(text), techniqueID) {
		baseConfidence += 0.2
	}
	
	confidence := baseConfidence + freqBonus
	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

func extractContext(text string, start, end, contextLength int) string {
	textLen := len(text)
	contextStart := start - contextLength
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := end + contextLength
	if contextEnd > textLen {
		contextEnd = textLen
	}
	
	context := text[contextStart:contextEnd]
	context = strings.TrimSpace(context)
	
	if contextStart > 0 {
		context = "..." + context
	}
	if contextEnd < textLen {
		context = context + "..."
	}
	
	return context
}

func extractIOCContext(text, ioc string, contextLength int) string {
	index := strings.Index(strings.ToLower(text), strings.ToLower(ioc))
	if index == -1 {
		return ""
	}
	return extractContext(text, index, index+len(ioc), contextLength)
}

func isValidIOC(iocType, value string) bool {
	switch iocType {
	case "ip":
		if strings.HasPrefix(value, "127.") || strings.HasPrefix(value, "10.") {
			return false
		}
	case "domain":
		commonDomains := []string{"microsoft.com", "google.com", "github.com", "example.com"}
		for _, common := range commonDomains {
			if strings.Contains(value, common) {
				return false
			}
		}
	}
	return len(value) > 0
}
