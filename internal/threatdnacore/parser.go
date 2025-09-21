package threatdnacore

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strings"
	"time"
)

// HTMLParser handles HTML document parsing with optimizations
type HTMLParser struct {
	actorPatterns    []*regexp.Regexp
	campaignPatterns []*regexp.Regexp
	datePatterns     []*regexp.Regexp
	maxTextLength    int
}

// CTIParser handles parsing of different CTI formats
type CTIParser struct {
	attackData map[string]AttackTechnique
}

// NewCTIParser creates a new CTI parser instance
func NewCTIParser() *CTIParser {
	return &CTIParser{
		attackData: make(map[string]AttackTechnique),
	}
}

// GetAttackData returns the loaded MITRE ATT&CK data.
func (p *CTIParser) GetAttackData() map[string]AttackTechnique {
	return p.attackData
}

// NewHTMLParser creates an optimized HTML parser
func NewHTMLParser() *HTMLParser {
	return &HTMLParser{
		actorPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(APT\d+|Lazarus|Fancy Bear|Cozy Bear|Sandworm|Midnight Blizzard|Equation Group|Carbanak|FIN\d+|Turla|Silence|TA\d+|UNC\d+|OutSteel|SaintBot)`),
			regexp.MustCompile(`(?i)threat\s+actor[s]?:?\s*([A-Z][a-zA-Z0-9\s-]{3,30})`),
			regexp.MustCompile(`(?i)group[s]?:?\s*([A-Z][a-zA-Z0-9\s-]{3,30})`),
		},
		campaignPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)campaign[s]?:?\s*([A-Z][a-zA-Z0-9\s-]{3,50})`),
			regexp.MustCompile(`(?i)operation[s]?:?\s*([A-Z][a-zA-Z0-9\s-]{3,50})`),
		},
		datePatterns: []*regexp.Regexp{
			regexp.MustCompile(`\d{4}-\d{2}-\d{2}`),
			regexp.MustCompile(`\d{1,2}/\d{1,2}/\d{4}`),
			regexp.MustCompile(`(?i)(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}`),
		},
		maxTextLength: 100000, // Limit text length for performance
	}
}

// LoadMITREDataFromFile loads the comprehensive MITRE ATT&CK dataset from the specified JSON file.
func (p *CTIParser) LoadMITREDataFromFile(filepath string) error {
	log.Printf("Loading full MITRE ATT&CK dataset from %s...", filepath)

	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read MITRE file: %w", err)
	}

	var bundle MITREAttackBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("failed to unmarshal MITRE JSON: %w", err)
	}

	techniques := make(map[string]AttackTechnique)
	for _, obj := range bundle.Objects {
		// We only care about attack patterns (techniques and sub-techniques)
		if obj.Type != "attack-pattern" {
			continue
		}

		var techniqueID string
		for _, ref := range obj.ExternalReferences {
			if ref.SourceName == "mitre-attack" {
				techniqueID = ref.ExternalID
				break
			}
		}

		// Skip if it doesn't have a standard technique ID
		if techniqueID == "" {
			continue
		}

		var tactics []string
		for _, phase := range obj.KillChainPhases {
			if phase.KillChainName == "mitre-attack" {
				tactics = append(tactics, phase.PhaseName)
			}
		}
		
		// Generate keywords from name for searching
		keywords := strings.Split(strings.ToLower(obj.Name), " ")

		techniques[techniqueID] = AttackTechnique{
			ID:          techniqueID,
			Name:        obj.Name,
			Description: obj.Description,
			Keywords:    keywords,
			Platforms:   obj.Platforms,
			Tactics:     tactics,
		}
	}

	p.attackData = techniques
	log.Printf("Loaded %d MITRE techniques from file.", len(techniques))
	return nil
}

// ParseHTMLReportFast parses HTML with timeout and size limits
func (p *CTIParser) ParseHTMLReportFast(filepath string, htmlParser *HTMLParser) ([]CTIRecord, error) {
	log.Printf("📄 Processing: %s", filepath)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Read file with size check
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTML file: %w", err)
	}
	
	// Check file size (limit to 5MB for performance)
	if len(data) > 5*1024*1024 {
		log.Printf("⚠️  Large file detected (%d bytes), truncating for performance", len(data))
		data = data[:5*1024*1024]
	}
	
	// Parse HTML with context
	htmlContent := string(data)
	
	// Quick text extraction without full DOM parsing for large files
	text := extractTextQuick(htmlContent)
	
	// Limit text length
	if len(text) > htmlParser.maxTextLength {
		text = text[:htmlParser.maxTextLength] + "... [truncated]"
	}
	
	// Extract title quickly
	title := extractTitleQuick(htmlContent)
	
	record := CTIRecord{
		ID:      generateID(filepath),
		Source:  fmt.Sprintf("file:%s", filepath),
		Date:    extractDateFromText(text, htmlParser.datePatterns),
		RawText: text,
		Tags:    []string{"html-report"},
	}

	// Extract threat actor information
	if actor := extractActorFromText(text, htmlParser.actorPatterns); actor != "" {
		record.Actor = actor
		log.Printf("🎭 Found actor: %s", actor)
	}

	// Extract campaign information
	if campaign := extractCampaignFromText(text, htmlParser.campaignPatterns); campaign != "" {
		record.Campaign = campaign
		log.Printf("🚀 Found campaign: %s", campaign)
	}

	// If no actor found in text, try filename/title
	if record.Actor == "" {
		record.Actor = extractActorFromTitle(title + " " + filepath)
		if record.Actor != "" {
			log.Printf("🎭 Extracted actor from title: %s", record.Actor)
		}
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("HTML parsing timeout for %s", filepath)
	default:
		return []CTIRecord{record}, nil
	}
}

// Quick text extraction without full DOM parsing
func extractTextQuick(htmlContent string) string {
	// Remove script and style content
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	styleRe := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	htmlContent = scriptRe.ReplaceAllString(htmlContent, " ")
	htmlContent = styleRe.ReplaceAllString(htmlContent, " ")
	
	// Remove HTML tags
	tagRe := regexp.MustCompile(`<[^>]*>`)
	text := tagRe.ReplaceAllString(htmlContent, " ")
	
	// Clean up whitespace
	spaceRe := regexp.MustCompile(`\s+`)
	text = spaceRe.ReplaceAllString(text, " ")
	
	return strings.TrimSpace(text)
}

// Quick title extraction
func extractTitleQuick(htmlContent string) string {
	titleRe := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	matches := titleRe.FindStringSubmatch(htmlContent)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// Helper functions (simplified for performance)
func generateID(filepath string) string {
	return fmt.Sprintf("html_%d_%s", time.Now().Unix(), 
		strings.ReplaceAll(strings.ReplaceAll(filepath, "/", "_"), " ", "_"))
}

func extractDateFromText(text string, patterns []*regexp.Regexp) time.Time {
	for _, pattern := range patterns {
		match := pattern.FindString(text)
		if match != "" {
			formats := []string{"2006-01-02", "1/2/2006", "01/02/2006"}
			for _, format := range formats {
				if date, err := time.Parse(format, match); err == nil {
					return date
				}
			}
		}
	}
	return time.Now()
}

func extractActorFromText(text string, patterns []*regexp.Regexp) string {
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(text)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func extractCampaignFromText(text string, patterns []*regexp.Regexp) string {
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(text)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func extractActorFromTitle(title string) string {
	actorPattern := regexp.MustCompile(`(?i)(APT\d+|Lazarus|Fancy Bear|Cozy Bear|Sandworm|Midnight Blizzard|Carbanak|FIN\d+|Turla|Silence|TA\d+|UNC\d+|OutSteel|SaintBot)`)
	matches := actorPattern.FindStringSubmatch(title)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
