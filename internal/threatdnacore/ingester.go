package threatdnacore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DataIngester handles ingesting raw CTI data from various sources.
type DataIngester struct {
	parser     *CTIParser
	htmlParser *HTMLParser
	mu         sync.Mutex // Mutex to protect concurrent access if needed
}

// NewDataIngester creates a new DataIngester instance.
func NewDataIngester() *DataIngester {
	return &DataIngester{}
}

// Initialize loads the MITRE ATT&CK data and initializes the CTI parser.
func (di *DataIngester) Initialize() error {
	log.Println("🚀 Initializing CTI Parser...")

	mitreData, err := di.loadMitreAttackData("data/enterprise-attack.json")
	if err != nil {
		log.Printf("⚠️  Warning: could not load from 'data/enterprise-attack.json'. Falling back to sample data. Error: %v", err)
		mitreData = di.loadSampleMitreData() // Fallback to sample data
	}

	di.parser = NewCTIParser(mitreData)
	di.htmlParser = NewHTMLParser()
	return nil
}

// IngestDirectory processes all HTML files in a given directory.
func (di *DataIngester) IngestDirectory(dirPath string) ([]CTIRecord, error) {
	var records []CTIRecord
	log.Printf("📁 Found %d files to process", di.countHtmlFiles(dirPath))

	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dirPath, err)
	}

	processedCount := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".html") {
			processedCount++
			log.Printf("📄 Processing file %d/%d: %s", processedCount, di.countHtmlFiles(dirPath), file.Name())
			fullPath := filepath.Join(dirPath, file.Name())
			record, err := di.IngestFileFast(fullPath)
			if err != nil {
				log.Printf("❌ Error ingesting file %s: %v", fullPath, err)
				continue
			}
			records = append(records, *record)
		}
	}

	return records, nil
}

// IngestFileFast processes a single file quickly.
func (di *DataIngester) IngestFileFast(filePath string) (*CTIRecord, error) {
	log.Printf("📄 Processing: %s", filePath)

	// Ensure parser is initialized before use
	if di.parser == nil || di.htmlParser == nil {
		return nil, fmt.Errorf("CTI parser or HTML parser not initialized. Call Initialize() first.")
	}

	records, err := di.htmlParser.ParseHTMLReportFast(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML report: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no records extracted from %s", filePath)
	}

	record := &records[0] // Assuming one record per file for now

	log.Println("🔍 Extracting TTPs and IOCs...")
	di.parser.ProcessCTIRecord(record)

	return record, nil
}

// HTMLParser handles HTML document parsing with optimizations
type HTMLParser struct {
	actorPatterns    []*regexp.Regexp
	campaignPatterns []*regexp.Regexp
	datePatterns     []*regexp.Regexp
	maxTextLength    int
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

// ParseHTMLReportFast parses HTML with timeout and size limits
func (hp *HTMLParser) ParseHTMLReportFast(filepath string) ([]CTIRecord, error) {
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
	if len(text) > hp.maxTextLength {
		text = text[:hp.maxTextLength] + "... [truncated]"
	}

	// Extract title quickly
	title := extractTitleQuick(htmlContent)

	record := CTIRecord{
		ID:      generateID(filepath),
		Source:  fmt.Sprintf("file:%s", filepath),
		Date:    extractDateFromText(text, hp.datePatterns),
		RawText: text,
		Tags:    []string{"html-report"},
	}

	// Extract threat actor information
	if actor := extractActorFromText(text, hp.actorPatterns); actor != "" {
		record.Actor = actor
		log.Printf("🎭 Found actor: %s", actor)
	}

	// Extract campaign information
	if campaign := extractCampaignFromText(text, hp.campaignPatterns); campaign != "" {
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

// Helper functions
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

func (di *DataIngester) loadMitreAttackData(filePath string) (map[string]AttackTechnique, error) {
	log.Printf("Loading full MITRE ATT&CK dataset from %s...", filePath)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read MITRE file: %w", err)
	}

	var bundle MITREAttackBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MITRE JSON: %w", err)
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
			ID:                 techniqueID,
			Name:               obj.Name,
			Description:        obj.Description,
			Keywords:           keywords,
			Platforms:          obj.Platforms,
			Tactics:            tactics,
			ExternalReferences: obj.ExternalReferences,
		}
	}

	log.Printf("Loaded %d MITRE techniques from file.", len(techniques))
	return techniques, nil
}

func (di *DataIngester) loadSampleMitreData() map[string]AttackTechnique {
	log.Println("Loading sample MITRE ATT&CK data...")
	// This is a very minimal sample for demonstration purposes
	return map[string]AttackTechnique{
		"T1003": {
			ID:          "T1003",
			Name:        "OS Credential Dumping",
			Tactics:     []string{"credential-access"},
			Keywords:    []string{"lsass", "mimikatz"},
		},
		"T1059": {
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			Tactics:     []string{"execution"},
			Keywords:    []string{"powershell", "cmd.exe", "bash"},
		},
	}
}

func generateRecordID(filePath string) string {
	hash := sha256.Sum256([]byte(filePath))
	return fmt.Sprintf("%x", hash)
}

func (di *DataIngester) countHtmlFiles(dirPath string) int {
	count := 0
	filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".html") {
			count++
		}
		return nil
	})
	return count
}
