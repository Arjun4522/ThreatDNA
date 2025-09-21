package main

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

// CTIRecord represents a normalized Cyber Threat Intelligence record
type CTIRecord struct {
	ID       string    `json:"id"`
	Source   string    `json:"source"`
	Date     time.Time `json:"date"`
	Actor    string    `json:"actor,omitempty"`
	Campaign string    `json:"campaign,omitempty"`
	RawText  string    `json:"raw_text"`
	TTPs     []TTP     `json:"ttps,omitempty"`
	IOCs     []IOC     `json:"iocs,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
}

// TTP represents a Tactic, Technique, or Procedure with confidence
type TTP struct {
	TechniqueID string  `json:"technique_id"` // e.g., "T1059"
	Confidence  float64 `json:"confidence"`   // 0.0 - 1.0
	Context     string  `json:"context"`      // surrounding text
	Tactic      string  `json:"tactic,omitempty"`
}

// IOC represents Indicators of Compromise
type IOC struct {
	Type    string `json:"type"`  // ip, domain, hash, etc.
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}

// AttackTechnique contains MITRE ATT&CK technique information
type AttackTechnique struct {
	ID          string
	Name        string
	Description string
	Keywords    []string
	Platforms   []string
	Tactics     []string
}

// TechniqueExtractor handles rule-based technique extraction
type TechniqueExtractor struct {
	techniques  map[string]AttackTechnique
	patterns    map[string]*regexp.Regexp
	iocPatterns map[string]*regexp.Regexp
}

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

// MITREAttackBundle represents the top-level structure of the enterprise-attack.json file.
type MITREAttackBundle struct {
	Objects []MITREObject `json:"objects"`
}

// MITREObject represents a single object within the bundle, which could be an attack-pattern, tactic, etc.
type MITREObject struct {
	Type                string               `json:"type"`
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	Description         string               `json:"description"`
	KillChainPhases     []KillChainPhase     `json:"kill_chain_phases"`
	ExternalReferences  []ExternalReference  `json:"external_references"`
	Platforms           []string             `json:"x_mitre_platforms"`
	IsSubtechnique      bool                 `json:"x_mitre_is_subtechnique"`
}

// KillChainPhase represents the tactic (e.g., initial-access) an attack pattern belongs to.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// ExternalReference contains the mapping to the external ID, like "T1566".
type ExternalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
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

// DataIngester with performance optimizations
type DataIngester struct {
	parser     *CTIParser
	extractor  *TechniqueExtractor
	htmlParser *HTMLParser
}

func NewDataIngester() *DataIngester {
	parser := NewCTIParser()
	htmlParser := NewHTMLParser()
	return &DataIngester{
		parser:     parser,
		htmlParser: htmlParser,
	}
}

func (d *DataIngester) Initialize() error {
	log.Println("🚀 Initializing CTI Parser...")

	// Load full MITRE data from file
	if err := d.parser.LoadMITREDataFromFile("enterprise-attack.json"); err != nil {
		log.Printf("⚠️  Warning: could not load from 'enterprise-attack.json'. Falling back to sample data. Error: %v", err)
		// Fallback to sample data if file loading fails
		return nil // Or handle fallback appropriately
	}

	// Initialize technique extractor
	d.extractor = NewTechniqueExtractor(d.parser.attackData)

	log.Printf("✅ Initialized with %d MITRE techniques", len(d.parser.attackData))
	return nil
}

func (d *DataIngester) IngestDirectory(dirPath string) ([]CTIRecord, error) {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dirPath, err)
	}

	var allRecords []CTIRecord
	
	log.Printf("📁 Found %d files to process", len(files))
	
	for i, file := range files {
		if file.IsDir() {
			continue
		}
		
		log.Printf("📄 Processing file %d/%d: %s", i+1, len(files), file.Name())
		
		filepath := fmt.Sprintf("%s/%s", dirPath, file.Name())
		records, err := d.IngestFileFast(filepath)
		if err != nil {
			log.Printf("⚠️  Warning: failed to ingest %s: %v", filepath, err)
			continue
		}
		
		allRecords = append(allRecords, records...)
		log.Printf("✅ Ingested %d records from %s", len(records), file.Name())
	}
	
	log.Printf("🎉 Completed processing %d files", len(files))
	return allRecords, nil
}

func (d *DataIngester) IngestFileFast(filepath string) ([]CTIRecord, error) {
	ext := strings.ToLower(filepath[strings.LastIndex(filepath, "."):])
	
	var records []CTIRecord
	var err error
	
	switch ext {
	case ".html", ".htm":
		records, err = d.parser.ParseHTMLReportFast(filepath, d.htmlParser)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Process records with progress indication
	for i := range records {
		log.Printf("🔍 Extracting TTPs and IOCs...")
		d.parser.ProcessCTIRecord(&records[i], d.extractor)
		records[i].Source = fmt.Sprintf("file:%s", filepath)
		log.Printf("✅ Found %d TTPs, %d IOCs", len(records[i].TTPs), len(records[i].IOCs))
	}
	
	return records, nil
}

func (p *CTIParser) ProcessCTIRecord(record *CTIRecord, extractor *TechniqueExtractor) {
	record.TTPs = extractor.ExtractTTPs(record.RawText)
	record.IOCs = extractor.ExtractIOCs(record.RawText)
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
		if strings.HasPrefix(value, "127.") || strings.HasPrefix(value, "10.") ||
			strings.HasPrefix(value, "192.168.") {
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

// Main function with progress tracking
func main() {
	startTime := time.Now()
	log.Println("🚀 ThreatDNA CTI Parser - Optimized Version")
	log.Println("=" + strings.Repeat("=", 50))
	
	// Initialize
	ingester := NewDataIngester()
	if err := ingester.Initialize(); err != nil {
		log.Fatal("❌ Failed to initialize:", err)
	}
	
	// Process data directory
	log.Println("\n📁 Processing HTML data Directory...")
	records, err := ingester.IngestDirectory("data")
	if err != nil {
		log.Printf("❌ Error processing directory: %v", err)
		return
	}
	
	// Display results
	log.Printf("\n🎉 Processing complete! Found %d records", len(records))
	
	for i, record := range records {
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
		fmt.Printf("📄 Report %d: %s\n", i+1, record.Source)
		fmt.Printf("🎭 Actor: %s\n", record.Actor)
		fmt.Printf("🚀 Campaign: %s\n", record.Campaign)
		fmt.Printf("📅 Date: %s\n", record.Date.Format("2006-01-02"))
		
		fmt.Printf("\n🎯 TTPs Found: %d\n", len(record.TTPs))
		for _, ttp := range record.TTPs {
			fmt.Printf("  • %s - %s (%.2f confidence)\n", 
				ttp.TechniqueID, ttp.Tactic, ttp.Confidence)
		}
		
		fmt.Printf("\n🔍 IOCs Found: %d\n", len(record.IOCs))
		iocCounts := make(map[string]int)
		for _, ioc := range record.IOCs {
			iocCounts[ioc.Type]++
		}
		for iocType, count := range iocCounts {
			fmt.Printf("  • %s: %d\n", iocType, count)
		}
	}
	
	// Export results
	if jsonData, err := json.MarshalIndent(records, "", "  "); err == nil {
		if err := ioutil.WriteFile("cti_results.json", jsonData, 0644); err == nil {
			log.Printf("\n💾 Results exported to cti_results.json")
		}
	}
	
	duration := time.Since(startTime)
	log.Printf("\n⏱️  Total processing time: %v", duration)
	log.Println("🎉 Analysis complete!")
}