package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"time"
	"github.com/boltdb/bolt"
)

// CTIRecord represents the structure from your cti_results.json
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
	TechniqueID string  `json:"technique_id"`
	Confidence  float64 `json:"confidence"`
	Context     string  `json:"context"`
	Tactic      string  `json:"tactic,omitempty"`
}

// IOC represents Indicators of Compromise
type IOC struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}

// Genome represents a complete threat sequence
type Genome struct {
	ID           string    `json:"id"`
	SourceIDs    []string  `json:"source_ids"`
	Actor        string    `json:"actor,omitempty"`
	Campaign     string    `json:"campaign,omitempty"`
	TTPs         []string  `json:"ttps"`
	Tactics      []string  `json:"tactics"`
	Platforms    []string  `json:"platforms"`
	CVEs         []string  `json:"cves,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Confidence   float64   `json:"confidence"`
	SourceCount  int       `json:"source_count"`
	IOCCount     int       `json:"ioc_count"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// GenomeBuilder creates genomes from CTI records
type GenomeBuilder struct {
	db *bolt.DB
}

// GenomeStats provides analytics on genome collection
type GenomeStats struct {
	TotalGenomes      int                `json:"total_genomes"`
	UniqueActors      int                `json:"unique_actors"`
	UniqueCampaigns   int                `json:"unique_campaigns"`
	AvgGenomeLength   float64            `json:"avg_genome_length"`
	TTPFrequency      map[string]int     `json:"ttp_frequency"`
	TacticFrequency   map[string]int     `json:"tactic_frequency"`
	IOCTypeFrequency  map[string]int     `json:"ioc_type_frequency"`
}

const (
	GenomeBucket = "genomes"
	IndexBucket  = "genome_index"
	StatsBucket  = "genome_stats"
)

// NewGenomeBuilder creates a new genome builder
func NewGenomeBuilder(dbPath string) (*GenomeBuilder, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize buckets
	err = db.Update(func(tx *bolt.Tx) error {
		buckets := []string{GenomeBucket, IndexBucket, StatsBucket}
		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", bucket, err)
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &GenomeBuilder{db: db}, nil
}

// LoadCTIRecords loads CTI records from JSON file
func LoadCTIRecords(filename string) ([]CTIRecord, error) {
	log.Printf("Loading CTI records from %s", filename)
	
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	var records []CTIRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	log.Printf("Loaded %d CTI records", len(records))
	return records, nil
}

// BuildGenome creates a genome from one or more CTI records
func (gb *GenomeBuilder) BuildGenome(records []CTIRecord) (*Genome, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records provided")
	}

	log.Printf("Building genome from %d CTI records", len(records))

	// Aggregate data from all records
	sourceIDs := make(map[string]bool)
	platforms := make(map[string]bool)
	cves := make(map[string]bool)
	var firstSeen, lastSeen time.Time
	var totalConfidence float64
	var allTTPs []TTP
	totalIOCs := 0

	for _, record := range records {
		sourceIDs[record.ID] = true
		
		// Track dates
		if firstSeen.IsZero() || record.Date.Before(firstSeen) {
			firstSeen = record.Date
		}
		if lastSeen.IsZero() || record.Date.After(lastSeen) {
			lastSeen = record.Date
		}

		// Extract platforms and CVEs from tags
		for _, tag := range record.Tags {
			if strings.HasPrefix(strings.ToUpper(tag), "CVE-") {
				cves[tag] = true
			} else if isValidPlatform(tag) {
				platforms[tag] = true
			}
		}

		// Collect TTPs
		allTTPs = append(allTTPs, record.TTPs...)
		totalIOCs += len(record.IOCs)
	}

	// Build the ordered sequence, removing duplicates
	var ttps []string
	var tactics []string
	seenTTPs := make(map[string]bool)

	// Sort TTPs by confidence (highest first)
	sort.Slice(allTTPs, func(i, j int) bool {
		return allTTPs[i].Confidence > allTTPs[j].Confidence
	})

	for _, ttp := range allTTPs {
		techID := ttp.TechniqueID
		
		// Skip duplicates (keep first occurrence due to sorting)
		if seenTTPs[techID] {
			continue
		}
		seenTTPs[techID] = true

		ttps = append(ttps, techID)
		totalConfidence += ttp.Confidence

		// Add tactic
		if ttp.Tactic != "" {
			tactics = append(tactics, ttp.Tactic)
		} else {
			tactics = append(tactics, "unknown")
		}
	}

	// Determine primary actor and campaign
	actor, campaign := determineActorAndCampaign(records)

	// Convert maps to slices
	sourceIDList := make([]string, 0, len(sourceIDs))
	for id := range sourceIDs {
		sourceIDList = append(sourceIDList, id)
	}

	platformList := make([]string, 0, len(platforms))
	for platform := range platforms {
		platformList = append(platformList, platform)
	}

	cveList := make([]string, 0, len(cves))
	for cve := range cves {
		cveList = append(cveList, cve)
	}

	// Calculate overall confidence
	avgConfidence := 0.0
	if len(ttps) > 0 {
		avgConfidence = totalConfidence / float64(len(ttps))
	}
	
	// Create genome
	genome := &Genome{
		ID:          generateGenomeID(ttps, actor, campaign),
		SourceIDs:   sourceIDList,
		Actor:       actor,
		Campaign:    campaign,
		TTPs:        ttps,
		Tactics:     tactics,
		Platforms:   platformList,
		CVEs:        cveList,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
		Confidence:  avgConfidence,
		SourceCount: len(records),
		IOCCount:    totalIOCs,
		Metadata: map[string]interface{}{
			"build_time": time.Now(),
			"ttp_count":  len(ttps),
			"unique_tactics": len(removeDuplicates(tactics)),
		},
	}

	log.Printf("Built genome %s with %d TTPs (confidence: %.2f)", 
		genome.ID, len(genome.TTPs), genome.Confidence)

	return genome, nil
}

// SaveGenome saves genome to database
func (gb *GenomeBuilder) SaveGenome(genome *Genome) error {
	data, err := json.Marshal(genome)
	if err != nil {
		return fmt.Errorf("failed to marshal genome: %w", err)
	}

	return gb.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(GenomeBucket))
		if bucket == nil {
			return fmt.Errorf("genome bucket not found")
		}

		if err := bucket.Put([]byte(genome.ID), data); err != nil {
			return fmt.Errorf("failed to save genome: %w", err)
		}

		log.Printf("Saved genome %s to database", genome.ID)
		return nil
	})
}

// GetGenome retrieves a genome by ID
func (gb *GenomeBuilder) GetGenome(id string) (*Genome, error) {
	var genome Genome

	err := gb.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(GenomeBucket))
		if bucket == nil {
			return fmt.Errorf("genome bucket not found")
		}

		data := bucket.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("genome %s not found", id)
		}

		return json.Unmarshal(data, &genome)
	})

	return &genome, err
}

// ListGenomes returns all genomes with optional filtering
func (gb *GenomeBuilder) ListGenomes(actor, platform string, limit int) ([]*Genome, error) {
	var genomes []*Genome
	count := 0

	err := gb.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(GenomeBucket))
		if bucket == nil {
			return fmt.Errorf("genome bucket not found")
		}

		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if limit > 0 && count >= limit {
				break
			}

			var genome Genome
			if err := json.Unmarshal(value, &genome); err != nil {
				log.Printf("Warning: failed to unmarshal genome %s: %v", string(key), err)
				continue
			}

			// Apply filters
			if actor != "" && !strings.Contains(strings.ToLower(genome.Actor), strings.ToLower(actor)) {
				continue
			}

			if platform != "" {
				found := false
				for _, p := range genome.Platforms {
					if strings.Contains(strings.ToLower(p), strings.ToLower(platform)) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			genomes = append(genomes, &genome)
			count++
		}

		return nil
	})

	return genomes, err
}

// GetGenomeStats computes statistics about the genome collection
func (gb *GenomeBuilder) GetGenomeStats() (*GenomeStats, error) {
	stats := &GenomeStats{
		TTPFrequency:     make(map[string]int),
		TacticFrequency:  make(map[string]int),
		IOCTypeFrequency: make(map[string]int),
	}

	actors := make(map[string]bool)
	campaigns := make(map[string]bool)
	totalLength := 0

	err := gb.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(GenomeBucket))
		if bucket == nil {
			return fmt.Errorf("genome bucket not found")
		}

		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var genome Genome
			if err := json.Unmarshal(value, &genome); err != nil {
				continue
			}

			stats.TotalGenomes++
			totalLength += len(genome.TTPs)

			// Track unique actors and campaigns
			if genome.Actor != "" {
				actors[genome.Actor] = true
			}
			if genome.Campaign != "" {
				campaigns[genome.Campaign] = true
			}

			// Count TTP frequency
			for _, ttp := range genome.TTPs {
				stats.TTPFrequency[ttp]++
			}

			// Count tactic frequency
			for _, tactic := range genome.Tactics {
				if tactic != "unknown" {
					stats.TacticFrequency[tactic]++
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	stats.UniqueActors = len(actors)
	stats.UniqueCampaigns = len(campaigns)
	if stats.TotalGenomes > 0 {
		stats.AvgGenomeLength = float64(totalLength) / float64(stats.TotalGenomes)
	}

	return stats, nil
}

// Close closes the database connection
func (gb *GenomeBuilder) Close() error {
	if gb.db != nil {
		return gb.db.Close()
	}
	return nil
}

// Helper functions
func determineActorAndCampaign(records []CTIRecord) (string, string) {
	actorCounts := make(map[string]int)
	campaignCounts := make(map[string]int)

	for _, record := range records {
		if record.Actor != "" && record.Actor != "Unknown" {
			actorCounts[record.Actor]++
		}
		if record.Campaign != "" {
			campaignCounts[record.Campaign]++
		}
	}

	// Find most common actor
	var bestActor string
	maxActorCount := 0
	for actor, count := range actorCounts {
		if count > maxActorCount {
			maxActorCount = count
			bestActor = actor
		}
	}

	// Find most common campaign  
	var bestCampaign string
	maxCampaignCount := 0
	for campaign, count := range campaignCounts {
		if count > maxCampaignCount {
			maxCampaignCount = count
			bestCampaign = campaign
		}
	}

	return bestActor, bestCampaign
}

func generateGenomeID(ttps []string, actor, campaign string) string {
	content := strings.Join(ttps, "|") + "|" + actor + "|" + campaign
	hash := sha256.Sum256([]byte(content))
	shortHash := fmt.Sprintf("%x", hash)[:12]
	
	timestamp := time.Now().Format("20060102")
	return fmt.Sprintf("G-%s-%s", timestamp, shortHash)
}

func isValidPlatform(tag string) bool {
	validPlatforms := []string{"Windows", "Linux", "macOS", "Android", "iOS", "Network"}
	tagUpper := strings.ToUpper(tag)
	for _, platform := range validPlatforms {
		if strings.ToUpper(platform) == tagUpper {
			return true
		}
	}
	return false
}

func removeDuplicates(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// Main function to build genomes from CTI results
func main() {
	log.Println("🧬 ThreatDNA Genome Builder")
	log.Println("=" + strings.Repeat("=", 50))

	// Load CTI records from JSON file
	records, err := LoadCTIRecords("cti_results.json")
	if err != nil {
		log.Fatalf("Failed to load CTI records: %v", err)
	}

	// Initialize genome builder
	builder, err := NewGenomeBuilder("threat_genomes.db")
	if err != nil {
		log.Fatalf("Failed to create genome builder: %v", err)
	}
	defer builder.Close()

	// Group records by actor for genome building
	recordGroups := make(map[string][]CTIRecord)
	for _, record := range records {
		// Use actor as primary grouping key
		key := record.Actor
		if key == "" || key == "Unknown" {
			// Fallback to campaign or source-based grouping
			if record.Campaign != "" {
				key = "Campaign:" + record.Campaign
			} else {
				key = "Source:" + record.Source
			}
		}
		recordGroups[key] = append(recordGroups[key], record)
	}

	log.Printf("📊 Grouped %d records into %d genome candidates", len(records), len(recordGroups))

	var genomes []*Genome
	// Build genomes for each group
	for groupKey, groupRecords := range recordGroups {
		log.Printf("🧬 Building genome for: %s (%d records)", groupKey, len(groupRecords))
		
		genome, err := builder.BuildGenome(groupRecords)
		if err != nil {
			log.Printf("⚠️  Failed to build genome for %s: %v", groupKey, err)
			continue
		}

		if err := builder.SaveGenome(genome); err != nil {
			log.Printf("⚠️  Failed to save genome %s: %v", genome.ID, err)
			continue
		}

		genomes = append(genomes, genome)
		log.Printf("✅ Genome %s: %d TTPs, %.2f confidence", 
			genome.ID, len(genome.TTPs), genome.Confidence)
	}

	// Display genome collection summary
	log.Printf("\n🎯 Genome Collection Summary:")
	log.Printf("=" + strings.Repeat("=", 40))
	
	for i, genome := range genomes {
		fmt.Printf("\n🧬 Genome %d: %s\n", i+1, genome.ID)
		fmt.Printf("   🎭 Actor: %s\n", genome.Actor)
		fmt.Printf("   🚀 Campaign: %s\n", genome.Campaign)
		fmt.Printf("   📅 Timeline: %s → %s\n", 
			genome.FirstSeen.Format("2006-01-02"), 
			genome.LastSeen.Format("2006-01-02"))
		fmt.Printf("   🎯 TTPs: %v\n", genome.TTPs)
		fmt.Printf("   ⚖️  Tactics: %v\n", removeDuplicates(genome.Tactics))
		fmt.Printf("   💻 Platforms: %v\n", genome.Platforms)
		fmt.Printf("   🔗 Sources: %d\n", len(genome.SourceIDs))
		fmt.Printf("   📊 Confidence: %.2f\n", genome.Confidence)
		fmt.Printf("   🔍 IOCs: %d\n", genome.IOCCount)
	}

	// Display statistics
	stats, err := builder.GetGenomeStats()
	if err != nil {
		log.Printf("⚠️  Failed to get stats: %v", err)
		return
	}

	fmt.Printf("\n📈 Collection Statistics:\n")
	fmt.Printf("=" + strings.Repeat("=", 30) + "\n")
	fmt.Printf("🧬 Total Genomes: %d\n", stats.TotalGenomes)
	fmt.Printf("🎭 Unique Actors: %d\n", stats.UniqueActors)
	fmt.Printf("🚀 Unique Campaigns: %d\n", stats.UniqueCampaigns)
	fmt.Printf("📏 Avg Genome Length: %.1f TTPs\n", stats.AvgGenomeLength)

	// Show top TTPs across all genomes
	fmt.Printf("\n🔥 Most Frequent TTPs:\n")
	type ttpCount struct {
		ttp   string
		count int
	}
	var ttps []ttpCount
	for ttp, count := range stats.TTPFrequency {
		ttps = append(ttps, ttpCount{ttp, count})
	}
	sort.Slice(ttps, func(i, j int) bool { return ttps[i].count > ttps[j].count })
	
	for i, ttp := range ttps {
		if i >= 7 { // Show top 7
			break
		}
		fmt.Printf("  %d. %s - %d genomes\n", i+1, ttp.ttp, ttp.count)
	}

	// Show top tactics
	fmt.Printf("\n⚔️  Most Common Tactics:\n")
	type tacticCount struct {
		tactic string
		count  int
	}
	var tactics []tacticCount
	for tactic, count := range stats.TacticFrequency {
		tactics = append(tactics, tacticCount{tactic, count})
	}
	sort.Slice(tactics, func(i, j int) bool { return tactics[i].count > tactics[j].count })
	
	for i, tactic := range tactics {
		if i >= 5 { // Show top 5
			break
		}
		fmt.Printf("  %d. %s - %d occurrences\n", i+1, 
			strings.Title(strings.ReplaceAll(tactic.tactic, "-", " ")), 
			tactic.count)
	}

	// Export genomes to JSON
	genomesJSON, err := json.MarshalIndent(genomes, "", "  ")
	if err == nil {
		if err := ioutil.WriteFile("threat_genomes.json", genomesJSON, 0644); err == nil {
			log.Printf("\n💾 Genomes exported to threat_genomes.json")
		}
	}

	log.Printf("\n🎉 Genome building complete! Database: threat_genomes.db")
}