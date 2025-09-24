package threatdnacore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/segmentio/kafka-go"
)

// GenomeBuilder processes CTI records, builds threat genomes, and manages their storage and Kafka interactions.
type GenomeBuilder struct {
	db          bleve.Index
	kafkaReader *kafka.Reader
	dbPath      string
	mu          sync.Mutex // Mutex to protect concurrent DB access
}

// NewGenomeBuilder creates a new instance of GenomeBuilder.
func NewGenomeBuilder(dbPath, kafkaBroker, kafkaTopic string) (*GenomeBuilder, error) {
	// Ensure the directory for the Bleve database exists
	dir := dbPath[:len(dbPath)-len("/test_genomes.db")] // Extract directory from dbPath
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	db, err := bleve.Open(dbPath)
	if err == bleve.ErrorIndexPathDoesNotExist {
		log.Printf("Creating new Bleve index at %s...", dbPath)
		indexMapping := CreateBleveIndexMapping()
		db, err = bleve.New(dbPath, indexMapping)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	builder := &GenomeBuilder{
		db:     db,
		dbPath: dbPath,
	}

	builder.kafkaReader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{kafkaBroker},
		Topic:    kafkaTopic, // This is the topic the builder consumes from
		GroupID:  "threatdna-builder-group",
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
		MaxAttempts: 10,
		Dialer: &kafka.Dialer{
			Timeout:   10 * time.Second,
			DualStack: true,
		},
	})

	return builder, nil
}

// StartKafkaConsumer starts consuming CTI records from Kafka
func (gb *GenomeBuilder) StartKafkaConsumer(ctx context.Context) {
	log.Printf("Starting Kafka consumer for topic %s on broker %s", gb.kafkaReader.Config().Topic, gb.kafkaReader.Config().Brokers[0])

	for {
		select {
		case <-ctx.Done():
			log.Println("Kafka consumer stopped.")
			return
		default:
			m, err := gb.kafkaReader.ReadMessage(ctx)
			if err != nil {
				log.Printf("Error reading message from Kafka: %v", err)
				continue
			}

			log.Printf("Received message from Kafka topic %s, partition %d, offset %d: %s",
				m.Topic, m.Partition, m.Offset, string(m.Value))

			var record CTIRecord
			if err := json.Unmarshal(m.Value, &record); err != nil {
				log.Printf("Failed to unmarshal CTI record from Kafka message: %v", err)
				continue
			}

			genome, err := gb.BuildGenome([]CTIRecord{record})
			if err != nil {
				log.Printf("Failed to build genome from CTI record %s: %v", record.ID, err)
				continue
			}

			if err := gb.indexGenome(genome); err != nil {
				log.Printf("Failed to index genome %s: %v", genome.ID, err)
				continue
			}
			log.Printf("Successfully processed and indexed genome %s from Kafka message", genome.ID)
		}
	}
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

	var allSourceTextBuilder strings.Builder
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

		// Aggregate RawText
		allSourceTextBuilder.WriteString(record.RawText)
		allSourceTextBuilder.WriteString("\n") // Add a newline for separation
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
		AllSourceText: allSourceTextBuilder.String(),
		Metadata: map[string]interface{}{
			"build_time": time.Now(),
			"ttp_count":  len(ttps),
			"unique_tactics": len(RemoveDuplicates(tactics)),
		},
	}

	log.Printf("Built genome %s with %d TTPs (confidence: %.2f)",
		genome.ID, len(genome.TTPs), genome.Confidence)

	return genome, nil
}

// indexGenome enriches and indexes the document.
func (gb *GenomeBuilder) indexGenome(genome *Genome) error {
	searchDoc := SearchDocument{
		Actor:         genome.Actor,
		Campaign:      genome.Campaign,
		TTPs:          genome.TTPs,
		Tactics:       genome.Tactics,
		Platforms:     genome.Platforms,
		Confidence:    genome.Confidence,
		FirstSeen:     genome.FirstSeen,
		LastSeen:      genome.LastSeen,
		AllSourceText: genome.AllSourceText,
		Type:          "genome",
	}

	return gb.db.Index(genome.ID, searchDoc)
}

// Close closes the Bleve database and Kafka connections.
func (gb *GenomeBuilder) Close() error {
	if gb.db != nil {
		if err := gb.db.Close(); err != nil {
			log.Printf("Error closing Bleve database: %v", err)
		}
	}
	if gb.kafkaReader != nil {
		if err := gb.kafkaReader.Close(); err != nil {
			log.Printf("Error closing Kafka reader: %v", err)
		}
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

func RemoveDuplicates(items []string) []string {
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

// SearchDocument is the enriched document we will store in the Bleve index.
type SearchDocument struct {
	Actor           string    `json:"actor"`
	Campaign        string    `json:"campaign"`
	TTPs            []string  `json:"ttps"`
	Tactics         []string  `json:"tactics"`
	Platforms       []string  `json:"platforms"`
	Confidence      float64   `json:"confidence"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	AllSourceText   string    `json:"all_source_text"`
	Type            string    `json:"type"`
}

// createIndex builds and returns a new Bleve index with the correct mapping.
func CreateBleveIndexMapping() *mapping.IndexMappingImpl {
	keywordFieldMapping := bleve.NewKeywordFieldMapping()
	testFieldMapping := bleve.NewTextFieldMapping()

	docMapping := bleve.NewDocumentMapping()
	docMapping.AddFieldMappingsAt("actor", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("campaign", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("ttps", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("tactics", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("platforms", keywordFieldMapping)
	docMapping.AddFieldMappingsAt("all_source_text", testFieldMapping)

	indexMapping := bleve.NewIndexMapping()
	indexMapping.AddDocumentMapping("genome", docMapping)

	return indexMapping
}
