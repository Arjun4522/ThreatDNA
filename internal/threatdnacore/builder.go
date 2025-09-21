package threatdnacore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/segmentio/kafka-go"
)

// GenomeBuilder creates genomes from CTI records
type GenomeBuilder struct {
	db         *bolt.DB
	KafkaBroker string
	KafkaTopic  string
}

const (
	GenomeBucket = "genomes"
	IndexBucket  = "genome_index"
	StatsBucket  = "genome_stats"
)

// NewGenomeBuilder creates a new genome builder
func NewGenomeBuilder(dbPath, kafkaBroker, kafkaTopic string) (*GenomeBuilder, error) {
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

	return &GenomeBuilder{
		db:         db,
		KafkaBroker: kafkaBroker,
		KafkaTopic:  kafkaTopic,
	}, nil
}

// StartKafkaConsumer starts consuming CTI records from Kafka
func (gb *GenomeBuilder) StartKafkaConsumer(ctx context.Context) {
	log.Printf("Starting Kafka consumer for topic %s on broker %s", gb.KafkaTopic, gb.KafkaBroker)

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{gb.KafkaBroker},
		Topic:    gb.KafkaTopic,
		GroupID:  "threatdna-genome-builder", // Unique consumer group ID
		MinBytes: 10e3,                       // 10KB
		MaxBytes: 10e6,                       // 10MB
		MaxWait:  1 * time.Second,            // Maximum amount of time to wait for new data to become available
	})

	for {
		select {
		case <-ctx.Done():
			log.Println("Kafka consumer stopped.")
			return
		default:
			m, err := r.ReadMessage(ctx)
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

			// Build and save genome for this single CTI record
			// Note: BuildGenome expects a slice, so we pass a slice with one record
			genome, err := gb.BuildGenome([]CTIRecord{record})
			if err != nil {
				log.Printf("Failed to build genome from CTI record %s: %v", record.ID, err)
				continue
			}

			if err := gb.SaveGenome(genome); err != nil {
				log.Printf("Failed to save genome %s: %v", genome.ID, err)
				continue
			}
			log.Printf("Successfully processed and saved genome %s from Kafka message", genome.ID)
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
