package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/blevesearch/bleve/v2"
)

// Genome represents a threat actor's profile from threat_genomes.json
type Genome struct {
	ID          string    `json:"id"`
	SourceIDs   []string  `json:"source_ids"`
	Actor       string    `json:"actor"`
	Campaign    string    `json:"campaign"`
	TTPs        []string  `json:"ttps"`
	Tactics     []string  `json:"tactics"`
	Platforms   []string  `json:"platforms"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Confidence  float64   `json:"confidence"`
	SourceCount int       `json:"source_count"`
}

// CTIRecord represents a single report from cti_results.json
type CTIRecord struct {
	ID      string `json:"id"`
	RawText string `json:"raw_text"`
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

func main() {
	// --- 1. Define and Parse Command-Line Flags ---
	overwrite := flag.Bool("overwrite", false, "If set, delete the existing index before creating a new one.")
	flag.Parse()

	indexPath := "threats.bleve"

	// --- 2. Handle Existing Index ---
	if _, err := os.Stat(indexPath); err == nil {
		// Index path exists
		if *overwrite {
			log.Printf("Index '%s' already exists. Overwriting as requested...", indexPath)
			if err := os.RemoveAll(indexPath); err != nil {
				log.Fatalf("Failed to remove existing index: %v", err)
			}
		} else {
			// Path exists but overwrite flag is not set
			log.Printf("Error: Index '%s' already exists.", indexPath)
			log.Println("Use the --overwrite flag to delete the existing index and rebuild it.")
			os.Exit(1)
		}
	} else if !os.IsNotExist(err) {
		// Some other error occurred trying to stat the path
		log.Fatalf("Error checking index path '%s': %v", indexPath, err)
	}

	// --- 3. Load Source Data ---
	log.Println("Loading source JSON files...")
	genomes, ctiMap := loadData()

	// --- 4. Build the Bleve Index ---
	log.Printf("Creating new Bleve index at '%s'...", indexPath)
	index := createIndex(indexPath)
	defer index.Close()

	// --- 5. Index the Data ---
	log.Println("Indexing documents...")
	indexData(index, genomes, ctiMap)

	log.Println("Indexing complete.")
}

// loadData reads and parses the source JSON files.
func loadData() ([]Genome, map[string]string) {
	genomeData, err := ioutil.ReadFile("threat_genomes.json")
	if err != nil {
		log.Fatalf("Failed to read threat_genomes.json: %v", err)
	}
	var genomes []Genome
	if err := json.Unmarshal(genomeData, &genomes); err != nil {
		log.Fatalf("Failed to parse threat_genomes.json: %v", err)
	}

	ctiData, err := ioutil.ReadFile("cti_results.json")
	if err != nil {
		log.Fatalf("Failed to read cti_results.json: %v", err)
	}
	var ctiRecords []CTIRecord
	if err := json.Unmarshal(ctiData, &ctiRecords); err != nil {
		log.Fatalf("Failed to parse cti_results.json: %v", err)
	}
	ctiMap := make(map[string]string)
	for _, rec := range ctiRecords {
		ctiMap[rec.ID] = rec.RawText
	}
	log.Printf("Loaded %d genomes and %d CTI records.", len(genomes), len(ctiRecords))
	return genomes, ctiMap
}

// createIndex builds and returns a new Bleve index with the correct mapping.
func createIndex(indexPath string) bleve.Index {
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

	index, err := bleve.New(indexPath, indexMapping)
	if err != nil {
		log.Fatalf("Failed to create Bleve index: %v", err)
	}
	return index
}

// indexData enriches and indexes the documents in batches.
func indexData(index bleve.Index, genomes []Genome, ctiMap map[string]string) {

batch := index.NewBatch()
	count := 0

	for _, genome := range genomes {
		var allText string
		for _, sourceID := range genome.SourceIDs {
			if text, ok := ctiMap[sourceID]; ok {
				allText += text + "\n"
			}
		}

		searchDoc := SearchDocument{
			Actor:         genome.Actor,
			Campaign:      genome.Campaign,
			TTPs:          genome.TTPs,
			Tactics:       genome.Tactics,
			Platforms:     genome.Platforms,
			Confidence:    genome.Confidence,
			FirstSeen:     genome.FirstSeen,
			LastSeen:      genome.LastSeen,
			AllSourceText: allText,
			Type:          "genome",
		}

		batch.Index(genome.ID, searchDoc)
		count++

		if count%10 == 0 {
			if err := index.Batch(batch); err != nil {
				log.Printf("Failed to index batch: %v", err)
			}
			batch = index.NewBatch()
		}
	}

	if batch.Size() > 0 {
		if err := index.Batch(batch); err != nil {
			log.Printf("Failed to index final batch: %v", err)
		}
	}
	log.Printf("Successfully indexed %d documents.", count)
}