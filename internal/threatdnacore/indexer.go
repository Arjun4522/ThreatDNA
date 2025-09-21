package threatdnacore

import (
	"log"
	"time"

	"github.com/blevesearch/bleve/v2"
)

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

// loadData reads and parses the source JSON files.

// createIndex builds and returns a new Bleve index with the correct mapping.
func CreateBleveIndex(indexPath string) bleve.Index {
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
func IndexBleveData(index bleve.Index, genomes []*Genome) {

	batch := index.NewBatch()
	count := 0

	for _, genome := range genomes {
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
