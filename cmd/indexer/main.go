package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/blevesearch/bleve/v2"
	"threatdna/internal/threatdnacore"
)

func main() {
	// --- 1. Define and Parse Command-Line Flags ---
	flag.Parse()

	indexPath := "threats.bleve/bleve_index"

	var index bleve.Index

	// --- 2. Handle Existing Index / Create New ---
	if _, err := os.Stat(indexPath); err == nil {
		// Index path exists, try to open it
		log.Printf("Index '%s' already exists. Opening existing index...", indexPath)
		index, err = bleve.Open(indexPath)
		if err != nil {
			log.Fatalf("Failed to open existing Bleve index: %v", err)
		}
	} else if os.IsNotExist(err) {
		// Index path does not exist, create a new one
		log.Printf("Creating new Bleve index at '%s'...", indexPath)
		index = threatdnacore.CreateBleveIndex(indexPath)
	} else {
		// Some other error occurred trying to stat the path
		log.Fatalf("Error checking index path '%s': %v", indexPath, err)
	}
	defer index.Close()

	// --- 3. Load Source Data from BoltDB ---
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "threats.bleve/test_genomes.db" // Default DB path
		log.Printf("DB_PATH environment variable not set, using default: %s", dbPath)
	}

	var builder *threatdnacore.GenomeBuilder
	var err error

	// Retry opening the database for a certain duration
	const maxRetries = 10
	const retryDelay = 5 * time.Second

	log.Printf("Attempting to open database at %s...", dbPath)
	for i := 0; i < maxRetries; i++ {
		log.Printf("Trying to open database (attempt %d/%d)...", i+1, maxRetries)
		builder, err = threatdnacore.NewGenomeBuilder(dbPath, "", "") // Kafka broker/topic not needed for indexer
		if err == nil {
			log.Println("Successfully opened database.")
			break
		}
		log.Printf("Failed to open database: %v. Retrying in %v...", err, retryDelay)
		time.Sleep(retryDelay)
	}

	if err != nil {
		log.Fatalf("Failed to open database after %d retries: %v", maxRetries, err)
	}
	defer builder.Close()

	log.Println("Loading genomes from BoltDB...")
	genomes, err := builder.ListGenomes("", "", 0) // Get all genomes
	if err != nil {
		log.Fatalf("Failed to list genomes from DB: %v", err)
	}
	log.Printf("Loaded %d genomes from BoltDB.", len(genomes))

	// --- 5. Index the Data ---
	log.Println("Indexing documents...")
	threatdnacore.IndexBleveData(index, genomes)

	log.Println("Indexing complete.")
}