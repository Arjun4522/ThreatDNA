package main

import (
	"flag"
	"log"
	"os"

	"threatdna/internal/threatdnacore"
)

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
	genomes, ctiMap := threatdnacore.LoadIndexerData()

	// --- 4. Build the Bleve Index ---
	log.Printf("Creating new Bleve index at '%s'...", indexPath)
	index := threatdnacore.CreateBleveIndex(indexPath)
	defer index.Close()

	// --- 5. Index the Data ---
	log.Println("Indexing documents...")
	threatdnacore.IndexBleveData(index, genomes, ctiMap)

	log.Println("Indexing complete.")
}
