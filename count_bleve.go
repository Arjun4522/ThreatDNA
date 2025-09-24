package main

import (
	"fmt"
	"log"

	"github.com/blevesearch/bleve/v2"
)

func main() {
	indexPath := "/app/threats.bleve/test_genomes.db"

	index, err := bleve.Open(indexPath)
	if err != nil {
		log.Fatalf("Failed to open Bleve index: %v", err)
	}
	defer index.Close()

	count, err := index.DocCount()
	if err != nil {
		log.Fatalf("Failed to get document count: %v", err)
	}
	fmt.Printf("Total documents in Bleve index: %d\n", count)
}
