
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/blevesearch/bleve/v2"
)

func main() {
	// --- 1. Check for Query and Open Index ---
	if len(os.Args) < 2 {
		log.Fatalf("Usage: go run search.go <query>")
	}
	queryStr := os.Args[1]
	indexPath := "threats.bleve"

	index, err := bleve.Open(indexPath)
	if err != nil {
		log.Fatalf("Failed to open index: %v", err)
	}

	// --- 2. Build a simple Match Query ---
	log.Printf(`Searching for "%s"...\n`, queryStr)
	query := bleve.NewMatchQuery(queryStr)

	searchRequest := bleve.NewSearchRequest(query)
	searchRequest.Fields = []string{"actor", "campaign"} 
	searchRequest.Size = 5 // Ask for the top 5 results

	// --- 3. Execute the Search ---
	searchResults, err := index.Search(searchRequest)
	if err != nil {
		log.Fatalf("Search failed: %v", err)
	}

	// --- 4. Print Results ---
	fmt.Printf("\n--- Search Results (%d hits) ---", searchResults.Total)
	for i, hit := range searchResults.Hits {
		fmt.Printf("%d. Document ID: %s (Score: %.2f)\n", i+1, hit.ID, hit.Score)
		fmt.Printf("   Actor: %v\n", hit.Fields["actor"])
		fmt.Printf("   Campaign: %v\n", hit.Fields["campaign"])
		fmt.Println("-------------------------------------")
	}

	if err := index.Close(); err != nil {
		log.Printf("Failed to close index: %v", err)
	}
}
