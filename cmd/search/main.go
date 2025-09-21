package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/blevesearch/bleve/v2"
	"github.com/rs/cors"

	"threatdna/internal/threatdnacore"
)

const indexPath = "threats.bleve"
const listenPort = ":8080"

// searchHandler handles search requests from the frontend
func searchHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for all responses
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	queryStr := r.URL.Query().Get("query")
	if queryStr == "" {
		http.Error(w, "Query parameter 'query' is required", http.StatusBadRequest)
		return
	}

	index, err := bleve.Open(indexPath)
	if err != nil {
		log.Printf("Failed to open index: %v", err)
		http.Error(w, "Internal server error: could not open search index", http.StatusInternalServerError)
		return
	}
	defer index.Close()

	query := bleve.NewMatchQuery(queryStr)
	searchRequest := bleve.NewSearchRequest(query)
	searchRequest.Fields = []string{"id", "actor", "campaign"}
	searchRequest.Size = 10 // Limit results for API

	searchResults, err := index.Search(searchRequest)
	if err != nil {
		log.Printf("Search failed: %v", err)
		http.Error(w, "Internal server error: search failed", http.StatusInternalServerError)
		return
	}

	var apiResults []threatdnacore.APISearchResult
	for _, hit := range searchResults.Hits {
		actor := ""
		if a, ok := hit.Fields["actor"]; ok {
			if actorSlice, isSlice := a.([]interface{}); isSlice && len(actorSlice) > 0 {
				if actorStr, isStr := actorSlice[0].(string); isStr {
					actor = actorStr
				}
			}
		}

		campaign := ""
		if c, ok := hit.Fields["campaign"]; ok {
			if campaignSlice, isSlice := c.([]interface{}); isSlice && len(campaignSlice) > 0 {
				if campaignStr, isStr := campaignSlice[0].(string); isStr {
					campaign = campaignStr
				}
			}
		}

		apiResults = append(apiResults, threatdnacore.APISearchResult{
			ID:       hit.ID,
			Actor:    actor,
			Campaign: campaign,
			Score:    hit.Score,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(apiResults); err != nil {
		log.Printf("Failed to encode search results: %v", err)
		http.Error(w, "Internal server error: could not encode results", http.StatusInternalServerError)
	}
}

func main() {
	log.Printf("Starting ThreatDNA Search API on port %s", listenPort)

	// Setup CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Allow all origins for development
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
	}) 

	hm := http.NewServeMux()
	hm.HandleFunc("/api/search", searchHandler)

	handler := c.Handler(hm)

	log.Fatal(http.ListenAndServe(listenPort, handler))
}
