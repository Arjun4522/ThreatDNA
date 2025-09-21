package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"threatdna/internal/threatdnacore"
)

// Main function with progress tracking
func main() {
	startTime := time.Now()
	log.Println("🚀 ThreatDNA CTI Parser - Optimized Version")
	log.Println("=" + strings.Repeat("=", 50))
	
	// Initialize
	ingester := threatdnacore.NewDataIngester()
	if err := ingester.Initialize(); err != nil {
		log.Fatal("❌ Failed to initialize:", err)
	}
	
	// Process data directory
	log.Println("\n📁 Processing HTML data Directory...")
	records, err := ingester.IngestDirectory("data")
	if err != nil {
		log.Printf("❌ Error processing directory: %v", err)
		return
	}
	
	// Display results
	log.Printf("\n🎉 Processing complete! Found %d records", len(records))
	
	for i, record := range records {
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
		fmt.Printf("📄 Report %d: %s\n", i+1, record.Source)
		fmt.Printf("🎭 Actor: %s\n", record.Actor)
		fmt.Printf("🚀 Campaign: %s\n", record.Campaign)
		fmt.Printf("📅 Date: %s\n", record.Date.Format("2006-01-02"))
		
		fmt.Printf("\n🎯 TTPs Found: %d\n", len(record.TTPs))
		for _, ttp := range record.TTPs {
					fmt.Printf("  • %s - %s (%.2f confidence)\n", 
						ttp.TechniqueID, ttp.Tactic, ttp.Confidence)		}
		
		fmt.Printf("\n🔍 IOCs Found: %d\n", len(record.IOCs))
		iocCounts := make(map[string]int)
		for _, ioc := range record.IOCs {
			iocCounts[ioc.Type]++
		}
		for iocType, count := range iocCounts {
			fmt.Printf("  • %s: %d\n", iocType, count)
		}
	}
	
	// Export results
	if jsonData, err := json.MarshalIndent(records, "", "  "); err == nil {
		if err := ioutil.WriteFile("cti_results.json", jsonData, 0644); err == nil {
			log.Printf("\n💾 Results exported to cti_results.json")
		}
	}
	
	duration := time.Since(startTime)
	log.Printf("\n⏱️  Total processing time: %v", duration)
	log.Println("🎉 Analysis complete!")
}
