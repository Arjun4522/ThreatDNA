package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"

	"threatdna/internal/threatdnacore"
)

// Main function to build genomes from CTI results
func main() {
	log.Println("🧬 ThreatDNA Genome Builder")
	log.Println("=" + strings.Repeat("=", 50))

	// Load CTI records from JSON file
	records, err := threatdnacore.LoadCTIRecords("cti_results.json")
	if err != nil {
		log.Fatalf("Failed to load CTI records: %v", err)
	}

	// Initialize genome builder
	builder, err := threatdnacore.NewGenomeBuilder("threat_genomes.db")
	if err != nil {
		log.Fatalf("Failed to create genome builder: %v", err)
	}
	defer builder.Close()

	// Group records by actor for genome building
	recordGroups := make(map[string][]threatdnacore.CTIRecord)
	for _, record := range records {
		// Use actor as primary grouping key
		key := record.Actor
		if key == "" || key == "Unknown" {
			// Fallback to campaign or source-based grouping
			if record.Campaign != "" {
				key = "Campaign:" + record.Campaign
			} else {
				key = "Source:" + record.Source
			}
		}
		recordGroups[key] = append(recordGroups[key], record)
	}

	log.Printf("📊 Grouped %d records into %d genome candidates", len(records), len(recordGroups))

	var genomes []*threatdnacore.Genome
	// Build genomes for each group
	for groupKey, groupRecords := range recordGroups {
		log.Printf("🧬 Building genome for: %s (%d records)", groupKey, len(groupRecords))
		
		genome, err := builder.BuildGenome(groupRecords)
		if err != nil {
			log.Printf("⚠️  Failed to build genome for %s: %v", groupKey, err)
			continue
		}

		if err := builder.SaveGenome(genome); err != nil {
			log.Printf("⚠️  Failed to save genome %s: %v", genome.ID, err)
			continue
		}

		genomes = append(genomes, genome)
		log.Printf("✅ Genome %s: %d TTPs, %.2f confidence", 
			genome.ID, len(genome.TTPs), genome.Confidence)
	}

	// Display genome collection summary
	log.Printf("\n🎯 Genome Collection Summary:")
	log.Printf("=" + strings.Repeat("=", 40))
	
	for i, genome := range genomes {
		fmt.Printf("\n🧬 Genome %d: %s\n", i+1, genome.ID)
		fmt.Printf("   🎭 Actor: %s\n", genome.Actor)
		fmt.Printf("   🚀 Campaign: %s\n", genome.Campaign)
		fmt.Printf("   📅 Timeline: %s → %s\n", 
			genome.FirstSeen.Format("2006-01-02"), 
			genome.LastSeen.Format("2006-01-02"))
		fmt.Printf("   🎯 TTPs: %v\n", genome.TTPs)
		fmt.Printf("   ⚖️  Tactics: %v\n", threatdnacore.RemoveDuplicates(genome.Tactics))
		fmt.Printf("   💻 Platforms: %v\n", genome.Platforms)
		fmt.Printf("   🔗 Sources: %d\n", len(genome.SourceIDs))
		fmt.Printf("   📊 Confidence: %.2f\n", genome.Confidence)
		fmt.Printf("   🔍 IOCs: %d\n", genome.IOCCount)
	}

	// Display statistics
	stats, err := builder.GetGenomeStats()
	if err != nil {
		log.Printf("⚠️  Failed to get stats: %v", err)
		return
	}

	fmt.Printf("\n📈 Collection Statistics:\n")
	fmt.Printf("=" + strings.Repeat("=", 30) + "\n")
	fmt.Printf("🧬 Total Genomes: %d\n", stats.TotalGenomes)
	fmt.Printf("🎭 Unique Actors: %d\n", stats.UniqueActors)
	fmt.Printf("🚀 Unique Campaigns: %d\n", stats.UniqueCampaigns)
	fmt.Printf("📏 Avg Genome Length: %.1f TTPs\n", stats.AvgGenomeLength)

	// Show top TTPs across all genomes
	fmt.Printf("\n🔥 Most Frequent TTPs:\n")
	type ttpCount struct {
		ttp   string
		count int
	}
	var ttps []ttpCount
	for ttp, count := range stats.TTPFrequency {
		ttps = append(ttps, ttpCount{ttp, count})
	}
	sort.Slice(ttps, func(i, j int) bool { return ttps[i].count > ttps[j].count })
	
	for i, ttp := range ttps {
		if i >= 7 { // Show top 7
			break
		}
		fmt.Printf("  %d. %s - %d genomes\n", i+1, ttp.ttp, ttp.count)
	}

	// Show top tactics
	fmt.Printf("\n⚔️  Most Common Tactics:\n")
	type tacticCount struct {
		tactic string
		count  int
	}
	var tactics []tacticCount
	for tactic, count := range stats.TacticFrequency {
		tactics = append(tactics, tacticCount{tactic, count})
	}
	sort.Slice(tactics, func(i, j int) bool { return tactics[i].count > tactics[j].count })
	
	for i, tactic := range tactics {
		if i >= 5 { // Show top 5
			break
		}
		fmt.Printf("  %d. %s - %d occurrences\n", i+1, 
			strings.Title(strings.ReplaceAll(tactic.tactic, "-", " ")), 
			tactic.count)
	}

	// Export genomes to JSON
	genomesJSON, err := json.MarshalIndent(genomes, "", "  ")
	if err == nil {
		if err := ioutil.WriteFile("threat_genomes.json", genomesJSON, 0644); err == nil {
			log.Printf("\n💾 Genomes exported to threat_genomes.json")
		}
	}

	log.Printf("\n🎉 Genome building complete! Database: threat_genomes.db")
}
