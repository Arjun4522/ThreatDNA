package main

import (
	"log"
	"os"

	"threatdna/internal/threatdnacore"
)

const dbPath = "threats.bleve/test_genomes.db"

func main() {
	log.Println("Starting ThreatDNA Builder")

	kafkaBroker := os.Getenv("KAFKA_BROKER")
	if kafkaBroker == "" {
		kafkaBroker = "localhost:9092" // Default Kafka broker address
		log.Printf("KAFKA_BROKER environment variable not set, using default: %s", kafkaBroker)
	}

	kafkaTopic := os.Getenv("KAFKA_TOPIC")
	if kafkaTopic == "" {
		kafkaTopic = "cti-records" // Default Kafka topic
		log.Printf("KAFKA_TOPIC environment variable not set, using default: %s", kafkaTopic)
	}

	builder, err := threatdnacore.NewGenomeBuilder(dbPath, kafkaBroker, kafkaTopic)
	if err != nil {
		log.Fatalf("Failed to create genome builder: %v", err)
	}
	defer builder.Close()

	// Initialize and process data directory
	ingester := threatdnacore.NewDataIngester()
	if err := ingester.Initialize(); err != nil {
		log.Fatalf("Failed to initialize data ingester: %v", err)
	}
	log.Println("📁 Processing HTML data Directory...")
	records, err := ingester.IngestDirectory("data")
	if err != nil {
		log.Printf("❌ Error processing data directory: %v", err)
	} else {
		log.Printf("🎉 Ingested %d records from data directory. Processing...", len(records))
		for _, record := range records {
			genome, err := builder.BuildGenome([]threatdnacore.CTIRecord{record})
			if err != nil {
				log.Printf("❌ Error building genome from ingested record: %v", err)
				continue
			}
			if err := builder.SaveGenome(genome); err != nil {
				log.Printf("❌ Error saving genome from ingested record: %v", err)
			}
		}
		log.Println("✅ Finished processing records from data directory.")
	}

	log.Println("ThreatDNA Builder finished processing data directory.")
	os.Exit(0)
}
