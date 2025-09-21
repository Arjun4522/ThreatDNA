package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"threatdna/internal/threatdnacore"
)

const dbPath = "threats.bleve/genomes.db"

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Kafka consumer in a goroutine
	go builder.StartKafkaConsumer(ctx)

	log.Println("ThreatDNA Builder started. Waiting for CTI records from Kafka...")

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down ThreatDNA Builder...")
	cancel() // Signal consumer to stop
}
