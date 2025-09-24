package main

import (
	"context"
	"log"
	"os"

	"threatdna/internal/threatdnacore"
)

const dbPath = "threats.bleve/test_genomes.db"

func main() {
	log.Println("Starting ThreatDNA Builder (Consumer & Indexer)")

	kafkaBroker := os.Getenv("KAFKA_BROKER")
	if kafkaBroker == "" {
		kafkaBroker = "localhost:9092"
		log.Printf("KAFKA_BROKER environment variable not set, using default: %s", kafkaBroker)
	}

	kafkaTopic := os.Getenv("KAFKA_TOPIC")
	if kafkaTopic == "" {
		kafkaTopic = "cti-records"
		log.Printf("KAFKA_TOPIC environment variable not set, using default: %s", kafkaTopic)
	}

	builder, err := threatdnacore.NewGenomeBuilder(dbPath, kafkaBroker, kafkaTopic)
	if err != nil {
		log.Fatalf("Failed to create genome builder: %v", err)
	}
	defer builder.Close()

	ctx := context.Background()
	builder.StartKafkaConsumer(ctx)
}
