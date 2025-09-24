package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/segmentio/kafka-go"

	"threatdna/internal/threatdnacore"
)

func main() {
	log.Println("Starting ThreatDNA Producer")

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

	writer := &kafka.Writer{
		Addr:     kafka.TCP(kafkaBroker),
		Topic:    kafkaTopic,
		Balancer: &kafka.LeastBytes{},
		BatchTimeout: 10 * time.Millisecond,
		RequiredAcks: kafka.RequireOne,
	}
	defer writer.Close()

	log.Println("Publishing initial data to Kafka...")
	publishInitialData(writer, kafkaTopic)
}

func publishInitialData(writer *kafka.Writer, topic string) {
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
		log.Printf("🎉 Ingested %d records from data directory. Publishing to Kafka...", len(records))
		for _, record := range records {
			data, err := json.Marshal(record)
			if err != nil {
				log.Printf("❌ Error marshaling record %s: %v", record.ID, err)
				continue
			}
			msg := kafka.Message{
				Key:   []byte(record.ID),
				Value: data,
			}
			if err := writer.WriteMessages(context.Background(), msg); err != nil {
				log.Printf("❌ Error publishing record %s to Kafka: %v", record.ID, err)
			}
		}
		log.Println("✅ Finished publishing records from data directory.")
	}
}