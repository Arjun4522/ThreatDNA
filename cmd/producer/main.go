package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
	"threatdna/internal/threatdnacore"
)

func main() {
	log.Println("Starting ThreatDNA Kafka Producer")

	kafkaBroker := os.Getenv("KAFKA_BROKER")
	if kafkaBroker == "" {
		kafkaBroker = "localhost:9093" // Default Kafka broker address
		log.Printf("KAFKA_BROKER environment variable not set, using default: %s", kafkaBroker)
	}

	kafkaTopic := os.Getenv("KAFKA_TOPIC")
	if kafkaTopic == "" {
		kafkaTopic = "cti-records" // Default Kafka topic
		log.Printf("KAFKA_TOPIC environment variable not set, using default: %s", kafkaTopic)
	}

	ctiFile := os.Getenv("CTI_FILE")
	if ctiFile == "" {
		ctiFile = "enterprise-attack.json" // Default CTI file
		log.Printf("CTI_FILE environment variable not set, using default: %s", ctiFile)
	}

	// Load CTI records from JSON file
	log.Printf("Loading CTI records from %s", ctiFile)
	data, err := ioutil.ReadFile(ctiFile)
	if err != nil {
		log.Fatalf("Failed to read file %s: %v", ctiFile, err)
	}

	var mitreBundle threatdnacore.MITREAttackBundle
	if err := json.Unmarshal(data, &mitreBundle); err != nil {
		log.Fatalf("Failed to parse JSON from %s into MITREAttackBundle: %v", ctiFile, err)
	}
	log.Printf("Loaded %d objects from %s", len(mitreBundle.Objects), ctiFile)

	// Create a Kafka writer
	w := &kafka.Writer{
		Addr:     kafka.TCP(kafkaBroker),
		Topic:    kafkaTopic,
		Balancer: &kafka.LeastBytes{},
		BatchTimeout: 10 * time.Millisecond, // Flush messages more frequently
	}
	defer w.Close()

	ctx := context.Background()
	var messages []kafka.Message

	for _, obj := range mitreBundle.Objects {
		// Only process 'attack-pattern' objects for now as a simplified CTIRecord
		if obj.Type == "attack-pattern" {
			// Simplified conversion from MITREObject to CTIRecord
			// In a real system, this would be a more sophisticated parsing/extraction
			var ttps []threatdnacore.TTP
			var tags []string
			var tactics []string

			for _, extRef := range obj.ExternalReferences {
				if extRef.SourceName == "mitre-attack" && extRef.ExternalID != "" {
					ttps = append(ttps, threatdnacore.TTP{TechniqueID: extRef.ExternalID, Confidence: 0.7, Context: obj.Name})
				}
			}
			for _, platform := range obj.Platforms {
				tags = append(tags, platform)
			}
			for _, kc := range obj.KillChainPhases {
				tactics = append(tactics, kc.PhaseName)
			}

			// Create a basic CTIRecord
			ctiRecord := threatdnacore.CTIRecord{
				ID:       obj.ID,
				Source:   "MITRE ATT&CK",
				Date:     time.Now(), // Use current time for simplicity
				Actor:    "",         // Actors are not directly in attack-pattern objects
				Campaign: "",       // Campaigns are not directly in attack-pattern objects
				RawText:  obj.Description,
				TTPs:     ttps,
				IOCs:     []threatdnacore.IOC{}, // No direct IOCs in attack-pattern
				Tags:     tags,
			}

			messageBody, err := json.Marshal(ctiRecord)
			if err != nil {
				log.Printf("Failed to marshal CTIRecord for %s: %v", ctiRecord.ID, err)
				continue
			}
			messages = append(messages, kafka.Message{
				Key:   []byte(ctiRecord.ID),
				Value: messageBody,
			})
		}
	}

	log.Printf("Publishing %d CTIRecords (derived from MITRE ATT&CK) to Kafka topic %s on broker %s", len(messages), kafkaTopic, kafkaBroker)

	err = w.WriteMessages(ctx, messages...)
	if err != nil {
		log.Fatalf("Failed to write messages to Kafka: %v", err)
	}

	log.Printf("Successfully published all derived CTIRecords to Kafka.")
}
