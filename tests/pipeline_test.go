package tests

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"threatdna/internal/threatdnacore"
)

const (
	testDBPath    = "./threats.bleve/threat_genomes.db" // Relative to project root
	testKafkaBroker = "localhost:9093"
	testKafkaTopic  = "test-cti-records"
	ctiFile       = "../enterprise-attack.json" // Relative to tests/ directory
)

func TestMain(m *testing.M) {
	// Setup: Ensure Kafka is running and clean up before tests
	log.Println("Setting up test environment...")
	err := setupKafkaAndDB()
	if err != nil {
		log.Fatalf("Failed to set up Kafka and DB for tests: %v", err)
	}

	// Run tests
	code := m.Run()

	// Teardown: Clean up after tests
	log.Println("Tearing down test environment...")
	teardownKafkaAndDB()

	os.Exit(code)
}

func setupKafkaAndDB() error {
	// Ensure Docker Compose is up
	cmd := exec.Command("docker-compose", "up", "-d")
	cmd.Dir = ".." // Run docker-compose from project root
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start docker-compose: %v\n%s", err, output)
	}
	log.Println("Docker Compose started.")

	// Give Kafka some time to start up
	time.Sleep(10 * time.Second)

	// Create test topic
	conn, err := kafka.DialContext(context.Background(), "tcp", testKafkaBroker)
	if err != nil {
		return fmt.Errorf("failed to dial kafka broker: %w", err)
	}
	defer conn.Close()

	err = conn.CreateTopics(kafka.TopicConfig{
		Topic:             testKafkaTopic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create kafka topic %s: %w", testKafkaTopic, err)
	}
	log.Printf("Kafka topic %s ensured.", testKafkaTopic)

	// Clear test DB
	os.Remove(testDBPath)
	log.Printf("Cleared test database: %s", testDBPath)

	return nil
}

func teardownKafkaAndDB() {
	// Stop Docker Compose
	cmd := exec.Command("docker-compose", "down")
	cmd.Dir = ".." // Run docker-compose from project root
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to stop docker-compose: %v\n%s", err, output)
	}
	log.Println("Docker Compose stopped.")

	// Delete test topic (optional, but good for clean slate)
	conn, err := kafka.DialContext(context.Background(), "tcp", testKafkaBroker)
	if err == nil {
		defer conn.Close()
		conn.DeleteTopics(testKafkaTopic)
		log.Printf("Deleted Kafka topic %s.", testKafkaTopic)
	}

	// Clean up test DB
	os.Remove(testDBPath)
	log.Printf("Cleaned up test database: %s", testDBPath)
}

func TestPipelineEndToEnd(t *testing.T) {
	// Ensure DB is clean before this specific test
	os.Remove(testDBPath)

	// 1. Start builder in background
	log.Println("Starting builder for end-to-end test...")
	builderCmd := exec.Command("go", "run", "./cmd/builder/main.go")
	builderCmd.Env = append(os.Environ(),
		fmt.Sprintf("KAFKA_BROKER=%s", testKafkaBroker),
		fmt.Sprintf("KAFKA_TOPIC=%s", testKafkaTopic),
		fmt.Sprintf("DB_PATH=%s", testDBPath), // Pass test DB path
	)
	builderCmd.Dir = ".." // Run builder from project root
	// builderOutput, err := builderCmd.StderrPipe() // Removed unused variable
	builderStderr, err := builderCmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to get builder stderr pipe: %v", err)
	}
	builderStdout, err := builderCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to get builder stdout pipe: %v", err)
	}

	if err := builderCmd.Start(); err != nil {
		t.Fatalf("Failed to start builder: %v", err)
	}

	go func() {
		slurp, _ := io.ReadAll(builderStderr)
		if len(slurp) > 0 {
			t.Logf("Builder Stderr: %s", slurp)
		}
	}()
	go func() {
		slurp, _ := io.ReadAll(builderStdout)
		if len(slurp) > 0 {
			t.Logf("Builder Stdout: %s", slurp)
		}
	}()
	defer func() {
		builderCmd.Process.Kill()
		builderCmd.Wait()
		log.Println("Builder stopped.")
	}()

	// Give builder some time to start Kafka consumer
	time.Sleep(5 * time.Second)

	// 2. Run producer to publish CTI data
	log.Println("Running producer to publish CTI data...")
	producerCmd := exec.Command("go", "run", "./cmd/producer/main.go")
	producerCmd.Env = append(os.Environ(),
		fmt.Sprintf("KAFKA_BROKER=%s", testKafkaBroker),
		fmt.Sprintf("KAFKA_TOPIC=%s", testKafkaTopic),
		fmt.Sprintf("CTI_FILE=%s", ctiFile),
	)
	producerCmd.Dir = ".." // Run producer from project root
	producerOutput, err := producerCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Producer failed: %v\n%s", err, producerOutput)
	}
	log.Printf("Producer output:\n%s", producerOutput)

	// Give builder time to process messages
	time.Sleep(10 * time.Second)

	// 3. Stop builder (to release DB lock)
	log.Println("Stopping builder to release DB lock...")
	builderCmd.Process.Kill()
	builderCmd.Wait()

	// 4. Query genome count
	log.Println("Querying genome count...")
	builder, err := threatdnacore.NewGenomeBuilder(testDBPath, "", "")
	if err != nil {
		t.Fatalf("Failed to create genome builder for stats: %v", err)
	}
	defer builder.Close()

	stats, err := builder.GetGenomeStats()
	if err != nil {
		t.Fatalf("Failed to get genome statistics: %v", err)
	}

	expectedGenomes := 823 // Based on previous producer run
	if stats.TotalGenomes != expectedGenomes {
		t.Errorf("Expected %d genomes, got %d", expectedGenomes, stats.TotalGenomes)
	}
	log.Printf("Successfully verified %d genomes in the database.", stats.TotalGenomes)
}
