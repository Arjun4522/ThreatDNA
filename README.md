# ThreatDNA

ThreatDNA is a comprehensive threat intelligence platform designed to process, index, and enable searching of Cyber Threat Intelligence (CTI) data. It leverages a microservices architecture with Go for backend services and React for the frontend, orchestrated using Docker Compose.

## Architecture

ThreatDNA is built as a modular system, with distinct services handling specific responsibilities.

### Components

*   **`producer`**: (Go Service) Responsible for ingesting initial CTI data and publishing it to a Kafka topic.
*   **`builder`**: (Go Service) Consumes CTI records from Kafka, extracts Tactics, Techniques, and Procedures (TTPs) and Indicators of Compromise (IOCs), builds a threat "genome," and saves it to a Bleve database.
*   **`search`**: (Go Service) Provides a RESTful API for querying the indexed threat data. It performs searches against the Bleve index and returns relevant results to the frontend.
*   **`frontend`**: (React Application) A web-based user interface that allows users to interact with the ThreatDNA platform.
*   **Kafka**: A distributed streaming platform used for asynchronous communication between the backend services.
*   **Zookeeper**: Manages Kafka brokers and handles distributed coordination.

### Data Flow

1.  **Ingestion**: The `producer` service reads CTI data and publishes it to a Kafka topic.
2.  **Processing & Indexing**: The `builder` service consumes these raw CTI records from Kafka. It processes the data, extracts relevant entities (TTPs, IOCs), constructs a structured threat "genome," and indexes it into a Bleve search index (`threats.bleve`). This index is persistent and shared via a Docker volume.
3.  **Querying**: The `frontend` application makes HTTP requests to the `search` service's API (e.g., `/api/search`).
4.  **Searching**: The `search` service queries the `threats.bleve` index based on the user's input and returns structured search results to the `frontend`.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Docker Desktop
*   Go (Golang)
*   Node.js and npm

### Running the Application

1.  **Build and start all services**:
    ```bash
    docker-compose up --build -d
    ```
2.  **Verify services are running**:
    ```bash
    docker-compose ps
    ```
3.  **Access the application**:
    *   **Frontend**: `http://localhost:3000`
    *   **Search API**: `curl "http://localhost:8080/api/search?query=ransomware"`

## Known Issues

### Search Service Not Starting

*   **Symptom**: The `search` service fails to start and may not produce any logs.
*   **Cause**: The `builder` service and the `search` service are both trying to access the same Bleve index file on disk. Bleve is designed for concurrent access within a single process, not from multiple processes. This causes a file locking issue that prevents the `search` service from starting.
*   **Solution**: The recommended solution is to merge the `builder` and `search` services into a single service. This aligns with Bleve's design and will resolve the file locking issue. This work is currently in progress.