# ThreatDNA

ThreatDNA is a comprehensive threat intelligence platform designed to process, index, and enable searching of Cyber Threat Intelligence (CTI) data. It leverages a microservices architecture with Go for backend services and React for the frontend, orchestrated using Docker Compose.

## Architecture

ThreatDNA is built as a modular system, with distinct services handling specific responsibilities.

### Components

*   **`producer`**: (Go Service) Responsible for ingesting initial CTI data (e.g., `enterprise-attack.json`) and publishing it to a Kafka topic.
*   **`builder`**: (Go Service) Consumes CTI records from Kafka, extracts Tactics, Techniques, and Procedures (TTPs) and Indicators of Compromise (IOCs), builds a threat "genome," and saves it to a Bleve database. It also publishes processed genomes back to Kafka.
*   **`indexer`**: (Go Service) Subscribes to the Kafka topic where processed threat genomes are published. It indexes these genomes into a Bleve search index, making them searchable by the `search` service.
*   **`search`**: (Go Service) Provides a RESTful API for querying the indexed threat data. It performs searches against the Bleve index and returns relevant results to the frontend.
*   **`frontend`**: (React Application) A web-based user interface that allows users to interact with the ThreatDNA platform, primarily for searching and displaying threat intelligence.
*   **Kafka**: A distributed streaming platform used for asynchronous communication and data pipelines between the backend services.
*   **Zookeeper**: Manages Kafka brokers and handles distributed coordination.
*   **Bleve**: A modern text indexing and search library for Go, used for storing and querying threat intelligence data.

### Data Flow

1.  **Ingestion**: The `producer` service reads CTI data (e.g., `enterprise-attack.json`) and publishes raw CTI records to a Kafka topic (`test-cti-records`).
2.  **Processing**: The `builder` service consumes these raw CTI records from Kafka. It processes the data, extracts relevant entities (TTPs, IOCs), and constructs a structured threat "genome." This genome is then stored in a Bleve database and published to another Kafka topic (`threatdna-genomes`).
3.  **Indexing**: The `indexer` service subscribes to the `threatdna-genomes` Kafka topic. It consumes the processed threat genomes and indexes them into a Bleve search index (`threats.bleve`). This index is persistent and shared via a Docker volume.
4.  **Querying**: The `frontend` application makes HTTP requests to the `search` service's API (e.g., `/api/search`).
5.  **Searching**: The `search` service queries the `threats.bleve` index based on the user's input and returns structured search results to the `frontend`.

## Workflow

The ThreatDNA platform operates as a continuous pipeline:

1.  Initial CTI data is fed into the system via the `producer`.
2.  The `builder` enriches and transforms this data into a standardized threat "genome."
3.  The `indexer` continuously updates the search index with the latest threat genomes.
4.  The `search` API provides real-time access to this indexed data for the `frontend` or any other consumer.

This design ensures that the platform is scalable, resilient, and capable of handling a continuous stream of threat intelligence updates.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have the following installed on your system:

*   **Docker Desktop**: Includes Docker Engine and Docker Compose.
    *   [Download Docker Desktop](https://www.docker.com/products/docker-desktop)
*   **Go (Golang)**: Version 1.23 or higher (for local development/manual testing of Go services).
    *   [Download Go](https://golang.org/dl/)
*   **Node.js and npm**: (for frontend development).
    *   [Download Node.js](https://nodejs.org/en/download/)

### Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your-repo/ThreatDNA.git
    cd ThreatDNA
    ```
    *(Note: Replace `https://github.com/your-repo/ThreatDNA.git` with the actual repository URL if different.)*

2.  **Install frontend dependencies**:
    ```bash
    cd frontend
    npm install
    cd ..
    ```

### Running the Application

To run the entire ThreatDNA application using Docker Compose:

1.  **Build and start all services**:
    ```bash
    docker-compose up --build -d
    ```
    This command will:
    *   Build the Docker images for `producer`, `builder`, `indexer`, and `search` services.
    *   Start all defined services (Zookeeper, Kafka, kafka-setup, producer, builder, indexer, search, frontend) in detached mode.
    *   The `kafka-setup` service will create the necessary Kafka topics.
    *   The `builder` and `indexer` services will start processing and indexing data.

2.  **Verify services are running**:
    ```bash
    docker-compose ps
    ```
    You should see all services listed with `Up` status.

3.  **Check service logs (optional but recommended)**:
    To view logs for a specific service (e.g., `search`):
    ```bash
    docker-compose logs search
    ```
    You can also follow logs in real-time:
    ```bash
    docker-compose logs -f search
    ```

### Accessing the Application

*   **Frontend**: Once all services are up and running, you can access the frontend application in your web browser:
    ```
    http://localhost:3000
    ```
*   **Search API**: You can directly query the search API (e.g., using `curl` or your browser):
    ```bash
    curl "http://localhost:8080/api/search?query=ransomware"
    ```
*   **Count API**:
    ```bash
    curl "http://localhost:8080/api/count"
    ```

## Development

### Building Go Services Manually (for local testing/development)

If you want to build and run individual Go services outside of Docker (e.g., for debugging):

1.  **Ensure Go is installed** (see Prerequisites).
2.  **Navigate to the service directory** (e.g., `cmd/search`).
3.  **Build the executable**:
    ```bash
    go build -o my_service_name .
    ```
    (Replace `my_service_name` with the desired executable name, e.g., `search_local`).
4.  **Run the executable**:
    ```bash
    ./my_service_name
    ```
    *Note: When running locally, ensure that any required data directories (like `threats.bleve`) or environment variables (like `KAFKA_BROKER`) are correctly set or available in your local environment.*

### Frontend Development

To run the React frontend in development mode (with hot-reloading):

1.  **Navigate to the frontend directory**:
    ```bash
    cd frontend
    ```
2.  **Start the development server**:
    ```bash
    npm start
    ```
    This will typically open the application in your browser at `http://localhost:3000`.

## Troubleshooting

*   **"Search query getting stuck" or "CORS request did not succeed"**:
    *   **Cause**: This was a known issue related to the `search` service's interaction with the Bleve index and CORS configuration.
    *   **Solution**: Ensure you have the latest code from the `dev` branch. The `search` service now opens the Bleve index globally on startup to prevent contention and handles CORS requests correctly via middleware. Rebuild and restart the `search` service if you encounter this.
        ```bash
        docker-compose build search
        docker-compose up -d search
        ```
*   **`indexer` or `builder` failing to start/process**:
    *   **Cause**: Often related to Kafka/Zookeeper not being fully ready, or issues with data paths.
    *   **Solution**: Check `docker-compose logs <service_name>` for specific error messages. Ensure Kafka and Zookeeper are healthy (`docker-compose ps`). You might need to clear Docker volumes if the Bleve index is corrupted:
        ```bash
        docker-compose down -v
        docker-compose up --build -d
        ```
        *(Caution: This will delete all persistent data, including your Bleve index.)*
*   **"Error: (none) Exit Code: 128" during `git checkout -b dev`**:
    *   **Cause**: A branch named `dev` already exists.
    *   **Solution**: Simply switch to the existing `dev` branch: `git checkout dev`.
