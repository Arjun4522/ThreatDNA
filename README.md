# ThreatDNA

## Project Overview
ThreatDNA is a comprehensive platform for processing, analyzing, and querying Cyber Threat Intelligence (CTI). It ingests CTI data from various sources, builds a structured knowledge base of threat genomes, and provides powerful search capabilities to identify and understand threat actors, campaigns, and techniques.

## Backend

### Technologies Used
- **Go:** Primary language for backend services.
- **Kafka:** Distributed streaming platform for real-time CTI data ingestion.
- **Zookeeper:** Manages Kafka brokers.
- **BoltDB:** A key/value store used for persistent storage of threat genomes.
- **Bleve:** A full-text search and indexing library for Go, used for efficient querying of threat data.
- **Docker & Docker Compose:** For containerization and orchestration of all backend services.

### Services
- **Zookeeper & Kafka:** Provide the core messaging infrastructure for the CTI pipeline.
- **Producer:** Ingests static CTI data (e.g., from `enterprise-attack.json`) and publishes it as messages to a Kafka topic.
- **Builder:** Consumes CTI data from the Kafka topic and directly from the `data/` directory (for additional reports). It processes this raw CTI, extracts relevant threat intelligence, and builds structured threat "genomes" which are then stored in a BoltDB database.
- **Indexer:** Reads the processed threat genomes from the BoltDB database and creates optimized full-text search indexes using Bleve.
- **Search:** Provides an API (or command-line interface) to query the threat intelligence database, leveraging the Bleve indexes for fast and efficient searches.

### Backend Workflow
1.  The `producer` service ingests initial CTI data from `enterprise-attack.json` and sends it to Kafka.
2.  The `builder` service simultaneously consumes this data from Kafka and processes additional CTI reports found in the `data/` directory.
3.  All CTI records are processed by the `builder` to create and store threat genomes in the BoltDB database.
4.  The `indexer` service then reads these genomes and builds efficient search indexes.
5.  Finally, the `search` service uses these indexes to respond to queries, providing access to the comprehensive threat intelligence.

### Setup and Running with Docker Compose
1.  **Prerequisites:**
    *   [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed.
    *   [Go](https://golang.org/doc/install) (for local development/testing, though Docker handles most backend Go needs).

2.  **Build Docker Images:**
    Navigate to the project root directory (`/home/arjun/Desktop/ThreatDNA`) and run:
    ```bash
    docker-compose build
    ```
    If you encounter issues or want to ensure a fresh build, use:
    ```bash
    docker-compose build --no-cache
    ```

3.  **Start the Backend Services:**
    To run all backend services (Kafka, Producer, Builder, Indexer, Search) in detached mode:
    ```bash
    docker-compose up -d
    ```
    To view logs in real-time (useful for debugging):
    ```bash
    docker-compose logs -f
    ```

4.  **Stop the Backend Services:**
    To stop and remove all containers, networks, and volumes created by `docker-compose up`:
    ```bash
    docker-compose down
    ```

## Frontend

### Technologies Used
- **React:** A JavaScript library for building user interfaces.
- **TypeScript:** A typed superset of JavaScript that compiles to plain JavaScript.
- (Add any other relevant frontend technologies like Bootstrap, Material UI, etc. if known from `package.json`)

### Setup and Running
1.  **Prerequisites:**
    *   [Node.js](https://nodejs.org/en/download/) and [npm](https://docs.npmjs.com/cli/v7/commands/npm-install) (or [yarn](https://classic.yarnpkg.com/en/docs/install/)) installed.

2.  **Install Dependencies:**
    Navigate to the `frontend/` directory:
    ```bash
    cd frontend/
    npm install # or yarn install
    ```

3.  **Start the Frontend Development Server:**
    From the `frontend/` directory:
    ```bash
    npm start # or yarn start
    ```
    This will typically open the application in your browser at `http://localhost:3000`.

## Testing

### Go Backend Tests
1.  **Prerequisites:**
    *   [Go](https://golang.org/doc/install) installed.
    *   Docker and Docker Compose (for integration tests that rely on Kafka/DB).

2.  **Run Tests:**
    Navigate to the project root directory and run:
    ```bash
    go test ./...
    ```
    This command will execute all Go tests, including integration tests that spin up Docker Compose services.

### Frontend Tests
1.  **Run Tests:**
    Navigate to the `frontend/` directory:
    ```bash
    cd frontend/
    npm test # or yarn test
    ```