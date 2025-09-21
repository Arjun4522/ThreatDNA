
# ThreatDNA

A Cyber Threat Intelligence (CTI) analysis pipeline that automatically ingests threat reports, extracts structured data, and builds aggregated "threat genomes" to profile and analyze adversary behavior. The project uses a Go-based backend and features a powerful embedded search engine to make the collected intelligence fully queryable.

## Features

*   **Automated CTI Processing:** Ingests raw PDF/HTML reports and converts them into structured JSON data.
*   **MITRE ATT&CK Extraction:** Automatically identifies Tactics, Techniques, and Procedures (TTPs) from report text using the full ATT&CK dataset.
*   **Indicator of Compromise (IOC) Extraction:** Pulls out IPs, domains, and hashes from reports.
*   **Threat Genome Builder:** Aggregates data from multiple reports to build high-level behavioral profiles of threat actors, representing their unique "DNA".
*   **Embedded Search Engine:** Uses the Bleve search library to create a powerful, self-contained search index for all processed intelligence, allowing for complex queries.
*   **Advanced Search Capabilities:** The search client is designed to be extended with:
    *   **Behavioral Sequence Search:** Find actors who use a specific chain of TTPs.
    *   **Threat Actor Similarity Search:** Find actors with similar behavioral profiles.
    *   **Relevancy Tuning:** Boosts search results based on field importance (e.g., a match in `actor` is ranked higher).

---

## Project Structure

```
/ThreatDNA
|-- data/                     # Processed HTML reports
|-- reports/                  # Raw downloaded PDF reports
|-- threats.bleve/            # The self-contained Bleve search index
|
|-- main.go                   # Stage 1: Parses reports, extracts TTPs/IOCs
|-- builder.go                # Stage 2: Aggregates data and builds genomes
|-- indexer.go                # Stage 3: Creates the search index from final data
|-- search.go                 # Stage 4: CLI to query the search index
|
|-- fetch.py                  # Helper script to download PDF reports
|-- format.py                 # Helper script to convert PDFs to HTML
|-- requirements.txt          # Python dependencies for helper scripts
|
|-- enterprise-attack.json    # Full MITRE ATT&CK dataset used for TTP mapping
|-- cti_results.json          # Intermediate structured data from main.go
|-- threat_genomes.json       # Final aggregated genome data from builder.go
|-- threat_genomes.db         # BoltDB database storing the genomes
|-- go.mod / go.sum           # Go module information
|-- README.md                 # This file
```

---

## How It Works: The Intelligence Pipeline

The project operates as a four-stage pipeline:

**1. Data Collection & Preparation (`fetch.py`, `format.py`)**
*   The `fetch.py` script downloads PDF-based threat reports from a source repository.
*   The `format.py` script converts these PDFs into a clean HTML format in the `data/` directory, making them easier to parse.

**2. Parsing and Extraction (`main.go`)**
*   This program reads the HTML files from the `data/` directory.
*   It parses the text and, using the `enterprise-attack.json` dataset, identifies all mentions of MITRE ATT&CK TTPs.
*   It also extracts IOCs (IPs, domains, hashes) and key metadata like the threat actor and campaign name.
*   The output is `cti_results.json`, a structured file where each entry represents a single processed report.

**3. Genome Aggregation (`builder.go`)**
*   This program reads `cti_results.json`.
*   It groups all reports by the identified threat actor.
*   For each actor, it aggregates the data to create a `Genome`, which includes a unique, confidence-ranked sequence of TTPs that represents the actor's typical attack chain.
*   The final genomes are saved to `threat_genomes.db` and exported to `threat_genomes.json`.

**4. Indexing & Search (`indexer.go`, `search.go`)**
*   The `indexer.go` program reads the final `threat_genomes.json` and the intermediate `cti_results.json` to build a rich, searchable index using the Bleve library. The index is stored in the `threats.bleve` directory.
*   The `search.go` program provides a command-line interface to query this index.

---

## Installation and Usage

### Prerequisites

*   Go (version 1.18+)
*   Python 3
*   `pip` for Python package management

### Setup

1.  **Clone the repository (example):**
    ```bash
    git clone https://example.com/your-repo/ThreatDNA.git
    cd ThreatDNA
    ```

2.  **Install Go and Python dependencies:**
    ```bash
    go mod tidy
    pip install -r requirements.txt
    ```

### Running the Full Pipeline

Execute these commands in order from the project root directory.

1.  **Fetch and Format Reports:**
    ```bash
    python3 fetch.py
    python3 format.py
    ```

2.  **Parse Reports and Extract Data:**
    ```bash
    go run main.go
    ```

3.  **Build Threat Genomes:**
    ```bash
    go run builder.go
    ```

4.  **Create the Search Index:**
    *(You only need to run this once after building the genomes, or when they are updated)*
    ```bash
    go run indexer.go --overwrite
    ```

### Searching the Data

Once the index is built, you can use `search.go` to ask questions.

*   **Basic Text Search:**
    ```bash
    # Find all genomes from reports mentioning "ransomware"
    go run search.go "ransomware"
    ```

*   **Actor Search (with Boosting):**
    ```bash
    # The engine ranks the actual actor "OutSteel" highest
    go run search.go "OutSteel"
    ```

*   **Behavioral Sequence Search:**
    *(Note: This requires reverting `search.go` to the version that supports phrase queries)*
    ```bash
    # Find actors that use Phishing then Command & Scripting
    go run search.go "T1566,T1059"
    ```

*   **Threat Actor Similarity Search:**
    *(Note: This requires reverting `search.go` to the version that supports similarity search)*
    ```bash
    # Find actors that behave like apt42
    go run search.go --similar-to "apt42"
    ```

---

## Future Enhancements

This project has a strong foundation that can be extended with more advanced features:

*   **Faceted Search:** Enhance the UI to allow for filtering and summarizing results by actor, tactic, or platform.
*   **Data Enrichment:** Automatically enrich the index with GeoIP data for IPs or CVSS scores for vulnerabilities.
*   **Web Interface:** Build a full web-based UI for a more interactive search and exploration experience.
*   **More Query Types:** Add support for wildcard, fuzzy, and compositional searches to the CLI.
