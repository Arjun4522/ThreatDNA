package threatdnacore

import (
	"time"
)

// CTIRecord represents a normalized Cyber Threat Intelligence record
type CTIRecord struct {
	ID       string    `json:"id"`
	Source   string    `json:"source"`	
	Date     time.Time `json:"date"`
	Actor    string    `json:"actor,omitempty"`
	Campaign string    `json:"campaign,omitempty"`
	RawText  string    `json:"raw_text"`
	TTPs     []TTP     `json:"ttps,omitempty"`
	IOCs     []IOC     `json:"iocs,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
}

// TTP represents a Tactic, Technique, or Procedure with confidence
type TTP struct {
	TechniqueID string  `json:"technique_id"` // e.g., "T1059"
	Confidence  float64 `json:"confidence"`   // 0.0 - 1.0
	Context     string  `json:"context"`      // surrounding text
	Tactic      string  `json:"tactic,omitempty"`
}

// IOC represents Indicators of Compromise
type IOC struct {
	Type    string `json:"type"`  // ip, domain, hash, etc.
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}

// AttackTechnique contains MITRE ATT&CK technique information
type AttackTechnique struct {
	ID                  string
	Name                string
	Description         string
	Keywords            []string
	Platforms           []string
	Tactics             []string
	ExternalReferences  []ExternalReference
}

// MITREAttackBundle represents the top-level structure of the enterprise-attack.json file.
type MITREAttackBundle struct {
	Objects []MITREObject `json:"objects"`
}

// MITREObject represents a single object within the bundle, which could be an attack-pattern, tactic, etc.
type MITREObject struct {
	Type                string               `json:"type"`
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	Description         string               `json:"description"`
	KillChainPhases     []KillChainPhase     `json:"kill_chain_phases"`
	ExternalReferences  []ExternalReference  `json:"external_references"`
	Platforms           []string             `json:"x_mitre_platforms"`
	IsSubtechnique      bool                 `json:"x_mitre_is_subtechnique"`
}

// KillChainPhase represents the tactic (e.g., initial-access) an attack pattern belongs to.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// ExternalReference contains the mapping to the external ID, like "T1566".
type ExternalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

// Genome represents a complete threat sequence
type Genome struct {
	ID           string    `json:"id"`
	SourceIDs    []string  `json:"source_ids"`
	Actor        string    `json:"actor,omitempty"`
	Campaign     string    `json:"campaign,omitempty"`
	TTPs         []string  `json:"ttps"`
	Tactics      []string  `json:"tactics"`
	Platforms    []string  `json:"platforms"`
	CVEs         []string  `json:"cves,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Confidence   float64   `json:"confidence"`
	SourceCount  int       `json:"source_count"`
	IOCCount    int                    `json:"ioc_count"`
	AllSourceText string                 `json:"all_source_text"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// GenomeStats provides analytics on genome collection
type GenomeStats struct {
	TotalGenomes      int                `json:"total_genomes"`
	UniqueActors      int                `json:"unique_actors"`
	UniqueCampaigns   int                `json:"unique_campaigns"`
	AvgGenomeLength   float64            `json:"avg_genome_length"`
	TTPFrequency      map[string]int     `json:"ttp_frequency"`
	TacticFrequency   map[string]int     `json:"tactic_frequency"`
	IOCTypeFrequency  map[string]int     `json:"ioc_type_frequency"`
}

// APISearchResult represents a single search result returned by the API
type APISearchResult struct {
	ID       string  `json:"id"`
	Actor    string  `json:"actor,omitempty"`
	Campaign string  `json:"campaign,omitempty"`
	Score    float64 `json:"score"`
	// Add other fields as needed, e.g., TTPs, IOCs, Description snippet
}