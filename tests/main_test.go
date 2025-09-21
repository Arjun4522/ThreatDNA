
package tests

import (
	"testing"

	// Import the main package using the module path from go.mod
	"threatdna"
)

func TestExternalTTPAndIOCExtraction(t *testing.T) {
	// --- Setup ---
	// We now have to call the functions from the imported 'threatdna' package.
	// Note: This only works because the functions and types we need (like NewCTIParser, TTP, etc.)
	// were defined with a capital letter, making them exported and accessible to other packages.
	parser := threatdna.NewCTIParser()

	// The test needs to know the relative path to the data file.
	// Since the test runs from the project root, the path is correct.
	err := parser.LoadMITREDataFromFile("enterprise-attack.json")
	if err != nil {
		t.Fatalf("Failed to load MITRE data for test: %v", err)
	}
	extractor := threatdna.NewTechniqueExtractor(parser.GetAttackData()) // We need a getter for the attack data

	// --- Test Case ---
	sampleText := `
		A recent campaign by a known actor involved an initial compromise via Phishing (T1566).
		The adversary then used PowerShell (T1059) to download a payload from evil.com.
		The malware communicated with the C2 server at 192.168.1.100.
		A known hash for the payload is 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.
	`

	// --- Execution ---
	tps := extractor.ExtractTTPs(sampleText)
	iocs := extractor.ExtractIOCs(sampleText)

	// --- Assertions ---

	// Check for TTPs
	expectedTTPs := map[string]bool{
		"T1566": false, // Phishing
		"T1059": false, // PowerShell
	}

	for _, ttp := range ttps {
		if _, ok := expectedTTPs[ttp.TechniqueID]; ok {
			expectedTTPs[ttp.TechniqueID] = true
		}
	}

	for id, found := range expectedTTPs {
		if !found {
			t.Errorf("Expected to find TTP '%s', but it was not found.", id)
		}
	}

	// Check for IOCs
	expectedIOCs := map[string]string{
		"evil.com": "domain",
		"192.168.1.100": "ip",
		"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef": "hash",
	}

	iocFound := make(map[string]bool)
	for _, ioc := range iocs {
		if expectedType, ok := expectedIOCs[ioc.Value]; ok {
			if ioc.Type == expectedType {
				iocFound[ioc.Value] = true
			}
		}
	}

	for value := range expectedIOCs {
		if !iocFound[value] {
			t.Errorf("Expected to find IOC '%s', but it was not found.", value)
		}
	}
}
