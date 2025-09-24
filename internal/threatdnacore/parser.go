package threatdnacore

import (
	// "log"
)

// CTIParser handles parsing of different CTI formats
type CTIParser struct {
	techniqueExtractor *TechniqueExtractor
}

// NewCTIParser creates a new CTIParser instance.
func NewCTIParser(mitreData map[string]AttackTechnique) *CTIParser {
	return &CTIParser{
		techniqueExtractor: NewTechniqueExtractor(mitreData),
	}
}

// ProcessCTIRecord extracts TTPs and IOCs from a CTI record's raw text.
func (cp *CTIParser) ProcessCTIRecord(record *CTIRecord) {
	record.TTPs = cp.techniqueExtractor.ExtractTTPs(record.RawText)
	record.IOCs = cp.techniqueExtractor.ExtractIOCs(record.RawText)
}