package threatdnacore

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

// DataIngester with performance optimizations
type DataIngester struct {
	parser     *CTIParser
	extractor  *TechniqueExtractor
	htmlParser *HTMLParser
}

func NewDataIngester() *DataIngester {
	parser := NewCTIParser()
	htmlParser := NewHTMLParser()
	return &DataIngester{
		parser:     parser,
		htmlParser: htmlParser,
	}
}

func (d *DataIngester) Initialize() error {
	log.Println("🚀 Initializing CTI Parser...")

	// Load full MITRE data from file
	if err := d.parser.LoadMITREDataFromFile("enterprise-attack.json"); err != nil {
		log.Printf("⚠️  Warning: could not load from 'enterprise-attack.json'. Falling back to sample data. Error: %v", err)
		// Fallback to sample data if file loading fails
		return nil // Or handle fallback appropriately
	}

	// Initialize technique extractor
	d.extractor = NewTechniqueExtractor(d.parser.attackData)

	log.Printf("✅ Initialized with %d MITRE techniques", len(d.parser.attackData))
	return nil
}

func (d *DataIngester) IngestDirectory(dirPath string) ([]CTIRecord, error) {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dirPath, err)
	}

	var allRecords []CTIRecord
	
	log.Printf("📁 Found %d files to process", len(files))
	
	for i, file := range files {
		if file.IsDir() {
			continue
		}
		
		log.Printf("📄 Processing file %d/%d: %s", i+1, len(files), file.Name())
		
		filepath := fmt.Sprintf("%s/%s", dirPath, file.Name())
		records, err := d.IngestFileFast(filepath)
		if err != nil {
			log.Printf("⚠️  Warning: failed to ingest %s: %v", filepath, err)
			continue
		}
		
		allRecords = append(allRecords, records...)
		log.Printf("✅ Ingested %d records from %s", len(records), file.Name())
	}
	
	log.Printf("🎉 Completed processing %d files", len(files))
	return allRecords, nil
}

func (d *DataIngester) IngestFileFast(filepath string) ([]CTIRecord, error) {
	ext := strings.ToLower(filepath[strings.LastIndex(filepath, "."):])
	
	var records []CTIRecord
	var err error
	
	switch ext {
	case ".html", ".htm":
		records, err = d.parser.ParseHTMLReportFast(filepath, d.htmlParser)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Process records with progress indication
	for i := range records {
		log.Printf("🔍 Extracting TTPs and IOCs...")
		d.parser.ProcessCTIRecord(&records[i], d.extractor)
		records[i].Source = fmt.Sprintf("file:%s", filepath)
		log.Printf("✅ Found %d TTPs, %d IOCs", len(records[i].TTPs), len(records[i].IOCs))
	}
	
	return records, nil
}

func (p *CTIParser) ProcessCTIRecord(record *CTIRecord, extractor *TechniqueExtractor) {
	record.TTPs = extractor.ExtractTTPs(record.RawText)
	record.IOCs = extractor.ExtractIOCs(record.RawText)
}
