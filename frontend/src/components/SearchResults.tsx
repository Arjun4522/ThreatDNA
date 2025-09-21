import React from 'react';
import { Container, Card } from 'react-bootstrap';

// Define the structure of a search result from the Go backend
interface SearchResult {
  id: string;
  actor?: string;
  campaign?: string;
  score: number;
}

interface SearchResultsProps {
  results: SearchResult[];
}

const SearchResults: React.FC<SearchResultsProps> = ({ results }) => {
  if (results.length === 0) {
    return (
      <Container className="my-4">
        <p className="text-center">No results to display. Try a search!</p>
      </Container>
    );
  }

  return (
    <Container className="my-4">
      <h3>Search Results</h3>
      {results.map((result) => (
        <Card key={result.id} className="mb-3">
          <Card.Body>
            <Card.Title>{result.id}</Card.Title>
            <Card.Text>
              {result.actor && <p><strong>Actor:</strong> {result.actor}</p>}
              {result.campaign && <p><strong>Campaign:</strong> {result.campaign}</p>}
              <p><strong>Score:</strong> {result.score.toFixed(2)}</p>
            </Card.Text>
          </Card.Body>
        </Card>
      ))}
    </Container>
  );
};

export default SearchResults;