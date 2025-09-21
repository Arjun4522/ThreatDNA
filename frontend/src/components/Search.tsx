import React, { useState } from 'react';
import { Form, Button, Container, Row, Col } from 'react-bootstrap';

interface SearchProps {
  onSearch: (query: string) => void;
}

const Search: React.FC<SearchProps> = ({ onSearch }) => {
  const [query, setQuery] = useState<string>('');

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    onSearch(query);
  };

  return (
    <Container className="my-4">
      <Row className="justify-content-md-center">
        <Col md={8}>
          <Form onSubmit={handleSubmit}>
            <Form.Group className="mb-3" controlId="searchQuery">
              <Form.Label>Search Threat Intelligence</Form.Label>
              <Form.Control
                type="text"
                placeholder="Enter search query (e.g., 'ransomware', 'APT28')"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </Form.Group>
            <Button variant="primary" type="submit">
              Search
            </Button>
          </Form>
        </Col>
      </Row>
    </Container>
  );
};

export default Search;
