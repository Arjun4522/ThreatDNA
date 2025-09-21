import React, { useState } from 'react';
import AppNavbar from './components/Navbar';
import Search from './components/Search';
import SearchResults from './components/SearchResults';
import AppFooter from './components/Footer';
import './App.css';

// Define the structure of a search result from the Go backend
interface SearchResult {
  id: string;
  actor?: string; // Optional, as it might be empty
  campaign?: string; // Optional, as it might be empty
  score: number;
}

const App: React.FC = () => {
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async (query: string) => {
    setLoading(true);
    setError(null);
    setSearchResults([]); // Clear previous results

    try {
      // Construct the API URL for the Go backend
      const response = await fetch(`http://localhost:8080/api/search?query=${encodeURIComponent(query)}`);
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
      }

      const data: SearchResult[] = await response.json();
      setSearchResults(data);
    } catch (err: any) {
      console.error("Failed to fetch search results:", err);
      setError(err.message || "An unknown error occurred during search.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="d-flex flex-column min-vh-100">
      <AppNavbar />
      <main className="flex-grow-1">
        <Search onSearch={handleSearch} />
        {loading && <p className="text-center">Loading search results...</p>}
        {error && <p className="text-center text-danger">Error: {error}</p>}
        {!loading && !error && <SearchResults results={searchResults} />}
      </main>
      <AppFooter />
    </div>
  );
};

export default App;
