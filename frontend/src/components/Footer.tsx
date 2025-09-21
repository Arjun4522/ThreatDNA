import React from 'react';
import { Container } from 'react-bootstrap';

const AppFooter: React.FC = () => {
  return (
    <footer className="bg-dark text-white text-center py-3 mt-5">
      <Container>
        <p>&copy; {new Date().getFullYear()} ThreatDNA Platform. All rights reserved.</p>
      </Container>
    </footer>
  );
};

export default AppFooter;
