import React from 'react';
import TopNavigation from './TopNavigation';
import Footer from './Footer';

export default function Layout({ children }) {
  return (
    <div className="app-layout">
      <TopNavigation />
      <div className="page-wrapper">
        <div className="page-container">
          {children}
        </div>
      </div>
      <Footer />
    </div>
  );
}
