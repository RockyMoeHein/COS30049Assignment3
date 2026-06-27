import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import App from './App';

// Keep the routing smoke test lightweight by replacing the heavy D3 page.
jest.mock('./Statistics', () => function Statistics() {
  return <main>Statistics</main>;
});

beforeAll(() => {
  window.scrollTo = jest.fn();
});

test('renders the application navigation', () => {
  // Confirms that the shared layout and navbar render without route errors.
  render(
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <App />
    </BrowserRouter>
  );
  expect(screen.getByRole('navigation')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: /code vulnerability detector/i }))
    .toBeInTheDocument();
});
