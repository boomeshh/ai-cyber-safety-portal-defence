import { render, screen, waitFor } from '@testing-library/react';

// Mock react-router-dom to avoid broken package installation issues
jest.mock('react-router-dom', () => ({
  BrowserRouter: ({ children }) => <div>{children}</div>,
  Routes: ({ children }) => <div>{children}</div>,
  Route: ({ element }) => element,
}));

import App from './App';

// Mock auth utilities
jest.mock('./utils/auth', () => ({
  getStoredUser: () => ({ full_name: 'Admin User', role: 'admin', email: 'admin@test.com' }),
  getAuthHeaders: () => ({ Authorization: 'Bearer test-token' }),
  logoutUser: jest.fn(),
}));

beforeEach(() => {
  global.fetch = jest.fn(() =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({
          complaints: [],
          analytics: {
            total: 0,
            critical: 0,
            open_cases: 0,
            escalated: 0,
            linked_indicator_cases: 0,
            auto_escalated_cases: 0,
          },
          audit_logs: [],
          users: [],
          campaign_graph: { nodes: [], edges: [] },
        }),
    })
  );
});

afterEach(() => {
  jest.clearAllMocks();
});

test('renders admin dashboard', async () => {
  render(<App />);
  await waitFor(() => {
    expect(screen.getByText('Admin Triage Dashboard')).toBeInTheDocument();
  });
});
