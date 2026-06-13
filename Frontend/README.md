# CredHunter-X Dashboard

A React + TypeScript (Vite) dashboard for reviewing and triaging CredHunter-X findings.

## Features

- Configure the backend API base URL and optional `X-API-Key` (stored in `localStorage`).
- Load findings for a project and view a feedback summary (true/false positives, suppressed, unreviewed).
- Triage each finding: mark true positive, mark false positive, or suppress.

## Prerequisites

- Node.js 18+ and npm.
- A running CredHunter-X backend (see the project `SETUP.md`). By default the dashboard
  targets `http://localhost:8000`.

## Setup

```bash
cd Frontend
npm install
npm run dev
```

Then open the printed URL (default `http://localhost:5173`).

## Build

```bash
npm run build      # type-checks and produces a production build in dist/
npm run preview    # serves the production build locally
```

## Configuration

Set the API base URL and API key from the **Settings** panel in the UI. If the backend has
`CREDHUNTER_API_KEYS` configured, enter a matching key; otherwise leave it blank.
