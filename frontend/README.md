# DetectAI Dashboard

React + Vite + TypeScript SOC dashboard for DetectAI.

## Pages

- **Alerts** (`/`) — list of ingested alerts with severity/priority badges.
- **Alert Investigation** (`/alerts/:alertId`) — the main working view: risk score breakdown, evidence fields, raw source event, validated MITRE ATT&CK mapping, on-demand AI analysis trigger, and analyst feedback (submit + history).

## Running locally

```bash
npm install
cp .env.example .env.local   # point VITE_API_BASE_URL at your backend
npm run dev
```

Requires the backend running (see the root README) at the URL configured
in `.env.local` (default `http://localhost:8000/api/v1`).

## Build

```bash
npm run build   # type-checks with tsc, then builds with vite
npm run lint    # oxlint
```

## Known simplifications (MVP scope)

- AI analysis results are only shown for the current session — there's no
  "analysis history" fetch, since the backend doesn't yet expose a list
  endpoint for past `AIAnalysis` rows on an alert (only the most recent
  one, via the MITRE mapping endpoint's internal lookup). Triggering
  "Run AI Analysis" again after a page reload will re-run analysis rather
  than show the prior result.
- No auth — the analyst ID for feedback is a free-text field, not tied to
  a real login. Fine for a local MVP demo, not for a real deployment.
