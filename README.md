# Contact Computers — JobCard Ops

Internal job management system for service operations: job cards, tasks/calendar, customers, deliveries/collections, fuel logging, signatures and photos.

## Quick start

```bash
cd server
node index.js
```

Open **http://localhost:3847** in a browser (mobile-friendly).

### Default logins (change these immediately)

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | admin123   | Admin |
| office   | office123  | Office |
| field    | field123   | Field |

**Security:** After first login, go to **More → Users & Roles** (admin) and change all passwords. Do not leave defaults in production.

## Features

- **Job Cards** — create, assign, track status/priority, link customers
- **Tasks + Calendar** — tasks under a job; drag-and-drop on calendar updates due dates
- **Close rules** — cannot close until all tasks completed, customer signature captured, and at least one completion photo
- **Customer database** — search, add, bulk CSV import
- **Signature pad** — on-device capture, stored with the job
- **Before/after photos** — camera or file upload, timestamped
- **Deliveries & Collections** log
- **Fuel log** for company van + receipt photo
- **Dashboard** summaries
- **Users & Roles** — admin / office / field; persistent login until Logout
- **Audit trail** (admin)

## Theme

White + blue matching the Contact Computers logo (`logo.png` on the sign-in page).

## Data

- SQLite-style JSON store: `server/data.json`
- Uploads: `uploads/photos`, `uploads/signatures`, `uploads/fuel`

## Stack

- Pure Node.js HTTP server (no external runtime deps required beyond Node)
- Single-page mobile-first UI (HTML + Tailwind CDN + vanilla JS)
