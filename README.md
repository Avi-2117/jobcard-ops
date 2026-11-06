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

## Data and persistence

- **MongoDB is required**: set `MONGODB_URI` in the deployment environment. The app uses the existing `MONGODB_DB` value (default `jobcardops`) and `appdata` collection.
- The application refuses to start if MongoDB is not configured or cannot be reached. It will not silently fall back to `server/data.json`.
- Uploaded files remain in `uploads/` on the server. For Render, use persistent storage for uploads if they must survive deploys/restarts.
- Owner → More → **Backup & Export Data** downloads a `.tar.gz` archive containing the MongoDB application document and the current `uploads/` directory.
- The archive contains a MongoDB document export, not a `mongodump` binary backup. To restore, inspect the archive and import the `document` into the same `appdata` collection after taking a separate current backup.

## Offline behaviour

- Previously loaded job lists and job details are cached on the device for offline viewing.
- Job-card edits made while offline are queued in IndexedDB and replayed against the existing MongoDB-backed API when the device reconnects.
- The local queue is temporary device storage, not a second database. Offline creation of new jobs and comments is not queued, to avoid duplicate records when connectivity is uncertain.

## Stack

- Pure Node.js HTTP server (no external runtime deps required beyond Node)
- Single-page mobile-first UI (HTML + Tailwind CDN + vanilla JS)

## Field and office workflow features

The current production UI includes signed job-card sharing, customer call/history, structured parts and equipment, common job templates, labelled photo previews, a closed-needs-invoicing queue, technician assignment badges, job activity/comments, CSV operational reports, My Jobs, and Start/Finish time stamping. Offline job-card drafts and supported job edits queue locally and sync to the existing MongoDB store when connectivity returns.

See `CHANGELOG-MONGODB-OFFLINE.md` for the exact scope and limitations, including browser-dependent PDF sharing, the absence of push notifications, and which actions still require an internet connection.
