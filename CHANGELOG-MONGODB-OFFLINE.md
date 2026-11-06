# MongoDB backup and offline update changes

## Included

- MongoDB is now mandatory when the server starts. A missing or unreachable `MONGODB_URI` stops startup instead of silently switching to `server/data.json`.
- MongoDB writes are serialised through a persistence queue to reduce stale snapshot overwrites.
- Owner-only **More → Backup & Export Data** downloads a `.tar.gz` archive with the MongoDB `appdata` document and the server's `uploads/` folder.
- Previously fetched job lists and job detail records are cached locally for offline viewing.
- Offline edits to existing job cards (`PUT /api/jobs/:id`) are queued in IndexedDB and replayed against the existing API when connectivity returns.
- The service worker caches the application shell so it can reopen offline after a successful online visit.

## Important limitations

- The offline queue currently covers updates to existing job cards only. Creating jobs, posting comments, uploading photos/signatures, fuel records and other create operations are not queued offline.
- The export is an application-level MongoDB document export plus uploaded files, not a full `mongodump` of unrelated collections in the MongoDB database.
- The archive is `.tar.gz` (not `.zip`). It can be opened by common archive utilities such as 7-Zip.
- No automated restore button is included. Keep a separate copy of the archive and test any restore procedure against a non-production database first.
- Render needs a persistent disk or external object storage for uploaded files to survive deployments. MongoDB persistence does not automatically make the `uploads/` directory persistent.

## Deployment

1. Keep the existing `MONGODB_URI`, `MONGODB_DB`, `JWT_SECRET` and other environment variables unchanged.
2. Deploy the updated project.
3. Confirm the server log says `Connected to MongoDB` and `Using MongoDB for persistence`.
4. Sign in as an admin and use **More → Backup & Export Data** to download a backup.
5. Test offline job editing on a test job before relying on it in the field.

## JobCard Ops field, office and owner workflow additions

- Added signed-job-card sharing: mobile browsers that support file sharing can hand the PDF to WhatsApp or email with the PDF attached. On browsers without file sharing, the PDF downloads and an email draft opens with the customer's saved email address; the user must attach the downloaded file manually.
- Added call and job-address WhatsApp shortcuts on the job detail page, previous customer job history, and a visible job activity/comments panel with the actor and changed fields where recorded.
- Added structured parts/equipment rows (item, quantity, serial number) and quick re-add from previously recorded structured items. Existing free-text equipment data remains visible for older jobs.
- Added Network Install, Laptop Repair and Printer Setup/Repair job templates with prefilled scope checklists.
- Added Before / After / Fault photo labels, retagging, and full-size photo preview.
- Added a closed-jobs-needing-invoice quick queue for office users.
- Added a New Job badge for recently assigned open jobs and a WhatsApp job-details message shortcut. This is an in-app badge and share shortcut, not browser push notification delivery.
- Added Jobs per Technician, Hours Worked, Travel Kilometres and Jobs per Customer CSV exports for office/admin users.
- Added My Jobs filtering, Start/Finish time stamping, local form draft recovery, and offline creation of job-card drafts queued for MongoDB sync when connectivity returns. Existing offline job edits remain queued as before.

### Important sharing and offline notes

- The Web Share API determines which installed apps are available for sharing; the app cannot force WhatsApp or a specific email app to be present. Email recipients are prefilled in the fallback mail draft, but browser security does not permit silently attaching a local file to a `mailto:` draft.
- Push notifications are not included. The New Job badge appears in the app for recent jobs assigned to the signed-in technician.
- Offline job creation and existing job-card PUT edits are queued. Photo uploads, signatures, comments and other non-job-card creation workflows still require a connection. Offline-created job drafts are stored on the device until they sync.
- CSV files open in Excel, but they are CSV exports rather than formatted `.xlsx` workbooks.
