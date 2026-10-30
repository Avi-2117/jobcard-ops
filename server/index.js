import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { getDb, persist, hashPassword, addAudit, nextNumber, initDb } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3847;
const JWT_SECRET = process.env.JWT_SECRET || 'jobcard-ops-secret-key-change-in-prod-2026';

const UPLOADS = path.join(__dirname, '..', 'uploads');
const CLIENT = path.join(__dirname, '..', 'client', 'dist');


// Simple JWT (HS256-ish with HMAC)
function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now(), exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks);
      const ct = req.headers['content-type'] || '';
      if (ct.includes('application/json')) {
        try {
          resolve(JSON.parse(raw.toString() || '{}'));
        } catch {
          resolve({});
        }
      } else if (ct.includes('multipart/form-data')) {
        resolve(parseMultipart(raw, ct));
      } else {
        resolve({ _raw: raw });
      }
    });
    req.on('error', reject);
  });
}

function parseMultipart(buffer, contentType) {
  const boundaryMatch = contentType.match(/boundary=(.+)/);
  if (!boundaryMatch) return {};
  const boundary = boundaryMatch[1].trim();
  const parts = buffer.toString('binary').split('--' + boundary);
  const result = { files: {}, fields: {} };
  for (const part of parts) {
    if (!part || part === '--\r\n' || part === '--') continue;
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;
    const headers = part.slice(0, headerEnd);
    const body = part.slice(headerEnd + 4, part.lastIndexOf('\r\n'));
    const nameMatch = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    if (filenameMatch) {
      const filename = filenameMatch[1];
      const buf = Buffer.from(body, 'binary');
      result.files[name] = { filename, data: buf, size: buf.length };
    } else {
      result.fields[name] = body;
    }
  }
  return result;
}

function send(res, status, data, headers = {}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': typeof data === 'string' && !headers['Content-Type'] ? 'text/plain' : 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    ...headers
  });
  res.end(body);
}

function getAuth(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return verifyToken(h.slice(7));
  return null;
}

function requireAuth(req, res, roles = null) {
  const user = getAuth(req);
  if (!user) {
    send(res, 401, { error: 'Unauthorized' });
    return null;
  }
  const db = getDb();
  const full = db.users.find(u => u.id === user.id && u.active);
  if (!full) {
    send(res, 401, { error: 'User inactive or not found' });
    return null;
  }
  // Force-logout check: token issued before invalidBefore is rejected
  if (full.invalidBefore && user.iat && user.iat < full.invalidBefore) {
    send(res, 401, { error: 'Session expired — please sign in again' });
    return null;
  }
  if (roles && !roles.includes(full.role)) {
    send(res, 403, { error: 'Forbidden' });
    return null;
  }
  return full;
}

function serveStatic(req, res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const types = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.json': 'application/json',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2'
  };
  if (!fs.existsSync(filePath)) {
    // SPA fallback
    const index = path.join(CLIENT, 'index.html');
    if (fs.existsSync(index)) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      fs.createReadStream(index).pipe(res);
      return;
    }
    send(res, 404, { error: 'Not found' });
    return;
  }
  res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
  fs.createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    send(res, 204, '');
    return;
  }

  const url = new URL(req.url || '/', `http://localhost:${PORT}`);
  const pathname = url.pathname;

  // API routes
  if (pathname.startsWith('/api/')) {
    try {
      await handleApi(req, res, pathname, url);
    } catch (e) {
      console.error(e);
      send(res, 500, { error: e.message || 'Server error' });
    }
    return;
  }

  // Uploads
  if (pathname.startsWith('/uploads/')) {
    const filePath = path.join(UPLOADS, pathname.replace('/uploads/', ''));
    if (filePath.startsWith(UPLOADS) && fs.existsSync(filePath)) {
      serveStatic(req, res, filePath);
      return;
    }
    send(res, 404, { error: 'File not found' });
    return;
  }

  // Client static
  let filePath = path.join(CLIENT, pathname === '/' ? 'index.html' : pathname);
  serveStatic(req, res, filePath);
});

async function handleApi(req, res, pathname, url) {
  const db = getDb();
  const method = req.method;

  // AUTH
  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await parseBody(req);
    const user = db.users.find(u => u.username === body.username && u.active);
    if (!user || user.passwordHash !== hashPassword(body.password || '')) {
      send(res, 401, { error: 'Invalid username or password' });
      return;
    }
    const token = signToken({ id: user.id, username: user.username, role: user.role, name: user.name });
    addAudit(user.id, 'login', 'user', user.id);
    send(res, 200, {
      token,
      user: { id: user.id, username: user.username, name: user.name, role: user.role }
    });
    return;
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    send(res, 200, { id: user.id, username: user.username, name: user.name, role: user.role });
    return;
  }

  // USERS (admin only for write)
  if (pathname === '/api/users' && method === 'GET') {
    const user = requireAuth(req, res, ['admin', 'office']);
    if (!user) return;
    send(res, 200, db.users.map(u => ({
      id: u.id, username: u.username, name: u.name, role: u.role, active: u.active, createdAt: u.createdAt
    })));
    return;
  }

  if (pathname === '/api/users' && method === 'POST') {
    const user = requireAuth(req, res, ['admin']);
    if (!user) return;
    const body = await parseBody(req);
    if (!body.username || !body.password || !body.role) {
      send(res, 400, { error: 'username, password and role required' });
      return;
    }
    if (db.users.some(u => u.username === body.username)) {
      send(res, 400, { error: 'Username already exists' });
      return;
    }
    const newUser = {
      id: crypto.randomUUID(),
      username: body.username,
      passwordHash: hashPassword(body.password),
      name: body.name || body.username,
      role: body.role,
      active: true,
      createdAt: new Date().toISOString()
    };
    db.users.push(newUser);
    persist();
    addAudit(user.id, 'create', 'user', newUser.id, { username: newUser.username });
    send(res, 201, { id: newUser.id, username: newUser.username, name: newUser.name, role: newUser.role, active: true });
    return;
  }

  if (pathname.startsWith('/api/users/') && method === 'PUT') {
    const user = requireAuth(req, res, ['admin']);
    if (!user) return;
    const id = pathname.split('/')[3];
    const target = db.users.find(u => u.id === id);
    if (!target) {
      send(res, 404, { error: 'User not found' });
      return;
    }
    const body = await parseBody(req);
    if (body.name !== undefined) target.name = body.name;
    if (body.username !== undefined && body.username.trim()) {
      const taken = db.users.some(u => u.username === body.username.trim() && u.id !== target.id);
      if (taken) { send(res, 400, { error: 'Username already in use' }); return; }
      target.username = body.username.trim();
    }
    if (body.role !== undefined) target.role = body.role;
    if (body.active !== undefined) target.active = body.active;
    if (body.password) target.passwordHash = hashPassword(body.password);
    persist();
    addAudit(user.id, 'update', 'user', id);
    send(res, 200, { id: target.id, username: target.username, name: target.name, role: target.role, active: target.active });
    return;
  }

  if (pathname.startsWith('/api/users/') && method === 'DELETE') {
    const user = requireAuth(req, res, ['admin']);
    if (!user) return;
    const id = pathname.split('/')[3];
    if (id === user.id) {
      send(res, 400, { error: 'Cannot delete yourself' });
      return;
    }
    const idx = db.users.findIndex(u => u.id === id);
    if (idx === -1) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    db.users.splice(idx, 1);
    persist();
    addAudit(user.id, 'delete', 'user', id);
    send(res, 200, { ok: true });
    return;
  }

  // CUSTOMERS
  if (pathname === '/api/customers' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    const q = (url.searchParams.get('q') || '').toLowerCase();
    let list = db.customers;
    if (q) {
      list = list.filter(c =>
        (c.companyName || '').toLowerCase().includes(q) ||
        (c.contactPerson || '').toLowerCase().includes(q) ||
        (c.phone || '').includes(q) ||
        (c.email || '').toLowerCase().includes(q) ||
        (c.address || '').toLowerCase().includes(q)
      );
    }
    send(res, 200, list);
    return;
  }

  if (pathname === '/api/customers' && method === 'POST') {
    const user = requireAuth(req, res, ['admin', 'office']);
    if (!user) return;
    const body = await parseBody(req);
    const customer = {
      id: crypto.randomUUID(),
      companyName: body.companyName || '',
      contactPerson: body.contactPerson || '',
      phone: body.phone || '',
      email: body.email || '',
      address: body.address || '',
      notes: body.notes || '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    db.customers.push(customer);
    persist();
    addAudit(user.id, 'create', 'customer', customer.id);
    send(res, 201, customer);
    return;
  }

  if (pathname === '/api/customers/import' && method === 'POST') {
    const user = requireAuth(req, res, ['admin', 'office']);
    if (!user) return;
    const body = await parseBody(req);
    const rows = body.customers || [];
    const created = [];
    for (const row of rows) {
      const customer = {
        id: crypto.randomUUID(),
        companyName: row.companyName || row.company || '',
        contactPerson: row.contactPerson || row.contact || '',
        phone: row.phone || '',
        email: row.email || '',
        address: row.address || '',
        notes: row.notes || '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      db.customers.push(customer);
      created.push(customer);
    }
    persist();
    addAudit(user.id, 'import', 'customer', null, { count: created.length });
    send(res, 201, { imported: created.length, customers: created });
    return;
  }

  if (pathname.startsWith('/api/customers/') && method === 'PUT') {
    const user = requireAuth(req, res, ['admin', 'office']);
    if (!user) return;
    const id = pathname.split('/')[3];
    const c = db.customers.find(x => x.id === id);
    if (!c) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    const body = await parseBody(req);
    Object.assign(c, {
      companyName: body.companyName ?? c.companyName,
      contactPerson: body.contactPerson ?? c.contactPerson,
      phone: body.phone ?? c.phone,
      email: body.email ?? c.email,
      address: body.address ?? c.address,
      notes: body.notes ?? c.notes,
      updatedAt: new Date().toISOString()
    });
    persist();
    addAudit(user.id, 'update', 'customer', id);
    send(res, 200, c);
    return;
  }

  if (pathname.startsWith('/api/customers/') && method === 'DELETE') {
    const user = requireAuth(req, res, ['admin']);
    if (!user) return;
    const id = pathname.split('/')[3];
    const idx = db.customers.findIndex(x => x.id === id);
    if (idx === -1) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    db.customers.splice(idx, 1);
    persist();
    addAudit(user.id, 'delete', 'customer', id);
    send(res, 200, { ok: true });
    return;
  }

  // JOB CARDS
  if (pathname === '/api/jobs' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    const status = url.searchParams.get('status');
    const q = (url.searchParams.get('q') || '').toLowerCase();
    let list = [...db.jobCards].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    if (status) list = list.filter(j => j.status === status);
    if (q) {
      list = list.filter(j =>
        String(j.jobNumber).includes(q) ||
        (j.description || '').toLowerCase().includes(q) ||
        (j.siteLocation || '').toLowerCase().includes(q) ||
        (j.customerName || '').toLowerCase().includes(q)
      );
    }
    send(res, 200, list);
    return;
  }

  if (pathname === '/api/jobs' && method === 'POST') {
    const user = requireAuth(req, res, ['admin', 'office', 'field']);
    if (!user) return;
    const body = await parseBody(req);
    const num = nextNumber('job');
    const customer = body.customerId ? db.customers.find(c => c.id === body.customerId) : null;
    const job = {
      id: crypto.randomUUID(),
      jobNumber: `JC-${num}`,
      customerId: body.customerId || null,
      customerName: customer ? customer.companyName : (body.customerName || ''),
      siteLocation: body.siteLocation || '',
      description: body.description || '',
      status: body.status || 'open',
      priority: body.priority || 'normal',
      assignedStaff: body.assignedStaff || [],
      vehicle: body.vehicle || '',
      technician: body.technician || '',
      startDate: body.startDate || null,
      completionDate: body.completionDate || null,
      signature: null,
      photos: [],
      notes: body.notes || '',
      // Job scope
      workCarriedOut: body.workCarriedOut || '',
      timeIn: body.timeIn || '',
      timeOut: body.timeOut || '',
      timeSpentHours: body.timeSpentHours != null && body.timeSpentHours !== '' ? Number(body.timeSpentHours) : null,
      scopeComments: body.scopeComments || '',
      equipmentSpares: body.equipmentSpares || '',
      jobRating: body.jobRating != null && body.jobRating !== '' ? Number(body.jobRating) : null,
      hasInvoice: body.hasInvoice === true || body.hasInvoice === 'true' || body.hasInvoice === 'yes',
      invoiceNumber: body.invoiceNumber || '',
      createdBy: user.id,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    db.jobCards.push(job);
    persist();
    addAudit(user.id, 'create', 'job', job.id, { jobNumber: job.jobNumber });
    send(res, 201, job);
    return;
  }

  if (pathname.startsWith('/api/jobs/') && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = pathname.split('/')[3];
    const job = db.jobCards.find(j => j.id === id);
    if (!job) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    const tasks = db.tasks.filter(t => t.jobId === id);
    send(res, 200, { ...job, tasks });
    return;
  }

  if (pathname.startsWith('/api/jobs/') && method === 'PUT') {
    const user = requireAuth(req, res);
    if (!user) return;
    const parts = pathname.split('/');
    const id = parts[3];
    const action = parts[4];
    const job = db.jobCards.find(j => j.id === id);
    if (!job) {
      send(res, 404, { error: 'Not found' });
      return;
    }

    if (action === 'close') {
      const openTasks = db.tasks.filter(t => t.jobId === id && t.status !== 'completed');
      if (openTasks.length > 0) {
        send(res, 400, { error: 'All tasks must be completed before closing the job card' });
        return;
      }
      if (!job.signature) {
        send(res, 400, { error: 'Customer signature is required before closing' });
        return;
      }
      job.status = 'closed';
      job.completionDate = new Date().toISOString().slice(0, 10);
      job.updatedAt = new Date().toISOString();
      persist();
      addAudit(user.id, 'close', 'job', id);
      send(res, 200, job);
      return;
    }

    if (action === 'signature') {
      const body = await parseBody(req);
      if (!body.signatureData) {
        send(res, 400, { error: 'signatureData required' });
        return;
      }
      const filename = `sig-${id}-${Date.now()}.png`;
      const filePath = path.join(UPLOADS, 'signatures', filename);
      const sigData = body.signatureData;
      const base64 = sigData.replace(/^data:image\/\w+;base64,/, '');
      try {
        fs.mkdirSync(path.join(UPLOADS, 'signatures'), { recursive: true });
        fs.writeFileSync(filePath, Buffer.from(base64, 'base64'));
      } catch (e) {
        console.error('signature file write failed', e.message);
      }
      job.signature = {
        path: `/uploads/signatures/${filename}`,
        data: sigData,
        signedAt: new Date().toISOString(),
        signedBy: body.signedBy || 'Customer'
      };
      job.updatedAt = new Date().toISOString();
      persist();
      addAudit(user.id, 'signature', 'job', id);
      send(res, 200, job);
      return;
    }

    if (action === 'photo') {
      const body = await parseBody(req);
      let photoEntry = null;
      try { fs.mkdirSync(path.join(UPLOADS, 'photos'), { recursive: true }); } catch (_) {}
      if (body.files && body.files.photo) {
        const f = body.files.photo;
        const ext = path.extname(f.filename) || '.jpg';
        const filename = `photo-${id}-${Date.now()}${ext}`;
        try { fs.writeFileSync(path.join(UPLOADS, 'photos', filename), f.data); } catch (e) { console.error(e.message); }
        const dataUrl = 'data:image/jpeg;base64,' + f.data.toString('base64');
        photoEntry = {
          id: crypto.randomUUID(),
          path: `/uploads/photos/${filename}`,
          data: dataUrl,
          note: body.fields?.note || '',
          type: body.fields?.type || 'completion',
          uploadedAt: new Date().toISOString(),
          uploadedBy: user.id
        };
      } else if (body.imageData) {
        const filename = `photo-${id}-${Date.now()}.jpg`;
        const imageData = body.imageData;
        const base64 = imageData.replace(/^data:image\/\w+;base64,/, '');
        try { fs.writeFileSync(path.join(UPLOADS, 'photos', filename), Buffer.from(base64, 'base64')); } catch (e) { console.error(e.message); }
        photoEntry = {
          id: crypto.randomUUID(),
          path: `/uploads/photos/${filename}`,
          data: imageData,
          note: body.note || '',
          type: body.type || 'completion',
          uploadedAt: new Date().toISOString(),
          uploadedBy: user.id
        };
      }
      if (!photoEntry) {
        send(res, 400, { error: 'No photo data' });
        return;
      }
      job.photos = job.photos || [];
      job.photos.push(photoEntry);
      job.updatedAt = new Date().toISOString();
      persist();
      addAudit(user.id, 'photo', 'job', id);
      send(res, 200, job);
      return;
    }

    if (action === 'delete-photo') {
      const body = await parseBody(req);
      const photoId = body.photoId;
      if (!photoId) {
        send(res, 400, { error: 'photoId required' });
        return;
      }
      job.photos = job.photos || [];
      const photo = job.photos.find(p => p.id === photoId);
      if (!photo) {
        send(res, 404, { error: 'Photo not found' });
        return;
      }
      // try remove file from disk
      if (photo.path && photo.path.startsWith('/uploads/')) {
        try {
          const fp = path.join(UPLOADS, photo.path.replace('/uploads/', ''));
          if (fp.startsWith(UPLOADS) && fs.existsSync(fp)) fs.unlinkSync(fp);
        } catch (e) {
          console.error('photo file delete failed', e.message);
        }
      }
      job.photos = job.photos.filter(p => p.id !== photoId);
      job.updatedAt = new Date().toISOString();
      persist();
      addAudit(user.id, 'delete-photo', 'job', id, { photoId });
      send(res, 200, job);
      return;
    }

    // general update
    const body = await parseBody(req);
    const allowed = ['customerId', 'customerName', 'siteLocation', 'description', 'status', 'priority', 'assignedStaff', 'vehicle', 'technician', 'startDate', 'completionDate', 'notes', 'workCarriedOut', 'timeIn', 'timeOut', 'scopeComments', 'equipmentSpares', 'jobRating', 'hasInvoice', 'invoiceNumber', 'timeSpentHours'];
    for (const k of allowed) {
      if (body[k] !== undefined) job[k] = body[k];
    }
    if (body.jobRating !== undefined) {
      job.jobRating = body.jobRating === '' || body.jobRating === null ? null : Number(body.jobRating);
    }
    if (body.hasInvoice !== undefined) {
      job.hasInvoice = body.hasInvoice === true || body.hasInvoice === 'true' || body.hasInvoice === 'yes' || body.hasInvoice === 'on';
      if (!job.hasInvoice) job.invoiceNumber = '';
    }
    if (body.invoiceNumber !== undefined && job.hasInvoice) {
      job.invoiceNumber = body.invoiceNumber || '';
    }
    if (body.invoiceNumber !== undefined && body.hasInvoice === false) {
      job.invoiceNumber = '';
    }
    if (body.customerId) {
      const c = db.customers.find(x => x.id === body.customerId);
      if (c) job.customerName = c.companyName;
    }
    job.updatedAt = new Date().toISOString();
    persist();
    addAudit(user.id, 'update', 'job', id);
    send(res, 200, job);
    return;
  }

  if (pathname.startsWith('/api/jobs/') && method === 'DELETE') {
    const user = requireAuth(req, res, ['admin', 'office', 'field']);
    if (!user) return;

    const id = pathname.split('/')[3];
    const idx = db.jobCards.findIndex(j => j.id === id);
    if (idx === -1) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    db.jobCards.splice(idx, 1);
    db.tasks = db.tasks.filter(t => t.jobId !== id);
    persist();
    addAudit(user.id, 'delete', 'job', id);
    send(res, 200, { ok: true });
    return;
  }

  // TASKS
  if (pathname === '/api/tasks' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    const jobId = url.searchParams.get('jobId');
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    let list = [...db.tasks];
    if (jobId) list = list.filter(t => t.jobId === jobId);
    if (from) list = list.filter(t => t.dueDate >= from);
    if (to) list = list.filter(t => t.dueDate <= to);
    send(res, 200, list);
    return;
  }

  if (pathname === '/api/tasks' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) return;
    const body = await parseBody(req);
    if (!body.jobId) {
      send(res, 400, { error: 'jobId required' });
      return;
    }
    const job = db.jobCards.find(j => j.id === body.jobId);
    if (!job) {
      send(res, 404, { error: 'Job not found' });
      return;
    }
    const task = {
      id: crypto.randomUUID(),
      jobId: body.jobId,
      jobNumber: job.jobNumber,
      title: body.title || 'Task',
      notes: body.notes || '',
      status: body.status || 'pending',
      assignedStaff: body.assignedStaff || [],
      dueDate: body.dueDate || new Date().toISOString().slice(0, 10),
      startTime: body.startTime || null,
      endTime: body.endTime || null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    db.tasks.push(task);
    persist();
    addAudit(user.id, 'create', 'task', task.id);
    send(res, 201, task);
    return;
  }

  if (pathname.startsWith('/api/tasks/') && method === 'PUT') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = pathname.split('/')[3];
    const task = db.tasks.find(t => t.id === id);
    if (!task) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    const body = await parseBody(req);
    const fields = ['title', 'notes', 'status', 'assignedStaff', 'dueDate', 'startTime', 'endTime'];
    for (const f of fields) {
      if (body[f] !== undefined) task[f] = body[f];
    }
    task.updatedAt = new Date().toISOString();
    // auto update job if needed
    if (body.dueDate || body.startTime) {
      const job = db.jobCards.find(j => j.id === task.jobId);
      if (job && job.status === 'open') {
        // optional: sync start date
      }
    }
    persist();
    addAudit(user.id, 'update', 'task', id);
    send(res, 200, task);
    return;
  }

  if (pathname.startsWith('/api/tasks/') && method === 'DELETE') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = pathname.split('/')[3];
    const idx = db.tasks.findIndex(t => t.id === id);
    if (idx === -1) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    db.tasks.splice(idx, 1);
    persist();
    addAudit(user.id, 'delete', 'task', id);
    send(res, 200, { ok: true });
    return;
  }

  // DELIVERIES / COLLECTIONS
  if (pathname === '/api/deliveries' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    const type = url.searchParams.get('type');
    let list = [...db.deliveries].sort((a, b) => new Date(b.dateTime) - new Date(a.dateTime));
    if (type) list = list.filter(d => d.type === type);
    send(res, 200, list);
    return;
  }

  if (pathname === '/api/deliveries' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) return;
    const body = await parseBody(req);
    const num = nextNumber('delivery');
    const entry = {
      id: crypto.randomUUID(),
      ref: `DC-${num}`,
      type: body.type || 'delivery', // delivery | collection
      dateTime: body.dateTime || new Date().toISOString(),
      itemDetails: body.itemDetails || '',
      customerId: body.customerId || null,
      customerName: body.customerName || '',
      site: body.site || '',
      driver: body.driver || user.name,
      status: body.status || 'completed',
      notes: body.notes || '',
      jobId: body.jobId || null,
      signature: null,
      createdBy: user.id,
      createdAt: new Date().toISOString()
    };
    db.deliveries.push(entry);
    persist();
    addAudit(user.id, 'create', 'delivery', entry.id);
    send(res, 201, entry);
    return;
  }

  if (pathname.startsWith('/api/deliveries/') && method === 'PUT') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = pathname.split('/')[3];
    const entry = db.deliveries.find(d => d.id === id);
    if (!entry) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    const body = await parseBody(req);
    if (body.signatureData) {
      const filename = `sig-dc-${Date.now()}.png`;
      const sigData = body.signatureData;
      try {
        fs.mkdirSync(path.join(UPLOADS, 'signatures'), { recursive: true });
        const base64 = sigData.replace(/^data:image\/\w+;base64,/, '');
        fs.writeFileSync(path.join(UPLOADS, 'signatures', filename), Buffer.from(base64, 'base64'));
      } catch (e) { console.error('dc signature write', e.message); }
      entry.signature = {
        path: `/uploads/signatures/${filename}`,
        data: sigData,
        signedBy: body.signedBy || 'Recipient',
        signedAt: new Date().toISOString()
      };
      persist();
      addAudit(user.id, 'signature', 'delivery', id);
      send(res, 200, entry);
      return;
    }
    Object.assign(entry, {
      type: body.type ?? entry.type,
      dateTime: body.dateTime ?? entry.dateTime,
      itemDetails: body.itemDetails ?? entry.itemDetails,
      customerId: body.customerId ?? entry.customerId,
      customerName: body.customerName ?? entry.customerName,
      site: body.site ?? entry.site,
      driver: body.driver ?? entry.driver,
      status: body.status ?? entry.status,
      notes: body.notes ?? entry.notes,
      jobId: body.jobId ?? entry.jobId
    });
    persist();
    addAudit(user.id, 'update', 'delivery', id);
    send(res, 200, entry);
    return;
  }

  if (pathname.startsWith('/api/deliveries/') && method === 'DELETE') {
    const user = requireAuth(req, res, ['admin', 'office', 'field']);
    if (!user) return;
    const id = pathname.split('/')[3];
    const idx = db.deliveries.findIndex(d => d.id === id);
    if (idx === -1) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    db.deliveries.splice(idx, 1);
    persist();
    addAudit(user.id, 'delete', 'delivery', id);
    send(res, 200, { ok: true });
    return;
  }

  // FUEL LOGS
  if (pathname === '/api/fuel' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    send(res, 200, [...db.fuelLogs].sort((a, b) => new Date(b.dateTime) - new Date(a.dateTime)));
    return;
  }

  if (pathname === '/api/fuel' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) return;
    const body = await parseBody(req);
    const num = nextNumber('fuel');
    let receiptPath = null;
    if (body.receiptData) {
      const filename = `fuel-${Date.now()}.jpg`;
      const base64 = body.receiptData.replace(/^data:image\/\w+;base64,/, '');
      fs.writeFileSync(path.join(UPLOADS, 'fuel', filename), Buffer.from(base64, 'base64'));
      receiptPath = `/uploads/fuel/${filename}`;
    } else if (body.files && body.files.receipt) {
      const f = body.files.receipt;
      const filename = `fuel-${Date.now()}${path.extname(f.filename) || '.jpg'}`;
      fs.writeFileSync(path.join(UPLOADS, 'fuel', filename), f.data);
      receiptPath = `/uploads/fuel/${filename}`;
    }
    const entry = {
      id: crypto.randomUUID(),
      ref: `FL-${num}`,
      dateTime: body.dateTime || new Date().toISOString(),
      vehicle: body.vehicle || 'Company Van',
      registration: body.registration || '',
      odometer: body.odometer ? Number(body.odometer) : null,
      fuelType: body.fuelType || 'Diesel',
      litres: body.litres ? Number(body.litres) : null,
      amount: body.amount ? Number(body.amount) : null,
      paymentMethod: body.paymentMethod || '',
      station: body.station || '',
      driver: body.driver || user.name,
      notes: body.notes || '',
      receipt: receiptPath,
      receiptData: body.receiptData || null,
      createdBy: user.id,
      createdAt: new Date().toISOString()
    };
    db.fuelLogs.push(entry);
    persist();
    addAudit(user.id, 'create', 'fuel', entry.id);
    send(res, 201, entry);
    return;
  }

  if (pathname.startsWith('/api/fuel/') && method === 'PUT') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = pathname.split('/')[3];
    const entry = db.fuelLogs.find(f => f.id === id);
    if (!entry) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    const body = await parseBody(req);
    if (body.clearReceipt === true || body.clearReceipt === 'true' || body.clearReceipt === '1') {
      entry.receipt = null;
      entry.receiptData = null;
    }
    if (body.receiptData) {
      try {
        fs.mkdirSync(path.join(UPLOADS, 'fuel'), { recursive: true });
        const filename = `fuel-${Date.now()}.jpg`;
        const base64 = body.receiptData.replace(/^data:image\/\w+;base64,/, '');
        fs.writeFileSync(path.join(UPLOADS, 'fuel', filename), Buffer.from(base64, 'base64'));
        entry.receipt = `/uploads/fuel/${filename}`;
        entry.receiptData = body.receiptData;
      } catch (e) {
        console.error(e.message);
        entry.receiptData = body.receiptData;
      }
    }
    Object.assign(entry, {
      dateTime: body.dateTime ?? entry.dateTime,
      vehicle: body.vehicle ?? entry.vehicle,
      registration: body.registration ?? entry.registration,
      odometer: body.odometer !== undefined && body.odometer !== '' ? Number(body.odometer) : entry.odometer,
      fuelType: body.fuelType ?? entry.fuelType,
      litres: body.litres !== undefined && body.litres !== '' ? Number(body.litres) : entry.litres,
      amount: body.amount !== undefined && body.amount !== '' ? Number(body.amount) : entry.amount,
      paymentMethod: body.paymentMethod ?? entry.paymentMethod,
      station: body.station ?? entry.station,
      driver: body.driver ?? entry.driver,
      notes: body.notes ?? entry.notes
    });
    entry.updatedAt = new Date().toISOString();
    persist();
    addAudit(user.id, 'update', 'fuel', id);
    send(res, 200, entry);
    return;
  }

  if (pathname.startsWith('/api/fuel/') && method === 'DELETE') {
    const user = requireAuth(req, res, ['admin', 'office', 'field']);
    if (!user) return;
    const id = pathname.split('/')[3];
    const idx = db.fuelLogs.findIndex(f => f.id === id);
    if (idx === -1) {
      send(res, 404, { error: 'Not found' });
      return;
    }
    db.fuelLogs.splice(idx, 1);
    persist();
    addAudit(user.id, 'delete', 'fuel', id);
    send(res, 200, { ok: true });
    return;
  }


  // VEHICLES
  if (pathname === '/api/vehicles' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    send(res, 200, db.vehicles || []);
    return;
  }

  if (pathname === '/api/vehicles' && method === 'POST') {
    const user = requireAuth(req, res, ['admin', 'office']);
    if (!user) return;
    const body = await parseBody(req);
    if (!body.name) { send(res, 400, { error: 'Vehicle name required' }); return; }
    const v = {
      id: crypto.randomUUID(),
      name: body.name.trim(),
      registration: (body.registration || '').trim(),
      notes: body.notes || '',
      active: body.active !== false,
      createdAt: new Date().toISOString()
    };
    db.vehicles = db.vehicles || [];
    db.vehicles.push(v);
    persist();
    addAudit(user.id, 'create', 'vehicle', v.id);
    send(res, 201, v);
    return;
  }

  if (pathname.startsWith('/api/vehicles/') && method === 'PUT') {
    const user = requireAuth(req, res, ['admin', 'office']);
    if (!user) return;
    const id = pathname.split('/')[3];
    const v = (db.vehicles || []).find(x => x.id === id);
    if (!v) { send(res, 404, { error: 'Not found' }); return; }
    const body = await parseBody(req);
    if (body.name !== undefined) v.name = body.name.trim();
    if (body.registration !== undefined) v.registration = body.registration.trim();
    if (body.notes !== undefined) v.notes = body.notes;
    if (body.active !== undefined) v.active = !!body.active;
    v.updatedAt = new Date().toISOString();
    persist();
    addAudit(user.id, 'update', 'vehicle', id);
    send(res, 200, v);
    return;
  }

  if (pathname.startsWith('/api/vehicles/') && method === 'DELETE') {
    const user = requireAuth(req, res, ['admin']);
    if (!user) return;
    const id = pathname.split('/')[3];
    db.vehicles = db.vehicles || [];
    const idx = db.vehicles.findIndex(x => x.id === id);
    if (idx === -1) { send(res, 404, { error: 'Not found' }); return; }
    db.vehicles.splice(idx, 1);
    persist();
    addAudit(user.id, 'delete', 'vehicle', id);
    send(res, 200, { ok: true });
    return;
  }

  // DASHBOARD
  if (pathname === '/api/dashboard' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    const openJobs = db.jobCards.filter(j => j.status === 'open' || j.status === 'in_progress').length;
    const closedJobs = db.jobCards.filter(j => j.status === 'closed').length;
    const overdueTasks = db.tasks.filter(t => t.status !== 'completed' && t.dueDate < new Date().toISOString().slice(0, 10)).length;
    const pendingTasks = db.tasks.filter(t => t.status !== 'completed').length;
    const deliveries = db.deliveries.filter(d => d.type === 'delivery').length;
    const collections = db.deliveries.filter(d => d.type === 'collection').length;
    const fuelSpend = db.fuelLogs.reduce((s, f) => s + (f.amount || 0), 0);
    const recentJobs = [...db.jobCards].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)).slice(0, 8);
    send(res, 200, {
      openJobs,
      closedJobs,
      overdueTasks,
      pendingTasks,
      deliveries,
      collections,
      fuelSpend,
      recentJobs
    });
    return;
  }

  // AUDIT
  if (pathname === '/api/audit' && method === 'GET') {
    const user = requireAuth(req, res, ['admin']);
    if (!user) return;
    send(res, 200, db.audit.slice(0, 200));
    return;
  }

  // FORCE LOGOUT — preset Admin account only
  if (pathname === '/api/admin/force-logout' && method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) return;
    if (user.id !== 'admin-1' && user.username !== 'Admin') {
      send(res, 403, { error: 'Only the system Admin account can force logout' });
      return;
    }
    const admin = db.users.find(u => u.id === 'admin-1' || u.username === 'Admin');
    if (admin) {
      admin.invalidBefore = Date.now();
      persist();
      addAudit(user.id, 'force-logout', 'user', admin.id);
    }
    send(res, 200, { ok: true });
    return;
  }

  // STAFF list for assignment
  if (pathname === '/api/staff' && method === 'GET') {
    const user = requireAuth(req, res);
    if (!user) return;
    send(res, 200, db.users.filter(u => u.active).map(u => ({ id: u.id, name: u.name, role: u.role })));
    return;
  }

  send(res, 404, { error: 'API route not found' });
}

initDb().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`JobCard Ops server running on http://0.0.0.0:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
