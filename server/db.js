import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { MongoClient } from 'mongodb';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, 'data.json');
const UPLOADS = path.join(__dirname, '..', 'uploads');
const MONGO_URI = process.env.MONGODB_URI || '';

const defaultData = {
  users: [
    {
      id: 'admin-1',
      username: 'Admin',
      passwordHash: hashPassword('@dmin2117'),
      name: 'System Admin',
      role: 'admin',
      active: true,
      createdAt: new Date().toISOString()
    }
  ],
  customers: [],
  jobCards: [],
  tasks: [],
  deliveries: [],
  fuelLogs: [],
  vehicles: [],
  audit: [],
  counters: { job: 1000, delivery: 1000, fuel: 1000 }
};

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'jobcard-salt-v1').digest('hex');
}

function ensureDirs() {
  ['photos', 'signatures', 'fuel', 'receipts'].forEach(d => {
    const p = path.join(UPLOADS, d);
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
  });
}
ensureDirs();

function ensureAdmin(data) {
  data.users = data.users || [];
  const admin = data.users.find(u => u.username === 'Admin' || u.id === 'admin-1');
  if (!admin) {
    data.users.unshift({
      id: 'admin-1',
      username: 'Admin',
      passwordHash: hashPassword('@dmin2117'),
      name: 'System Admin',
      role: 'admin',
      active: true,
      createdAt: new Date().toISOString()
    });
  } else if (admin.id === 'admin-1' && admin.username === 'admin') {
    admin.username = 'Admin';
    admin.passwordHash = hashPassword('@dmin2117');
    admin.name = 'System Admin';
    admin.role = 'admin';
    admin.active = true;
  }
  data.users = data.users.filter(u => u.id !== 'office-1' && u.id !== 'field-1');
  data.customers = data.customers || [];
  data.jobCards = data.jobCards || [];
  data.tasks = data.tasks || [];
  data.deliveries = data.deliveries || [];
  data.fuelLogs = data.fuelLogs || [];
  data.vehicles = data.vehicles || [];
  data.audit = data.audit || [];
  data.counters = data.counters || { job: 1000, delivery: 1000, fuel: 1000 };
  return data;
}

// ---------- MongoDB backend ----------
let mongoClient = null;
let mongoCol = null;

async function connectMongo() {
  if (mongoCol) return mongoCol;
  mongoClient = new MongoClient(MONGO_URI);
  await mongoClient.connect();
  const database = mongoClient.db(process.env.MONGODB_DB || 'jobcardops');
  mongoCol = database.collection('appdata');
  console.log('Connected to MongoDB');
  return mongoCol;
}

async function loadFromMongo() {
  const col = await connectMongo();
  let doc = await col.findOne({ _id: 'main' });
  if (!doc) {
    const data = ensureAdmin(structuredClone(defaultData));
    await col.insertOne({ _id: 'main', data });
    return data;
  }
  const data = ensureAdmin(doc.data || {});
  return data;
}

async function saveToMongo(data) {
  const col = await connectMongo();
  await col.updateOne({ _id: 'main' }, { $set: { data } }, { upsert: true });
}

// ---------- File backend (local / fallback) ----------
function loadFromFile() {
  let data;
  try {
    if (fs.existsSync(DB_PATH)) {
      data = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {
    console.error('DB load error', e.message);
  }
  if (!data) data = structuredClone(defaultData);
  data = ensureAdmin(data);
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
  return data;
}

function saveToFile(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ---------- Public API (sync-looking via cached object) ----------
let db = null;
let useMongo = !!MONGO_URI;

export async function initDb() {
  if (useMongo) {
    try {
      db = await loadFromMongo();
      console.log('Using MongoDB for persistence');
    } catch (e) {
      console.error('MongoDB failed, falling back to file:', e.message);
      useMongo = false;
      db = loadFromFile();
    }
  } else {
    db = loadFromFile();
    console.log('Using local data.json (set MONGODB_URI for persistent storage)');
  }
  return db;
}

export function getDb() {
  if (!db) {
    // Sync fallback if initDb wasn't awaited (shouldn't happen)
    db = loadFromFile();
  }
  return db;
}

export function persist() {
  if (!db) return;
  if (useMongo) {
    saveToMongo(db).catch(e => console.error('Mongo save error', e.message));
  } else {
    saveToFile(db);
  }
}

export function reload() {
  return getDb();
}

export { hashPassword };

export function addAudit(userId, action, entity, entityId, details = {}) {
  const d = getDb();
  d.audit = d.audit || [];
  d.audit.unshift({
    id: crypto.randomUUID(),
    userId,
    action,
    entity,
    entityId,
    details,
    at: new Date().toISOString()
  });
  if (d.audit.length > 2000) d.audit = d.audit.slice(0, 2000);
  persist();
}

export function nextNumber(type) {
  const d = getDb();
  d.counters = d.counters || { job: 1000, delivery: 1000, fuel: 1000 };
  d.counters[type] = (d.counters[type] || 1000) + 1;
  persist();
  return d.counters[type];
}
