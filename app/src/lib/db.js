/**
 * In-memory SQLite (sql.js / WASM) so the SQL-injection PoC runs against a REAL
 * SQL engine with zero native build dependencies. Seeded with two tenants so we
 * can demonstrate SQLi (V-01) and IDOR (V-09) authentically.
 */
import initSqlJs from 'sql.js';

let db = null;

export async function initDb() {
  if (db) return db;
  const SQL = await initSqlJs();
  db = new SQL.Database();

  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      email TEXT UNIQUE,
      password_hash TEXT,
      role TEXT,
      cedula TEXT,          -- Colombian national ID (PII, Ley 1581)
      api_secret TEXT
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY,
      owner_id INTEGER,
      vehicle_plate TEXT,   -- fleet telemetry PII
      gps_last TEXT,
      amount INTEGER
    );
  `);

  // Seed users. api_secret is the "crown jewel" a SQLi is meant to exfiltrate.
  db.run(`
    INSERT INTO users (id, email, password_hash, role, cedula, api_secret) VALUES
      (1, 'alice@fleetsec.co', 'pbkdf2$alice', 'user',  '1020304050', 'SECRET_ALICE_a1b2c3'),
      (2, 'bob@fleetsec.co',   'pbkdf2$bob',   'user',  '1122334455', 'SECRET_BOB_d4e5f6'),
      (3, 'root@fleetsec.co',  'pbkdf2$root',  'admin', '9998887770', 'SECRET_ADMIN_deadbeef');
  `);

  db.run(`
    INSERT INTO orders (id, owner_id, vehicle_plate, gps_last, amount) VALUES
      (100, 1, 'ABC123', '4.6097,-74.0817', 250000),
      (101, 2, 'XYZ789', '6.2442,-75.5812', 480000),
      (102, 3, 'GOV001', '4.7110,-74.0721', 999000);
  `);

  return db;
}

export function getDb() {
  if (!db) throw new Error('DB not initialised — call initDb() first');
  return db;
}
