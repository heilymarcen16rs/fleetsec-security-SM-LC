import express from 'express';
import helmet from 'helmet';
import fs from 'node:fs';
import { initDb } from './lib/db.js';
import { vulnerableRouter } from './routes/vulnerable.js';
import { secureRouter } from './routes/secure.js';

const OPENAPI = new URL('../openapi.yaml', import.meta.url);

export async function buildApp() {
  await initDb();
  const app = express();

  // Secure defaults for the whole app (does not neuter the /vuln lab handlers,
  // which are the payload sinks we deliberately test).
  app.disable('x-powered-by');
  app.use(helmet());

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));

  // Serve the OpenAPI contract so the authenticated DAST scan (ZAP) can load it.
  app.get('/openapi.yaml', (_req, res) => {
    try {
      res.type('application/yaml').send(fs.readFileSync(OPENAPI, 'utf8'));
    } catch {
      res.status(404).json({ error: 'openapi spec not found' });
    }
  });

  // Lab surface (deliberately vulnerable) — gated so it cannot ship enabled.
  if (process.env.LAB_MODE !== 'false') {
    app.use('/vuln', vulnerableRouter);
  }
  // Remediated surface.
  app.use('/secure', secureRouter);

  return app;
}
