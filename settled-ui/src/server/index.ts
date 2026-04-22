import express from 'express';
import { rateLimit } from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sthRouter } from './routes/sth.js';
import { entriesRouter } from './routes/entries.js';
import { proofsRouter } from './routes/proofs.js';
import { eventsRouter } from './routes/events.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env['PORT'] ?? 3000);
const IS_PROD = process.env['NODE_ENV'] === 'production';

const app = express();
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/events',
});
app.use('/api', limiter);

app.use('/api/sth',     sthRouter);
app.use('/api/entries', entriesRouter);
app.use('/api/entries', proofsRouter);
app.use('/api/events',  eventsRouter);

if (IS_PROD) {
  const staticDir = path.resolve(__dirname, '../../public');
  app.use(express.static(staticDir));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(staticDir, 'index.html'));
  });
}

app.listen(PORT, () => {
  const grpcAddr = process.env['SETTLED_ADDR'] ?? 'localhost:50051';
  console.log(`settled-ui  http://localhost:${PORT}  (gRPC → ${grpcAddr})`);
});
