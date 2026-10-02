// TypeScript API with intentional vulnerabilities — CATO testing only
import express, { Request, Response } from 'express';
import { execSync } from 'child_process';

const app = express();
app.use(express.json());

// CRITICAL: Hardcoded database connection string
const db_url = "postgresql://admin:password123@prod.db.internal:5432/users";

// CRITICAL: Hardcoded API key
const api_key = "sk-live-xxxxxxxxxxxxxxxxxxxxxxxx";

// HIGH: SQL query with template literal interpolation
async function findUser(pool: any, username: string) {
  return pool.query(`SELECT * FROM users WHERE username = '${username}'`);
}

// HIGH: eval with user input
app.post('/run', (req: Request, res: Response) => {
  const result = eval(req.body.code);
  res.json({ result });
});

// HIGH: execSync with template literal
app.get('/status', (req: Request, res: Response) => {
  const output = execSync(`systemctl status ${req.query.service}`);
  res.send(output.toString());
});

// HIGH: new Function
function buildValidator(rule: string) {
  return new Function('value', `return ${rule}`);
}

// HIGH: innerHTML
function updateDOM(data: string): void {
  document.getElementById('output')!.innerHTML = data;
}

// MEDIUM: insecure random
function generateId(): string {
  return Math.random().toString(36).slice(2);
}

app.listen(4000);
export default app;
