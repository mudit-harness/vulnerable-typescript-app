// Intentionally Vulnerable TypeScript/Express Application
// DO NOT USE IN PRODUCTION - FOR SECURITY TESTING ONLY

import * as express from 'express';
import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
import * as session from 'express-session';
import * as jwt from 'jsonwebtoken';
import { execFile } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as axios from 'axios';
import * as xml2js from 'xml2js';
import * as yaml from 'js-yaml';
import * as _ from 'lodash';
import { Request, Response } from 'express';

const app = express();
const PORT = process.env.PORT || 3001;

// VULNERABILITY: Hardcoded secrets (CWE-798)
const JWT_SECRET: string = 'super_secret_typescript_key_12345';
const ADMIN_PASSWORD: string = 'admin123';
const DB_PASSWORD: string = 'password123';

// VULNERABILITY: Debug mode enabled in production
app.set('env', 'development');

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// VULNERABILITY: Insecure session configuration (CWE-1004)
app.use(session({
  secret: 'insecure-typescript-session-secret',
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false, // Should be true in HTTPS
    httpOnly: false, // Vulnerable to XSS
    maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year - too long
  }
}));

// VULNERABILITY: CORS misconfiguration (CWE-942)
app.use((req: Request, res: Response, next: express.NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// In-memory user store (simulating database)
interface User {
  id: number;
  username: string;
  password: string;
  email: string;
  role: string;
}

const users: User[] = [
  { id: 1, username: 'admin', password: '$2b$10$abcdefghijklmnopqrstuvwxyz', email: 'admin@example.com', role: 'admin' },
  { id: 2, username: 'user', password: '$2b$10$1234567890abcdefghijklmno', email: 'user@example.com', role: 'user' }
];

// VULNERABILITY: SQL Injection (CWE-89) - simulated with string concatenation
app.post('/api/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Vulnerable: Direct string concatenation simulating SQL injection
  const query: string = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log('Query:', query); // This would be vulnerable in real SQL

  const user = users.find((u: User) => u.username === username);
  if (user) {
    // VULNERABILITY: Weak JWT signing with predictable secret (CWE-327)
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, user });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// Allowlist: DNS hostname labels or IPv4 addresses only - no shell metacharacters,
// no leading '-' (so the value can never be read as a ping option).
const HOSTNAME_ALLOWLIST: RegExp = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

app.get('/api/ping', (req: Request, res: Response) => {
  const host: string = req.query.host as string;
  // Fixed (CWE-78): reject anything that is not a plain hostname or IPv4 address
  if (typeof host !== 'string' || host.length > 253 || !HOSTNAME_ALLOWLIST.test(host)) {
    res.status(400).json({ error: 'Invalid host' });
    return;
  }
  // Fixed (CWE-78): argv array via execFile - no shell is spawned, so the
  // validated host cannot be interpreted as a shell command
  execFile('ping', ['-c', '3', host], (error: any, stdout: string, stderr: string) => {
    if (error) {
      res.json({ error: error.message, stdout, stderr });
    } else {
      res.json({ success: true, output: stdout });
    }
  });
});

// Allowlist: a single safe basename - letters, digits, '_', '-', '.' only.
// No path separators, no leading dot, and '..' can never match.
const UPLOAD_FILENAME_ALLOWLIST: RegExp = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;

// Canonical root of the intended destination directory, resolved once.
const UPLOADS_ROOT: string = path.resolve(__dirname, '../uploads');

app.get('/api/files', (req: Request, res: Response) => {
  const filename: string = req.query.filename as string;
  // Fixed (CWE-22): only accept a bare filename - reject separators and traversal
  if (typeof filename !== 'string' || filename.length > 255 ||
      !UPLOAD_FILENAME_ALLOWLIST.test(filename)) {
    res.status(400).json({ error: 'Invalid filename' });
    return;
  }
  // Fixed (CWE-22): canonicalize the candidate and confine it to UPLOADS_ROOT
  // using a path-boundary-safe check, so a sibling like '../uploadsevil' cannot match
  const filePath: string = path.resolve(UPLOADS_ROOT, filename);
  if (filePath !== UPLOADS_ROOT && !filePath.startsWith(UPLOADS_ROOT + path.sep)) {
    res.status(400).json({ error: 'Invalid filename' });
    return;
  }
  fs.readFile(filePath, 'utf8', (err: NodeJS.ErrnoException | null, data: string) => {
    if (err) {
      res.status(404).json({ error: 'File not found' });
    } else {
      res.send(data);
    }
  });
});

// VULNERABILITY: Cross-Site Scripting (XSS) (CWE-79)
app.get('/api/search', (req: Request, res: Response) => {
  const query: string = req.query.query as string;
  // Vulnerable: Reflects user input without sanitization
  res.send(`<h1>Search Results for: ${query}</h1>`);
});

// VULNERABILITY: Server-Side Request Forgery (SSRF) (CWE-918)
app.get('/api/proxy', async (req: Request, res: Response) => {
  const url: string = req.query.url as string;
  // Vulnerable: No URL validation, allows internal network access
  try {
    const response = await axios.default.get(url);
    res.json(response.data);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Allowlist: decimal numbers, the four arithmetic operators, modulo, parentheses
// and whitespace only. Simple character class, so it cannot backtrack (no ReDoS).
const ARITHMETIC_EXPRESSION: RegExp = /^[0-9+\-*/%().\s]+$/;
const MAX_EXPRESSION_LENGTH: number = 256;

// Fixed (CWE-94/95): arithmetic is evaluated by this small recursive-descent
// parser instead of eval(). Request data is only ever read as numbers and
// operators - it is never handed to a dynamic-code sink (no eval, no Function,
// no vm), so arbitrary code execution is not possible.
function evaluateArithmetic(input: string): number {
  let pos: number = 0;

  function skipWhitespace(): void {
    while (pos < input.length && (input[pos] === ' ' || input[pos] === '\t')) {
      pos++;
    }
  }

  function parseNumber(): number {
    const start: number = pos;
    while (pos < input.length && input[pos] >= '0' && input[pos] <= '9') {
      pos++;
    }
    if (input[pos] === '.') {
      pos++;
      while (pos < input.length && input[pos] >= '0' && input[pos] <= '9') {
        pos++;
      }
    }
    if (pos === start || input.slice(start, pos) === '.') {
      throw new Error('Invalid expression');
    }
    return parseFloat(input.slice(start, pos));
  }

  function parseFactor(): number {
    skipWhitespace();
    if (input[pos] === '+') {
      pos++;
      return parseFactor();
    }
    if (input[pos] === '-') {
      pos++;
      return -parseFactor();
    }
    if (input[pos] === '(') {
      pos++;
      const value: number = parseSum();
      skipWhitespace();
      if (input[pos] !== ')') {
        throw new Error('Invalid expression');
      }
      pos++;
      return value;
    }
    return parseNumber();
  }

  function parseProduct(): number {
    let value: number = parseFactor();
    for (;;) {
      skipWhitespace();
      const operator: string = input[pos];
      if (operator !== '*' && operator !== '/' && operator !== '%') {
        return value;
      }
      pos++;
      const right: number = parseFactor();
      if (operator === '*') {
        value = value * right;
      } else if (operator === '/') {
        value = value / right;
      } else {
        value = value % right;
      }
    }
  }

  function parseSum(): number {
    let value: number = parseProduct();
    for (;;) {
      skipWhitespace();
      const operator: string = input[pos];
      if (operator !== '+' && operator !== '-') {
        return value;
      }
      pos++;
      const right: number = parseProduct();
      value = operator === '+' ? value + right : value - right;
    }
  }

  const result: number = parseSum();
  skipWhitespace();
  if (pos !== input.length || !Number.isFinite(result)) {
    throw new Error('Invalid expression');
  }
  return result;
}

app.post('/api/calculate', (req: Request, res: Response) => {
  const { expression } = req.body;
  // Fixed (CWE-94/95): reject anything that is not a plain arithmetic expression
  if (typeof expression !== 'string' || expression.length === 0 ||
      expression.length > MAX_EXPRESSION_LENGTH || !ARITHMETIC_EXPRESSION.test(expression)) {
    res.status(400).json({ error: 'Invalid expression' });
    return;
  }
  try {
    const result: number = evaluateArithmetic(expression);
    res.json({ result });
  } catch (error: any) {
    res.status(400).json({ error: 'Invalid expression' });
  }
});

// VULNERABILITY: Missing Authentication (CWE-862)
app.delete('/api/admin/users/:id', (req: Request, res: Response) => {
  const id: string = req.params.id as string;
  // Vulnerable: No authentication or authorization check!
  const index = users.findIndex((u: User) => u.id === parseInt(id));
  if (index !== -1) {
    users.splice(index, 1);
    res.json({ success: true, message: 'User deleted' });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// VULNERABILITY: Insecure Direct Object Reference (IDOR) (CWE-639)
app.get('/api/users/:id', (req: Request, res: Response) => {
  const id: string = req.params.id as string;
  // Vulnerable: No authorization check - any user can view any user's data
  const user = users.find((u: User) => u.id === parseInt(id));
  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// VULNERABILITY: XML External Entity (XXE) Injection (CWE-611)
app.post('/api/parse-xml', (req: Request, res: Response) => {
  const { xml } = req.body;
  // Vulnerable: XML parser without XXE protection
  xml2js.parseString(xml, { strict: false }, (err: Error | null, result: any) => {
    if (err) {
      res.status(400).json({ error: err.message });
    } else {
      res.json(result);
    }
  });
});

// VULNERABILITY: YAML Deserialization (CWE-502)
app.post('/api/parse-yaml', (req: Request, res: Response) => {
  const { yamlContent } = req.body;
  try {
    // Vulnerable: YAML parsing can execute arbitrary code
    const parsed = yaml.safeLoad(yamlContent);
    res.json(parsed);
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

// VULNERABILITY: Mass Assignment (CWE-915)
app.post('/api/register', (req: Request, res: Response) => {
  // Vulnerable: Directly assigning all properties from user input
  const newUser: User = {
    id: users.length + 1,
    ...req.body, // Attacker could set role: 'admin'
  };
  users.push(newUser);
  res.json({ success: true, user: newUser });
});

// VULNERABILITY: Sensitive Data Exposure (CWE-200)
app.get('/api/debug', (req: Request, res: Response) => {
  // Vulnerable: Exposes sensitive environment variables
  res.json({
    environment: process.env,
    secret: JWT_SECRET,
    adminPassword: ADMIN_PASSWORD,
    users: users,
    config: {
      dbPassword: DB_PASSWORD
    }
  });
});

// VULNERABILITY: Regex Denial of Service (ReDoS) (CWE-1333)
app.post('/api/validate-email', (req: Request, res: Response) => {
  const { email } = req.body;
  // Vulnerable: Complex regex that can cause ReDoS
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  const isValid: boolean = emailRegex.test(email);
  res.json({ valid: isValid });
});

// VULNERABILITY: Insecure Randomness (CWE-330)
app.get('/api/token', (req: Request, res: Response) => {
  // Vulnerable: Math.random() is not cryptographically secure
  const token: string = Math.random().toString(36).substring(7);
  res.json({ token });
});

// VULNERABILITY: Open Redirect (CWE-601)
app.get('/redirect', (req: Request, res: Response) => {
  const url: string = req.query.url as string;
  // Vulnerable: No validation of redirect URL
  res.redirect(url);
});

// VULNERABILITY: Prototype Pollution (CWE-1321)
app.post('/api/merge', (req: Request, res: Response) => {
  const { target, source } = req.body;
  // Vulnerable: Using lodash merge without proper sanitization
  const merged = _.merge(target, source);
  res.json({ result: merged });
});

// VULNERABILITY: Information Disclosure through Error Messages (CWE-209)
app.get('/api/error-test', (req: Request, res: Response) => {
  try {
    throw new Error('Database connection failed: mysql://admin:password@localhost:3306/mydb');
  } catch (error: any) {
    // Vulnerable: Exposes sensitive information in error message
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'running', vulnerabilities: 'many' });
});

// Root endpoint
app.get('/', (req: Request, res: Response) => {
  res.send(`
    <html>
      <head><title>Vulnerable TypeScript App</title></head>
      <body>
        <h1>Intentionally Vulnerable TypeScript Application</h1>
        <p>This application contains numerous security vulnerabilities for testing purposes.</p>
        <h2>Available Endpoints:</h2>
        <ul>
          <li>POST /api/login - SQL Injection</li>
          <li>GET /api/ping?host=example.com - Command Injection</li>
          <li>GET /api/files?filename=test.txt - Path Traversal</li>
          <li>GET /api/search?query=test - XSS</li>
          <li>GET /api/proxy?url=http://example.com - SSRF</li>
          <li>POST /api/calculate - RCE via eval</li>
          <li>DELETE /api/admin/users/1 - Missing Authentication</li>
          <li>GET /api/users/1 - IDOR</li>
          <li>POST /api/parse-xml - XXE Injection</li>
          <li>POST /api/parse-yaml - YAML Deserialization</li>
          <li>POST /api/register - Mass Assignment</li>
          <li>GET /api/debug - Sensitive Data Exposure</li>
          <li>POST /api/validate-email - ReDoS</li>
          <li>GET /api/token - Insecure Randomness</li>
          <li>GET /redirect?url= - Open Redirect</li>
          <li>POST /api/merge - Prototype Pollution</li>
        </ul>
      </body>
    </html>
  `);
});

// Error handler that exposes stack traces
app.use((err: Error, req: Request, res: Response, next: express.NextFunction) => {
  console.error(err.stack);
  // VULNERABILITY: Stack trace exposure (CWE-209)
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    details: err
  });
});

app.listen(PORT, () => {
  console.log(`Vulnerable TypeScript app listening on port ${PORT}`);
  console.log(`WARNING: This application is intentionally vulnerable!`);
  console.log(`DO NOT deploy to production!`);
});

export default app;
