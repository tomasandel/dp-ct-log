// Generates a merged CT log list (Google's public logs + attack simulation logs).
// Output: ct-log/log-list.json — served as a static file by Caddy.
// Usage: node ct-log/generate-log-list.mjs [--base-url https://ct.jvgc-a.com]

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..');
const CA_DIR = path.join(ROOT, 'ca');
const BASE_URL = process.argv.find(a => a.startsWith('--base-url='))?.split('=')[1]
  || process.argv[process.argv.indexOf('--base-url') + 1]
  || 'https://ct.jvgc-a.com';

function loadLogInfo(name) {
  const pubPem = fs.readFileSync(path.join(CA_DIR, `${name}.pub`), 'utf8');
  const pubDer = crypto.createPublicKey(pubPem).export({ type: 'spki', format: 'der' });
  return {
    logId: crypto.createHash('sha256').update(pubDer).digest().toString('base64'),
    key: pubDer.toString('base64'),
  };
}

const logA = loadLogInfo('log-a');
const logB = loadLogInfo('log-b');

// Fetch Google's official log list
const GOOGLE_LOG_LIST = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';
let googleList = { operators: [] };

try {
  const resp = await fetch(GOOGLE_LOG_LIST);
  if (resp.ok && resp.headers.get('content-type')?.includes('json')) {
    googleList = await resp.json();
    console.log(`Fetched Google log list: ${googleList.operators.length} operators`);
  } else {
    console.log(`Google log list returned ${resp.status}, using empty list`);
  }
} catch (e) {
  console.log(`Could not fetch Google log list: ${e.message}`);
}

// Append attack simulation logs (separate operators for Firefox CT policy)
const merged = {
  ...googleList,
  operators: [
    ...googleList.operators,
    {
      name: 'Attack Operator A',
      logs: [{
        log_id: logA.logId,
        key: logA.key,
        url: `${BASE_URL}/log-a/`,
        mmd: 86400,
        description: 'Attack Log A',
        state: { usable: { timestamp: new Date().toISOString() } },
      }],
    },
    {
      name: 'Attack Operator B',
      logs: [{
        log_id: logB.logId,
        key: logB.key,
        url: `${BASE_URL}/log-b/`,
        mmd: 86400,
        description: 'Attack Log B',
        state: { usable: { timestamp: new Date().toISOString() } },
      }],
    },
  ],
};

const outPath = path.join(import.meta.dirname, 'log-list.json');
fs.writeFileSync(outPath, JSON.stringify(merged, null, 2));
console.log(`\nWrote ${outPath}`);
console.log(`  Log A: id=${logA.logId.slice(0, 20)}... url=${BASE_URL}/log-a/`);
console.log(`  Log B: id=${logB.logId.slice(0, 20)}... url=${BASE_URL}/log-b/`);
console.log(`  Total operators: ${merged.operators.length}`);
