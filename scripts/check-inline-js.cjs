const { readFileSync } = require('node:fs');
const { Script } = require('node:vm');
const { join, basename } = require('node:path');

const htmlPath = join(__dirname, '..', 'app', 'Wag & Wash booking app.html');
const html = readFileSync(htmlPath, 'utf8');
const scriptTags = html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi);
let checked = 0;

for (const [, attributes, source] of scriptTags) {
  if (/\bsrc\s*=/i.test(attributes) || !source.trim()) {
    continue;
  }

  checked += 1;
  new Script(source, { filename: `${basename(htmlPath)} inline script ${checked}` });
}

if (checked === 0) {
  throw new Error(`No inline JavaScript found in ${htmlPath}`);
}

console.log(`JavaScript syntax valid (${checked} inline script${checked === 1 ? '' : 's'}).`);
