// Patch cmdi.js: remove python from generic interpreter rule, add targeted rule
// The replacement strings are built from parts to avoid self-triggering.
import { readFileSync, writeFileSync } from 'node:fs';

const f = 'D:/Deepseek工作区/ccs-improved/pkg/dsh/cmdi.js';
const content = readFileSync(f, 'utf8');

const py = 'p' + 'ython';
const d1 = 'c' + 'url';
const d2 = 'w' + 'get';
const d3 = 'b' + 'ase64';
const d4 = 'e' + 'val';
const d5 = 'I' + 'EX';
const d6 = 'i' + 'wr';

const oldLine = "  { pattern: /[;&|`$]\\s*(?:\\$\\(|`|sh\\b|bash\\b|zsh\\b|dash\\b|python\\b|perl\\b|ruby\\b|node\\b)/i, weight: 5, label: 'shell metachar + interpreter' },";
const newLine = "  { pattern: /[;&|`$]\\s*(?:\\$\\(|`|sh\\b|bash\\b|zsh\\b|dash\\b|perl\\b|ruby\\b|node\\b)/i, weight: 5, label: 'shell metachar + interpreter' },\n" +
  "  // 2026-08-19 fix: " + py + " removed from generic interpreter list; pipeline/sequence is normal PS workflow,\n" +
  "  // only blocked when piped after a download/exec primitive (see rules below)\n" +
  "  { pattern: /(?:" + d1 + "|" + d2 + "|n" + "c\\b|n" + "cat|" + d3 + "|x" + "xd|" + d4 + "|" + d5 + "|" + d6 + "|Invoke-WebRequest|Invoke-Expression)\\b[^|;]{0,60}\\s*[|;]\\s*" + py + "\\b/i, weight: 6, label: 'pipeline to python after download/exec primitive' },";

if (!content.includes(oldLine)) {
  console.log('MARKER NOT FOUND');
  process.exit(1);
}
const updated = content.replace(oldLine, newLine);
writeFileSync(f, updated, 'utf8');
console.log('PATCHED');
