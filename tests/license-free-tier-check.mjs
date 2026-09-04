import { checkLicense } from '../dsh/license.js';
const s = checkLicense();
if (s.tier !== 'free' || s.can_fix || s.can_report) { console.error('FAIL:', JSON.stringify(s)); process.exit(1); }
console.log('free-tier PASS:', s.tier, '| can_fix:', s.can_fix, '| can_report:', s.can_report, '| fix_preview:', s.fix_preview);
