import { checkLicense } from "file:///C:/Users/Administrator/.dsh/profiles/web/node_modules/correctover/dsh/license.js";
const s = checkLicense();
console.log("清理后 tier:", s.tier, "(应 free)");
