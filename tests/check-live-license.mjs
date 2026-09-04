import { checkLicense } from "file:///C:/Users/Administrator/.dsh/profiles/web/node_modules/correctover/dsh/license.js";
const s = checkLicense();
console.log("当前实例 tier:", s.tier, "| can_fix:", s.can_fix, "| 有密钥:", s.license_key ? "yes" : "no");
console.log("环境变量 CORRECTOVER_LICENSE_KEY:", process.env.CORRECTOVER_LICENSE_KEY ? "set" : "unset");
