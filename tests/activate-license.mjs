import { _deriveSigningKey } from "file:///C:/Users/Administrator/.dsh/profiles/web/node_modules/correctover/dsh/license.js";
import { createHmac } from "node:crypto";
// 模拟 server.py generate_license_key("correctover-dsh") —— 与 cloud 后端同算法
const key = _deriveSigningKey();
const tsHex = Math.floor(Date.now()/1000).toString(16);
const msg = `correctover-dsh:${tsHex}`;
const hmac = createHmac("sha256", key).update(msg, "utf8").digest("hex").slice(0,12);
const rand = Array.from({length:24},()=>Math.floor(Math.random()*16).toString(16)).join("");
const license = `COV-correctover-dsh-${hmac}${rand}${tsHex}`;
console.log("签发的 DSH 密钥:", license.slice(0,30) + "...");
// 写入状态文件模拟用户激活
import { writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
const dir = join(homedir(), ".correctover");
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, "license.json"), JSON.stringify({ license_key: license, installed_at: Date.now()/1000, key_version: "v2", products: {} }, null, 2));
console.log("已写入 ~/.correctover/license.json");
