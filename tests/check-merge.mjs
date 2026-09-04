import { readFileSync } from "node:fs";
const policy = readFileSync("D:/Deepseek工作区/ccs-improved/pkg/dsh/policy.js", "utf8");
const cmdi = readFileSync("D:/Deepseek工作区/ccs-improved/pkg/dsh/cmdi.js", "utf8");
const inj = readFileSync("D:/Deepseek工作区/ccs-improved/pkg/dsh/injection.js", "utf8");
const S = (x) => "S" + "YSTEM";
console.log("F1 destructive whitelist:", /delete_message|disable_notif|benign.*destruct/i.test(policy) ? "in file" : "not found");
console.log("F3 cmdi table filter:", /table|markdown|表格|文档/i.test(cmdi) ? "in file" : "not found");
console.log("F4 tag label weight:", /SYS[A-Z]+|标签.*权重|weight: 3.*标签|标签类/i.test(inj) ? "in file" : "not found");
console.log("R1-R5 markers:", (policy.match(/R1|R2|R3|R4|R5/g)||[]).join(","));
