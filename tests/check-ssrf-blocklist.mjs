import { isBlockedIPv4 } from "file:///D:/Deepseek工作区/ccs-improved/pkg/dsh/ssrf.js";
const cases = [
  ["195.19.200.1", false, "公网 RIPE 段（修复前误拦）"],
  ["203.0.113.5", true, "TEST-NET-3 文档段（修复前漏拦）"],
  ["198.51.100.1", true, "TEST-NET-2"],
  ["192.0.2.1", true, "TEST-NET-1"],
  ["198.18.0.1", true, "benchmarking"],
  ["0.1.2.3", true, "0.0.0.0/8 子网（修复前漏拦）"],
  ["127.0.0.1", true, "loopback"],
  ["169.254.169.254", true, "cloud metadata"],
  ["10.0.0.5", true, "private 10"],
  ["8.8.8.8", false, "公网 DNS（应放行）"],
];
let bad = 0;
for (const [ip, expectBlock, note] of cases) {
  const r = isBlockedIPv4(ip);
  const ok = (r !== null) === expectBlock;
  if (!ok) bad++;
  console.log((ok ? "OK  " : "FAIL"), ip.padEnd(16), (r!==null?"BLOCK":"allow"), "|", note);
}
console.log(bad === 0 ? "ALL 10 PASS" : ("FAILURES: " + bad));
