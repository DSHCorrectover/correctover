import { validateFetchUrl } from "file:///D:/Deepseek工作区/ccs-improved/pkg/dsh/ssrf.js";
const cases = [
  "http://0xdeadbeef.com/path",
  "http://0x7f000001/",
  "http://2130706433/",
  "http://169.254.169.254/latest/meta-data/",
];
for (const u of cases) {
  try {
    const r = await validateFetchUrl(u);
    console.log((r.allowed?"ALLOW":"BLOCK"), "|", u.slice(0,40), "|", (r.reason||"").slice(0,50));
  } catch (e) {
    console.log("CRASH!", u.slice(0,40), "|", e.message.slice(0,60));
  }
}
