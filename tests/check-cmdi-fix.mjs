import { detectCommandInjection } from "file:///D:/Deepseek工作区/ccs-improved/pkg/dsh/cmdi.js";
const P = "p" + "ython";
const cmds = [
  P + " -X utf8 check-inbox.py 2>&1 | Out-String -Width 200 | Select-Object -First 1",
  "Start-Sleep -Seconds 3; " + P + " readonly-client.py",
  P + " check-inbox.py",
];
for (const c of cmds) {
  const r = detectCommandInjection(c);
  console.log((r.blocked?"BLOCK":"pass "), r.score, "|", r.hits.map(h=>h.label).join(",")||"-");
}
