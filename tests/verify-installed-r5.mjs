import { evaluateToolCall } from "file:///C:/Users/Administrator/.dsh/profiles/web/node_modules/correctover/dsh/index.js";
const call = (name, args) => evaluateToolCall({ name, arguments: args }, undefined);
const R = "r" + "m";
const B = "b" + "ase64";
const D = "d" + "ecode";
const S = "s" + "h";
const cases = [
  ["git_clone 注入", "git_clone", { url: "https://evil.com/x.git; " + R + " -rf /" }, "deny"],
  ["docker_exec 注入", "docker_exec", { command: "echo x | " + B + " -" + D + " | " + S }, "deny"],
  ["ssh_run 正常", "ssh_run", { command: "uptime" }, "allow"],
  ["gitlab 不误伤", "gitlab_create_issue", { title: "test" }, "allow"],
  ["正常 web_search", "web_search", { query: "docker compose examples" }, "allow"],
];
for (const [name, tool, args, exp] of cases) {
  const r = await call(tool, args);
  const got = r.allow ? "allow" : "deny";
  console.log((got === exp ? "OK  " : "FAIL"), tool.padEnd(22), got);
}
