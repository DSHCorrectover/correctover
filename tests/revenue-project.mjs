// 基于真实 npm 数据的付费潜力推算
const mcpServer = 4711;   // correctover-mcp-server 月下载
const scan = 1114;        // correctover-scan
const main = 770;         // correctover 主包
const gate = 110;         // mcp-gateway

// 行业基准（待调研军团确认）：npm 包下载→活跃用户约 5-15%，免费→付费转化 1-5%
console.log("=== Correctover 付费潜力推算（基于真实下载量）===");
console.log(`月下载: mcp-server=${mcpServer} scan=${scan} main=${main} gateway=${gate}`);
console.log("");
for (const [name, dl] of [["MCP server", mcpServer], ["scan", scan], ["主包", main], ["gateway", gate]]) {
  const activeLow = Math.round(dl * 0.05), activeHigh = Math.round(dl * 0.15);
  const payLow = Math.round(activeLow * 0.01), payHigh = Math.round(activeHigh * 0.05);
  console.log(`${name} (${dl}/月): 活跃 ${activeLow}-${activeHigh} | 付费 ${payLow}-${payHigh} 用户`);
}
console.log("");
console.log("=== 不同定价的收入预估 ===");
for (const [tier, price] of [["Pro $9/月", 9], ["Pro $29/月", 29], ["Pro $49/月", 49]]) {
  const users = Math.round(mcpServer * 0.10 * 0.03); // 10% 活跃 * 3% 转化
  console.log(`${tier}: ${users} 付费用户 → 月收入 $${users * price}`);
}
