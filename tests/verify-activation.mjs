import { checkLicense, getFixCta, isPro } from "file:///C:/Users/Administrator/.dsh/profiles/web/node_modules/correctover/dsh/license.js";
const s = checkLicense();
console.log("=== DSH 插件激活验证 ===");
console.log("tier:", s.tier, "| can_fix:", s.can_fix, "| can_report:", s.can_report, "| isPro:", isPro());
if (s.tier === "pro") {
  console.log("✅ Pro 激活成功 —— 用户付费后密钥真实可用");
  const cta = getFixCta(10, 12);
  console.log("Pro 无 CTA:", cta === "" ? "✅ 正确(空)" : "❌ 应空");
} else {
  console.log("❌ 激活失败, fix_preview:", s.fix_preview);
}
