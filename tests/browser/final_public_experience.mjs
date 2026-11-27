import fs from "node:fs/promises";
import path from "node:path";
import { chromium, devices } from "playwright";
import AxeBuilder from "@axe-core/playwright";

const outputDir = process.env.PLAYWRIGHT_OUTPUT_DIR || "playwright-artifacts";
const routes = [
  { name: "witness", url: "https://falsum-evidence-lab.vercel.app/witness/" },
  { name: "applications", url: "https://falsum-evidence-lab.vercel.app/applications/" },
];
const viewports = [
  { name: "desktop", options: { viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 } },
  { name: "mobile", options: { ...devices["iPhone 13"] } },
];

async function main() {
  await fs.mkdir(outputDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const report = { schema_version: 1, routes: [], axe_violations: [] };
  try {
    for (const route of routes) {
      for (const viewport of viewports) {
        const context = await browser.newContext(viewport.options);
        const page = await context.newPage();
        try {
          const response = await page.goto(route.url, { waitUntil: "networkidle", timeout: 60000 });
          if (!response || response.status() !== 200) {
            throw new Error(`${route.url} returned ${response?.status() ?? "no response"}`);
          }
          const title = await page.title();
          const h1Count = await page.locator("h1").count();
          const mainCount = await page.locator("main").count();
          const viewportMetaCount = await page.locator('meta[name="viewport"]').count();
          if (!title || h1Count !== 1 || mainCount !== 1 || viewportMetaCount !== 1) {
            throw new Error(`${route.name}/${viewport.name} failed structural judge checks`);
          }
          const axe = await new AxeBuilder({ page })
            .withTags(["wcag2a", "wcag2aa"])
            .analyze();
          report.routes.push({
            name: route.name,
            url: route.url,
            viewport: viewport.name,
            status: response.status(),
            title,
            h1_count: h1Count,
            main_count: mainCount,
            viewport_meta_count: viewportMetaCount,
            screenshot: `${route.name}-${viewport.name}.png`,
            axe_violation_count: axe.violations.length,
          });
          if (axe.violations.length) {
            report.axe_violations.push({ route: route.name, viewport: viewport.name, violations: axe.violations });
          }
          await page.screenshot({
            path: path.join(outputDir, `${route.name}-${viewport.name}.png`),
            fullPage: true,
          });
        } finally {
          await context.close();
        }
      }
    }
  } finally {
    await browser.close();
  }
  await fs.writeFile(path.join(outputDir, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  if (report.axe_violations.length) {
    console.error(JSON.stringify(report.axe_violations, null, 2));
    process.exitCode = 1;
  }
  console.log(JSON.stringify({
    status: report.axe_violations.length ? "FAILED" : "PASSED",
    route_viewports: report.routes.length,
    axe_violations: report.axe_violations.length,
    screenshots: report.routes.map((item) => item.screenshot),
  }));
}

await main();
