import { describe, expect, it } from "vitest";
import { runScan } from "../src/core/engine.js";
import { parseFileContent } from "../src/core/parse-diff.js";

const sample = `
import * as crypto from "node:crypto";
const KEY = "AKIAIOSFODNN7EXAMPLE";
export function f() {
  // TODO: real impl
  throw new Error("not implemented");
  const id = crypto.randomUUIDv4();
}
`;

describe("engine", () => {
  it("runs all detectors and aggregates findings", async () => {
    const report = await runScan([parseFileContent("a.ts", sample)]);
    const detectors = new Set(report.findings.map((f) => f.detector));
    expect(detectors.has("secrets")).toBe(true);
    expect(detectors.has("hallucinated_apis")).toBe(true);
    expect(detectors.has("stubs")).toBe(true);
    expect(report.stats.filesScanned).toBe(1);
    expect(report.stats.linesScanned).toBe(sample.split("\n").length);
  });

  it("respects --detectors filter", async () => {
    const report = await runScan([parseFileContent("a.ts", sample)], {
      detectors: ["secrets"],
    });
    const detectors = new Set(report.findings.map((f) => f.detector));
    expect(detectors).toEqual(new Set(["secrets"]));
  });

  it("respects minSeverity", async () => {
    const full = await runScan([parseFileContent("a.ts", sample)]);
    const highOnly = await runScan([parseFileContent("a.ts", sample)], {
      minSeverity: "high",
    });
    expect(highOnly.findings.length).toBeLessThan(full.findings.length);
    for (const f of highOnly.findings) {
      expect(["high", "critical"]).toContain(f.severity);
    }
  });

  it("sorts findings by severity then location", async () => {
    const report = await runScan([parseFileContent("a.ts", sample)]);
    const sevs = report.findings.map((f) => f.severity);

    const ranks = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    for (let i = 1; i < sevs.length; i++) {
      expect(ranks[sevs[i - 1]]).toBeGreaterThanOrEqual(ranks[sevs[i]]);
    }
  });

  it("respects ignore globs", async () => {
    const report = await runScan([parseFileContent("src/a.ts", sample)], {
      ignore: ["src/**"],
    });
    expect(report.findings).toHaveLength(0);
  });
});
