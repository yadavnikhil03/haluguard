import { describe, expect, it } from "vitest";
import { runScan } from "../src/core/engine.js";
import { parseFileContent } from "../src/core/parse-diff.js";

describe("haluguard: ignore directives", () => {
  it("ignores a finding when same line has // haluguard: ignore", async () => {
    const code = `const KEY = "AKIAIOSFODNN7EXAMPLE"; // haluguard: ignore`;
    const report = await runScan([parseFileContent("a.ts", code)]);
    expect(report.findings).toHaveLength(0);
  });

  it("ignores a finding when previous line has // haluguard: ignore", async () => {
    const code = `// haluguard: ignore\nconst KEY = "AKIAIOSFODNN7EXAMPLE";`;
    const report = await runScan([parseFileContent("a.ts", code)]);
    expect(report.findings).toHaveLength(0);
  });

  it("ignores only the specified rule ID", async () => {
    const code = `// haluguard: ignore secret:aws_access_key_id\nconst KEY = "AKIAIOSFODNN7EXAMPLE";\nconst id = crypto.randomUUIDv4();`;
    const report = await runScan([parseFileContent("a.ts", code)]);
    const secretFindings = report.findings.filter((f) => f.detector === "secrets");
    const apiFindings = report.findings.filter((f) => f.detector === "hallucinated_apis");
    expect(secretFindings).toHaveLength(0);
    expect(apiFindings.length).toBeGreaterThan(0);
  });

  it("ignores by detector name", async () => {
    const code = `// haluguard: ignore secrets\nconst KEY = "AKIAIOSFODNN7EXAMPLE";`;
    const report = await runScan([parseFileContent("a.ts", code)]);
    expect(report.findings).toHaveLength(0);
  });

  it("does NOT ignore when directive is on a different line", async () => {
    const code = `// haluguard: ignore\nconst x = 1;\nconst KEY = "AKIAIOSFODNN7EXAMPLE";`;
    const report = await runScan([parseFileContent("a.ts", code)]);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it("supports Python # haluguard: ignore", async () => {
    const code = "import os\nhostname = os.hostnameSync()  # haluguard: ignore";
    const report = await runScan([parseFileContent("a.py", code)]);
    const apiFindings = report.findings.filter((f) => f.detector === "hallucinated_apis");
    expect(apiFindings).toHaveLength(0);
  });
});
