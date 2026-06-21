import { describe, expect, it } from "vitest";
import { parseFileContent } from "../src/core/parse-diff.js";
import { hallucinatedApiDetector } from "../src/detectors/hallucinated-apis.js";

const run = (path: string, content: string) =>
  hallucinatedApiDetector.run({
    files: [parseFileContent(path, content)],
    options: { cwd: process.cwd() },
  });

describe("hallucinated-apis detector", () => {
  it("flags an invented crypto method and suggests the real one", () => {
    const r = run(
      "a.ts",
      `import * as crypto from "node:crypto";\nconst id = crypto.randomUUIDv4();`,
    );
    const f = r.findings.find((x) => x.title.includes("randomUUIDv4"));
    expect(f).toBeDefined();
    expect(f?.message).toContain("crypto.randomUUID");
  });

  it("flags os.hostnameSync but not os.hostname()", () => {
    const good = run("a.ts", `import * as os from "node:os";\nos.hostname();`);
    expect(good.findings).toHaveLength(0);

    const bad = run("a.ts", `import * as os from "node:os";\nos.hostnameSync();`);
    expect(bad.findings.some((f) => f.title.includes("hostnameSync"))).toBe(true);
  });

  it("flags JSON.deserialize but not JSON.parse", () => {
    const good = run("a.ts", `const o = JSON.parse("{}");`);
    expect(good.findings).toHaveLength(0);

    const bad = run("a.ts", `const o = JSON.deserialize("{}");`);
    expect(bad.findings.some((f) => f.title.includes("deserialize"))).toBe(true);
  });

  it("respects ESM default imports", () => {
    const r = run("a.ts", `import crypto from "node:crypto";\ncrypto.randomUUIDv4();`);
    expect(r.findings.some((f) => f.title.includes("randomUUIDv4"))).toBe(true);
  });

  it("respects CommonJS require", () => {
    const r = run("a.ts", `const os = require("node:os");\nos.hostnameSync();`);
    expect(r.findings.some((f) => f.title.includes("hostnameSync"))).toBe(true);
  });

  it("respects named imports", () => {
    const r = run("a.ts", `import { randomUUID } from "node:crypto";\nrandomUUID();`);
    expect(r.findings).toHaveLength(0);
  });

  it("does not flag globals like Math/JSON that are used correctly", () => {
    const r = run("a.ts", "const x = Math.max(1, 2);\nconst y = JSON.stringify({});");
    expect(r.findings).toHaveLength(0);
  });

  it("flags Math methods that don't exist", () => {
    const r = run("a.ts", "const x = Math.maxim(1, 2);");
    expect(r.findings.some((f) => f.title.includes("Math.maxim"))).toBe(true);
  });

  it("does not flag unknown third-party packages (avoids false positives)", () => {
    const r = run("a.ts", `import lodash from "lodash";\nlodash.deepMerge({}, {});`);

    expect(r.findings).toHaveLength(0);
  });

  it("flags Python hallucinated methods", () => {
    const r = run("a.py", `import json\njson.parse("{}")`);

    expect(r.findings.some((f) => f.title.includes("json.parse"))).toBe(true);
  });

  it("does not flag Python methods that exist", () => {
    const r = run("a.py", `import json\njson.loads("{}")`);
    expect(r.findings).toHaveLength(0);
  });

  it("supports Python from-imports", () => {
    const r = run("a.py", `from os import path\npath.joins("a", "b")`);
    expect(r.findings.some((f) => f.title.includes("path.joins"))).toBe(true);
  });

  it("ignores languages outside its scope", () => {
    const r = run("a.go", "package main\nfunc main() { os.HostnameSync() }");
    expect(r.findings).toHaveLength(0);
  });
});
