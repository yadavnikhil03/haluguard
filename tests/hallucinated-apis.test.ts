import { describe, expect, it } from "vitest";
import { parseFileContent } from "../src/core/parse-diff.js";
import { hallucinatedApiDetector } from "../src/detectors/hallucinated-apis.js";

const run = (path: string, content: string) =>
  hallucinatedApiDetector.run({
    files: [parseFileContent(path, content)],
    options: { cwd: process.cwd() },
  }) as import("../src/types.js").DetectorResult;

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

  it("flags Go hallucinated methods", () => {
    const r = run("a.go", `import "fmt"\nfmt.Printlnn("hello")`);
    expect(r.findings.some((f) => f.title.includes("fmt.Printlnn"))).toBe(true);
  });

  it("does not flag valid Go stdlib methods", () => {
    const r = run("a.go", `import "fmt"\nfmt.Println("hello")`);
    expect(r.findings).toHaveLength(0);
  });

  it("supports Go aliased imports", () => {
    const r = run("a.go", `import s "strings"\ns.Concats("a", "b")`);
    expect(r.findings.some((f) => f.title.includes("s.Concats"))).toBe(true);
  });

  it("does not flag valid Go strings methods", () => {
    const r = run("a.go", `import "strings"\nstrings.Contains("hello", "ell")`);
    expect(r.findings).toHaveLength(0);
  });

  it("flags Java hallucinated methods", () => {
    const r = run("a.java", "import java.util.List;\nList.sortList()");
    expect(r.findings.some((f) => f.title.includes("List.sortList"))).toBe(true);
  });

  it("does not flag valid Java methods", () => {
    const r = run("a.java", "import java.util.List;\nList.sort()");
    expect(r.findings).toHaveLength(0);
  });

  it("flags Rust hallucinated methods", () => {
    const r = run("a.rs", "use std::fs;\nfs::read_file_sync()");
    expect(r.findings.some((f) => f.title.includes("fs::read_file_sync"))).toBe(true);
  });

  it("does not flag valid Rust methods", () => {
    const r = run("a.rs", "use std::fs;\nfs::read_to_string()");
    expect(r.findings).toHaveLength(0);
  });

  it("flags C# hallucinated methods", () => {
    const r = run("a.cs", "using System.IO;\nFile.ReadAllTextSync()");
    expect(r.findings.some((f) => f.title.includes("File.ReadAllTextSync"))).toBe(true);
  });

  it("does not flag valid C# methods", () => {
    const r = run("a.cs", "using System.IO;\nFile.ReadAllText()");
    expect(r.findings).toHaveLength(0);
  });

  it("flags PHP hallucinated methods", () => {
    const r = run("a.php", "use PDO;\nPDO::connect()");
    expect(r.findings.some((f) => f.title.includes("PDO::connect"))).toBe(true);
  });

  it("does not flag valid PHP methods", () => {
    const r = run("a.php", "use PDO;\nPDO::prepare()");
    expect(r.findings).toHaveLength(0);
  });

  it("ignores languages fully outside its scope", () => {
    const r = run("a.rb", "puts 'hello'");
    expect(r.findings).toHaveLength(0);
  });
});
