import { describe, expect, it } from "vitest";
import { maliciousPackageDetector } from "../src/detectors/malicious-packages.js";

function makeFile(path: string, lines: string[]) {
  return {
    path,
    language: "typescript" as const,
    addedLines: lines.map((text, i) => ({ lineNumber: i + 1, text })),
  };
}

describe("malicious_packages", () => {
  it("flags typosquatted require", () => {
    const result = maliciousPackageDetector.run({
      files: [makeFile("test.ts", ['const x = require("loadash");'])],
      options: { cwd: "" },
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("malicious:typosquat_npm");
  });

  it("flags typosquatted import", () => {
    const result = maliciousPackageDetector.run({
      files: [makeFile("test.ts", ['import x from "loadash";'])],
      options: { cwd: "" },
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("malicious:typosquat_import");
  });

  it("passes on legitimate packages", () => {
    const result = maliciousPackageDetector.run({
      files: [makeFile("test.ts", ['const _ = require("lodash");'])],
      options: { cwd: "" },
    });
    expect(result.findings).toHaveLength(0);
  });

  it("flags known typosquats in python imports", () => {
    const result = maliciousPackageDetector.run({
      files: [makeFile("test.py", ["import mongose"])],
      options: { cwd: "" },
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("malicious:typosquat_python");
  });
});
