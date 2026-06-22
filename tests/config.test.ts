import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, mergeConfigWithOptions } from "../src/core/config.js";

const TMP = resolve(process.cwd(), "tests", ".tmp-config-test");

function setup(filename: string, content: string): string {
  mkdirSync(TMP, { recursive: true });
  const p = resolve(TMP, filename);
  writeFileSync(p, content, "utf-8");
  return TMP;
}

function cleanup(): void {
  try {
    rmSync(TMP, { recursive: true, force: true });
  } catch {}
}

describe("config loading", () => {
  it("returns empty config when no file exists", () => {
    const config = loadConfig("/nonexistent-dir-xyz");
    expect(config).toEqual({});
  });

  it("loads .haluguard.yml with all fields", () => {
    const dir = setup(
      ".haluguard.yml",
      `
detectors:
  - secrets
  - stubs
min_severity: medium
ignore:
  - "vendor/**"
fail_on: high
rules:
  secrets:
    enabled: true
  stubs:
    severity: low
`,
    );
    const config = loadConfig(dir);
    expect(config.detectors).toEqual(["secrets", "stubs"]);
    expect(config.min_severity).toBe("medium");
    expect(config.ignore).toEqual(["vendor/**"]);
    expect(config.fail_on).toBe("high");
    expect(config.rules?.secrets?.enabled).toBe(true);
    expect(config.rules?.stubs?.severity).toBe("low");
    cleanup();
  });

  it("loads from explicit path", () => {
    const dir = setup(
      "custom-config.yml",
      `
min_severity: high
`,
    );
    const config = loadConfig(dir, "custom-config.yml");
    expect(config.min_severity).toBe("high");
    cleanup();
  });

  it("ignores invalid severity values", () => {
    const dir = setup(
      ".haluguard.yml",
      `
min_severity: banana
`,
    );
    const config = loadConfig(dir);
    expect(config.min_severity).toBeUndefined();
    cleanup();
  });
});

describe("config merging", () => {
  it("CLI options take precedence over config", () => {
    const config = {
      detectors: ["secrets"],
      min_severity: "medium" as const,
      ignore: ["vendor/**"],
      fail_on: "high" as const,
    };
    const { scanOptions, failOn } = mergeConfigWithOptions(
      config,
      { detectors: ["stubs"] },
      "critical",
    );
    expect(scanOptions.detectors).toEqual(["stubs"]);
    expect(failOn).toBe("critical");
  });

  it("config fills in missing CLI options", () => {
    const config = {
      detectors: ["secrets"],
      min_severity: "medium" as const,
      ignore: ["vendor/**"],
      fail_on: "critical" as const,
    };
    const { scanOptions, failOn } = mergeConfigWithOptions(config, {});
    expect(scanOptions.detectors).toEqual(["secrets"]);
    expect(scanOptions.minSeverity).toBe("medium");
    expect(scanOptions.ignore).toEqual(["vendor/**"]);
    expect(failOn).toBe("critical");
  });
});
