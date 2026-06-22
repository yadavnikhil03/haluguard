import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { ScanOptions, SeverityLevel } from "../types.js";

export interface HaluGuardConfig {
  detectors?: string[];
  min_severity?: SeverityLevel;
  ignore?: string[];
  fail_on?: "never" | SeverityLevel;
  rules?: Record<string, { enabled?: boolean; severity?: SeverityLevel }>;
}

const CONFIG_FILENAMES = [".haluguard.yml", ".haluguard.yaml"];

export function loadConfig(cwd: string, explicitPath?: string): HaluGuardConfig {
  const path = explicitPath ? resolve(cwd, explicitPath) : findConfig(cwd);
  if (!path) return {};

  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = parseYaml(raw) as Record<string, unknown> | null;
    if (!parsed || typeof parsed !== "object") return {};
    return normalizeConfig(parsed);
  } catch {
    return {};
  }
}

function findConfig(cwd: string): string | undefined {
  for (const name of CONFIG_FILENAMES) {
    const p = resolve(cwd, name);
    if (existsSync(p)) return p;
  }
  return undefined;
}

function normalizeConfig(raw: Record<string, unknown>): HaluGuardConfig {
  const config: HaluGuardConfig = {};

  if (Array.isArray(raw.detectors)) {
    config.detectors = raw.detectors.filter((d): d is string => typeof d === "string");
  }

  if (typeof raw.min_severity === "string" && isValidSeverity(raw.min_severity)) {
    config.min_severity = raw.min_severity;
  }

  if (Array.isArray(raw.ignore)) {
    config.ignore = raw.ignore.filter((g): g is string => typeof g === "string");
  }

  if (typeof raw.fail_on === "string") {
    if (raw.fail_on === "never" || isValidSeverity(raw.fail_on)) {
      config.fail_on = raw.fail_on as HaluGuardConfig["fail_on"];
    }
  }

  if (raw.rules && typeof raw.rules === "object") {
    config.rules = {};
    for (const [key, val] of Object.entries(raw.rules as Record<string, unknown>)) {
      if (val && typeof val === "object") {
        const rule = val as Record<string, unknown>;
        config.rules[key] = {};
        if (typeof rule.enabled === "boolean") config.rules[key].enabled = rule.enabled;
        if (typeof rule.severity === "string" && isValidSeverity(rule.severity)) {
          config.rules[key].severity = rule.severity;
        }
      }
    }
  }

  return config;
}

const VALID_SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);

function isValidSeverity(v: string): v is SeverityLevel {
  return VALID_SEVERITIES.has(v);
}

export function mergeConfigWithOptions(
  config: HaluGuardConfig,
  cliOptions: Partial<ScanOptions>,
  cliFailOn?: string,
): { scanOptions: Partial<ScanOptions>; failOn?: string } {
  const scanOptions: Partial<ScanOptions> = { ...cliOptions };

  if (!scanOptions.detectors && config.detectors) {
    scanOptions.detectors = config.detectors;
  }
  if (!scanOptions.minSeverity && config.min_severity) {
    scanOptions.minSeverity = config.min_severity;
  }
  if ((!scanOptions.ignore || scanOptions.ignore.length === 0) && config.ignore) {
    scanOptions.ignore = config.ignore;
  }

  const failOn = cliFailOn ?? config.fail_on;
  return { scanOptions, failOn };
}
