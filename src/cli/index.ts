#!/usr/bin/env node

import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import process from "node:process";

import { loadConfig, mergeConfigWithOptions } from "../core/config.js";
import { registerBuiltinDetectors, runScan } from "../core/engine.js";
import { parseDiff, parseFileContent } from "../core/parse-diff.js";
import { renderReport } from "../reporters/cli-reporter.js";
import { renderSarif } from "../reporters/sarif-reporter.js";
import type { FileChange, ScanReport } from "../types.js";
import { HELP, type ParsedArgs, parseArgs, readStdin } from "./args.js";

const VERSION = "0.1.0";

registerBuiltinDetectors();

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(HELP);
    return;
  }
  if (args.version) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (args.initHook) {
    installPreCommitHook();
    return;
  }

  const config = loadConfig(process.cwd(), args.config);
  const { scanOptions, failOn } = mergeConfigWithOptions(
    config,
    {
      cwd: process.cwd(),
      detectors: args.detectors,
      minSeverity: args.minSeverity !== "info" ? args.minSeverity : undefined,
      ignore: args.ignore.length > 0 ? args.ignore : undefined,
    },
    args.failOn !== "high" ? args.failOn : undefined,
  );

  const resolvedFailOn = (failOn ?? args.failOn) as ParsedArgs["failOn"];

  const files = collectFiles(args);
  if (files.length === 0) {
    process.stdout.write(renderReport(emptyReport()));
    return;
  }

  const report = await runScan(files, {
    cwd: process.cwd(),
    ...scanOptions,
  });

  emit(report, args);
  process.exitCode = decideExitCode(report, resolvedFailOn);
}

function installPreCommitHook(): void {
  const gitDir = resolve(process.cwd(), ".git");
  if (!existsSync(gitDir)) {
    process.stderr.write("haluguard: not a git repository (no .git directory found)\n");
    process.exitCode = 1;
    return;
  }

  const hooksDir = resolve(gitDir, "hooks");
  if (!existsSync(hooksDir)) mkdirSync(hooksDir, { recursive: true });

  const hookPath = resolve(hooksDir, "pre-commit");
  if (existsSync(hookPath)) {
    process.stderr.write(`haluguard: pre-commit hook already exists at ${hookPath}\n`);
    process.stderr.write("haluguard: remove it manually first if you want to replace it\n");
    process.exitCode = 1;
    return;
  }

  const hookScript = [
    "#!/bin/sh",
    "# HaluGuard pre-commit hook — scans staged changes for AI hallucinations",
    "DIFF=$(git diff --cached --unified=0)",
    'if [ -z "$DIFF" ]; then exit 0; fi',
    'echo "$DIFF" | npx haluguard --stdin --fail-on high',
  ].join("\n");

  writeFileSync(hookPath, `${hookScript}\n`, "utf-8");
  try {
    chmodSync(hookPath, 0o755);
  } catch {
    // chmod may fail on Windows, hook still works via git
  }
  process.stdout.write(`\u2705  Pre-commit hook installed at ${hookPath}\n`);
}

function collectFiles(args: ParsedArgs): FileChange[] {
  if (args.stdin) {
    const diff = readStdin();
    return parseDiff(diff);
  }

  const changes: FileChange[] = [];
  for (const input of args.inputs) {
    let isFile = false;
    try {
      isFile = statSync(input).isFile();
    } catch {
      process.stderr.write(`haluguard: skipping "${input}" (not found)\n`);
      continue;
    }
    if (!isFile) continue;

    const ext = extname(input).toLowerCase();
    if (ext === ".diff" || ext === ".patch") {
      changes.push(...parseDiff(readFileSync(input, "utf-8")));
    } else {
      changes.push(parseFileContent(input, readFileSync(input, "utf-8")));
    }
  }
  return changes;
}

function emit(report: ScanReport, args: ParsedArgs): void {
  switch (args.format) {
    case "json":
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      break;
    case "sarif":
      process.stdout.write(`${renderSarif(report)}\n`);
      break;
    default:
      process.stdout.write(`${renderReport(report)}\n`);
      break;
  }
}

const SEVERITY_RANK: Record<string, number> = {
  info: 10,
  low: 20,
  medium: 30,
  high: 40,
  critical: 50,
};

function decideExitCode(
  report: Awaited<ReturnType<typeof runScan>>,
  failOn: ParsedArgs["failOn"],
): number {
  if (failOn === "never") return 0;
  const threshold = SEVERITY_RANK[failOn] ?? 0;
  const hit = report.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
  return hit ? 1 : 0;
}

function emptyReport() {
  return {
    findings: [],
    stats: {
      filesScanned: 0,
      linesScanned: 0,
      detectorStats: [],
      totalMs: 0,
    },
  };
}

main().catch((err) => {
  process.stderr.write(
    `haluguard: fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`,
  );
  process.exitCode = 2;
});
