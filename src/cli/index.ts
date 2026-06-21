#!/usr/bin/env node

import { readFileSync, statSync } from "node:fs";
import { extname } from "node:path";
import process from "node:process";

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

  const files = collectFiles(args);
  if (files.length === 0) {
    process.stdout.write(renderReport(emptyReport()));
    return;
  }

  const report = await runScan(files, {
    cwd: process.cwd(),
    detectors: args.detectors,
    minSeverity: args.minSeverity,
    ignore: args.ignore,
  });

  emit(report, args);
  process.exitCode = decideExitCode(report, args.failOn);
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
