import type { DiffLine, FileChange } from "../types.js";
import { detectLanguage } from "./language.js";

interface HunkMeta {
  newPath: string | null;
  hunks: DiffLine[];
}

export function parseDiff(diff: string): FileChange[] {
  const lines = diff.split(/\r?\n/);
  const files: FileChange[] = [];
  let current: HunkMeta | null = null;
  let inHunk = false;

  let newLine = 0;

  const flush = () => {
    if (current?.newPath) {
      const rawLines = new Map<number, string>();
      for (const line of current.hunks) {
        rawLines.set(line.lineNumber, line.text);
      }
      files.push({
        path: current.newPath,
        language: detectLanguage(current.newPath),
        addedLines: current.hunks,
        rawLines,
      });
    }
    current = null;
  };

  for (const raw of lines) {
    if (raw.startsWith("+++ ")) {
      flush();
      let p = raw.slice(4).trim();
      if (p === "/dev/null") {
        current = { newPath: null, hunks: [] };
        continue;
      }

      if (p.startsWith("b/")) p = p.slice(2);
      current = { newPath: p, hunks: [] };
      inHunk = false;
      continue;
    }
    if (raw.startsWith("--- ")) {
      continue;
    }
    if (raw.startsWith("diff --git") || raw.startsWith("index ")) {
      continue;
    }

    const hunkMatch = /^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/.exec(raw);
    if (hunkMatch) {
      inHunk = true;
      newLine = Number.parseInt(hunkMatch[2], 10);
      continue;
    }

    if (!inHunk || !current) continue;

    if (raw.startsWith("+")) {
      current.hunks.push({ lineNumber: newLine, text: raw.slice(1) });
      newLine++;
    } else if (raw.startsWith("-")) {
      // Removed line: new-file line counter does not advance.
    } else if (raw.startsWith(" ") || raw === "") {
      newLine++;
    }
    // "\ No newline at end of file" and others: ignore.
  }

  flush();
  return files;
}

export function parseFileContent(path: string, content: string): FileChange {
  const splitLines = content.split(/\r?\n/);
  const addedLines: DiffLine[] = splitLines.map((text, i) => ({
    lineNumber: i + 1,
    text,
  }));
  const rawLines = new Map<number, string>();
  for (const line of addedLines) {
    rawLines.set(line.lineNumber, line.text);
  }
  return {
    path,
    language: detectLanguage(path),
    addedLines,
    newContent: content,
    rawLines,
  };
}
