import type { FileLanguage } from "../types.js";

const EXT_MAP: Record<string, FileLanguage> = {
  ".ts": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".tsx": "tsx",
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".jsx": "jsx",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".kt": "java",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
};

export function detectLanguage(filePath: string): FileLanguage {
  const lower = filePath.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot === -1) return "unknown";
  const ext = lower.slice(dot);
  return EXT_MAP[ext] ?? "unknown";
}

export function isSupportedLanguage(lang: FileLanguage): boolean {
  return lang !== "unknown";
}
