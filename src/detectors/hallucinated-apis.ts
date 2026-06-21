import type { DiffLine, FileLanguage, Finding } from "../types.js";
import type { Detector, DetectorContext } from "./registry.js";

type MemberDB = Record<string, Set<string>>;

const NODE_BUILTINS: MemberDB = {
  crypto: new Set([
    "randomUUID",
    "randomInt",
    "randomBytes",
    "createHash",
    "createHmac",
    "createCipher",
    "createCipheriv",
    "createDecipher",
    "createDecipheriv",
    "getHashes",
    "getCiphers",
    "pbkdf2",
    "pbkdf2Sync",
    "scrypt",
    "scryptSync",
    "timingSafeEqual",
    "webcrypto",
    "constants",
    "Hash",
    "Hmac",
    "Cipher",
    "Decipher",
    "KeyObject",
  ]),
  os: new Set([
    "hostname",
    "platform",
    "arch",
    "type",
    "release",
    "uptime",
    "loadavg",
    "totalmem",
    "freemem",
    "cpus",
    "networkInterfaces",
    "networkInterfaces",
    "homedir",
    "tmpdir",
    "userInfo",
    "EOL",
    "constants",
    "availableParallelism",
    "getPriority",
    "setPriority",
    "machineId",
  ]),
  fs: new Set([
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "readdir",
    "readdirSync",
    "stat",
    "statSync",
    "lstat",
    "lstatSync",
    "existsSync",
    "mkdir",
    "mkdirSync",
    "rm",
    "rmSync",
    "unlink",
    "unlinkSync",
    "rename",
    "renameSync",
    "copyFile",
    "copyFileSync",
    "appendFile",
    "appendFileSync",
    "open",
    "openSync",
    "close",
    "closeSync",
    "createReadStream",
    "createWriteStream",
    "watch",
    "promises",
    "constants",
  ]),
  path: new Set([
    "join",
    "resolve",
    "relative",
    "normalize",
    "dirname",
    "basename",
    "extname",
    "sep",
    "delimiter",
    "isAbsolute",
    "parse",
    "format",
    "toNamespacedPath",
    "win32",
    "posix",
  ]),
  JSON: new Set(["parse", "stringify"]),
  Math: new Set([
    "abs",
    "ceil",
    "floor",
    "round",
    "max",
    "min",
    "pow",
    "sqrt",
    "cbrt",
    "log",
    "log2",
    "log10",
    "exp",
    "random",
    "sign",
    "trunc",
    "sin",
    "cos",
    "tan",
    "atan",
    "atan2",
    "PI",
    "E",
    "LN2",
    "LN10",
    "clz32",
    "fround",
    "hypot",
    "imul",
  ]),
  console: new Set([
    "log",
    "info",
    "warn",
    "error",
    "debug",
    "trace",
    "dir",
    "time",
    "timeEnd",
    "timeLog",
    "assert",
    "count",
    "countReset",
    "group",
    "groupEnd",
    "table",
    "clear",
  ]),
  Promise: new Set(["resolve", "reject", "all", "allSettled", "any", "race", "withResolvers"]),
  Object: new Set([
    "keys",
    "values",
    "entries",
    "assign",
    "freeze",
    "fromEntries",
    "getPrototypeOf",
    "getOwnPropertyNames",
    "getOwnPropertyDescriptor",
    "defineProperty",
    "defineProperties",
    "create",
    "is",
    "seal",
    "preventExtensions",
  ]),
  Array: new Set(["from", "of", "isArray"]),
};

const PACKAGE_MEMBERS: Record<string, MemberDB> = {
  // Intentionally empty seed — extend as curated lists are validated.
};

const KNOWN_HALLUCINATIONS: Record<string, Set<string>> = {
  // namespace-agnostic suspicious members we surface regardless of import.
};

const SUSPICIOUS_GLOBAL_SUFFIXES = new Set(["Sync", "Async", "AllSync", "AllAsync"]);

export const hallucinatedApiDetector: Detector = {
  id: "hallucinated_apis",
  name: "Hallucinated APIs",
  run(ctx: DetectorContext) {
    const start = Date.now();
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (
        file.language !== "typescript" &&
        file.language !== "javascript" &&
        file.language !== "tsx" &&
        file.language !== "jsx" &&
        file.language !== "python"
      ) {
        continue;
      }
      findings.push(...scanFile(file.path, file.language, file.addedLines, ctx.options.cwd));
    }

    return {
      detector: "hallucinated_apis",
      findings,
      durationMs: Date.now() - start,
    };
  },
};

interface ImportBindings {
  locals: Map<string, string>;
}

function scanFile(path: string, language: FileLanguage, lines: DiffLine[], cwd: string): Finding[] {
  const findings: Finding[] = [];
  const imports = collectImports(language, lines);

  for (const { lineNumber, text } of lines) {
    const accessPattern = /\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\b/g;
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic regex match loop
    while ((m = accessPattern.exec(text)) !== null) {
      const [, ident, member] = m;
      const namespaceKey = resolveNamespace(ident, imports, language, cwd, path);
      if (!namespaceKey) continue;

      const members = lookupMembers(namespaceKey);
      if (!members) continue;

      if (!members.has(member)) {
        const suggestion = closestMatch(member, members);
        findings.push(
          buildFinding(path, lineNumber, ident, member, namespaceKey, suggestion, text),
        );
      }
    }
  }

  return findings;
}

function collectImports(language: FileLanguage, lines: DiffLine[]): ImportBindings {
  const locals = new Map<string, string>();

  const record = (localName: string, source: string) => {
    const key = namespaceKeyForSource(source, language);
    if (key) locals.set(localName, key);
  };

  for (const { text } of lines) {
    if (language === "python") {
      const imp = /^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?/.exec(text);
      if (imp) {
        const local = imp[2] ?? imp[1].split(".")[0];
        record(local, imp[1]);
        continue;
      }

      const from = /^\s*from\s+([\w.]+)\s+import\s+(.+)/.exec(text);
      if (from) {
        for (const raw of from[2].split(",")) {
          const part = raw.trim().match(/^(\w+)(?:\s+as\s+(\w+))?/);
          if (!part) continue;
          const local = part[2] ?? part[1];
          record(local, from[1]);
        }
      }
      continue;
    }

    const defaultImport = /^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s+["']([^"']+)["']/.exec(text);
    if (defaultImport) {
      record(defaultImport[1], defaultImport[2]);
      continue;
    }
    const namespaceImport =
      /^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+["']([^"']+)["']/.exec(text);
    if (namespaceImport) {
      record(namespaceImport[1], namespaceImport[2]);
      continue;
    }
    const namedImport = /^\s*import\s+\{([^}]+)\}\s+from\s+["']([^"']+)["']/.exec(text);
    if (namedImport) {
      for (const raw of namedImport[1].split(",")) {
        const part = raw.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?/);
        if (!part) continue;
        record(part[2] ?? part[1], namedImport[2]);
      }
      continue;
    }
    const requireStmt =
      /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(["']([^"']+)["']\)/.exec(text);
    if (requireStmt) {
      record(requireStmt[1], requireStmt[2]);
    }
  }

  return { locals };
}

function namespaceKeyForSource(source: string, language: FileLanguage): string | undefined {
  let s = source.startsWith("node:") ? source.slice(5) : source;

  if (language === "python") {
    return `py:${s.split(".")[0]}`;
  }

  if (NODE_BUILTINS[s]) return s;

  if (PACKAGE_MEMBERS[s]) return s;

  const slash = s.indexOf("/");
  if (slash >= 0)
    s = slash === 0 ? s : s.startsWith("@") ? s.slice(0, s.indexOf("/", 1)) : s.slice(0, slash);

  if (NODE_BUILTINS[s]) return s;
  if (PACKAGE_MEMBERS[s]) return s;
  return undefined;
}

function resolveNamespace(
  ident: string,
  imports: ImportBindings,
  language: FileLanguage,
  cwd: string,
  filePath: string,
): string | undefined {
  if (NODE_BUILTINS[ident]) return ident;
  if (imports.locals.has(ident)) return imports.locals.get(ident);

  if (language === "python" && ident === "json") return "JSON";

  return resolveFromTypes(ident, cwd, filePath);
}

function lookupMembers(key: string): Set<string> | undefined {
  if (NODE_BUILTINS[key]) return NODE_BUILTINS[key];
  if (key.startsWith("py:")) return PYTHON_STDLIB_MEMBERS[key.slice(3)];

  const pkg = PACKAGE_MEMBERS[key];
  if (pkg) return pkg[key];
  return undefined;
}

function resolveFromTypes(_ident: string, _cwd: string, _filePath: string): string | undefined {
  return undefined;
}

function closestMatch(target: string, candidates: Set<string>): string | undefined {
  let best: string | undefined;
  let bestDist = Number.POSITIVE_INFINITY;
  for (const c of candidates) {
    const d = editDistance(target, c);
    if (d < bestDist) {
      bestDist = d;
      best = c;
    }
  }

  if (best === undefined) return undefined;
  const threshold = Math.max(2, Math.floor(target.length / 3));
  return bestDist <= threshold ? best : undefined;
}

function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 3) return Number.POSITIVE_INFINITY;
  const prev = new Array<number>(n + 1);
  const curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= n; j++) prev[j] = curr[j];
  }
  return prev[n];
}

function buildFinding(
  file: string,
  line: number,
  ident: string,
  member: string,
  namespaceKey: string,
  suggestion: string | undefined,
  source: string,
): Finding {
  const suspicious = SUSPICIOUS_GLOBAL_SUFFIXES.has(member.slice(member.length - 4));
  const title = `Possibly invented method: ${ident}.${member}`;
  const hint = suggestion ? ` Did you mean \`${ident}.${suggestion}\`?` : "";
  return {
    id: "hallucinated_api",
    category: "hallucinated_api",
    severity: "medium",
    detector: "hallucinated_apis",
    title,
    message: `\`${namespaceKey}\` does not export a member named \`${member}\`. This is a common LLM hallucination: the call looks plausible but will throw \`TypeError\` at runtime.${hint} If this is actually valid (e.g. added in a newer version, or from a custom augmentation), add an inline \`// haluguard: ignore\` comment.`,
    location: { file, startLine: line, endLine: line },
    snippet: truncate(snippet(source, ident, member), 120),
    confidence: suggestion ? 0.8 : suspicious ? 0.6 : 0.5,
  };
}

function snippet(source: string, ident: string, member: string): string {
  const idx = source.indexOf(`${ident}.${member}`);
  if (idx === -1) return source.trim();
  const start = Math.max(0, idx - 20);
  const end = Math.min(source.length, idx + ident.length + member.length + 20);
  return source.slice(start, end).trim();
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}

const PYTHON_STDLIB_MEMBERS: MemberDB = {
  json: new Set(["dumps", "loads", "dump", "load", "JSONDecoder", "JSONEncoder"]),
  os: new Set([
    "getcwd",
    "chdir",
    "listdir",
    "mkdir",
    "makedirs",
    "remove",
    "removedirs",
    "rename",
    "stat",
    "exists",
    "isfile",
    "isdir",
    "getenv",
    "environ",
    "path",
    "system",
    "pop",
    "popen",
    "getpid",
    "sep",
    "linesep",
    "name",
  ]),
  os_path: new Set([
    "join",
    "basename",
    "dirname",
    "split",
    "splitext",
    "exists",
    "isfile",
    "isdir",
    "abspath",
    "normpath",
    "realpath",
    "relpath",
    "expanduser",
  ]),
  sys: new Set([
    "argv",
    "exit",
    "path",
    "stdin",
    "stdout",
    "stderr",
    "platform",
    "version",
    "version_info",
    "maxsize",
    "modules",
  ]),
  math: new Set([
    "pi",
    "e",
    "tau",
    "inf",
    "nan",
    "sqrt",
    "pow",
    "exp",
    "log",
    "log2",
    "log10",
    "ceil",
    "floor",
    "fabs",
    "factorial",
    "gcd",
    "isclose",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "atan2",
    "degrees",
    "radians",
  ]),
};

export { KNOWN_HALLUCINATIONS };
