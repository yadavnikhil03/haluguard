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
        file.language !== "python" &&
        file.language !== "go" &&
        file.language !== "rust" &&
        file.language !== "java" &&
        file.language !== "csharp" &&
        file.language !== "php"
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
    const accessPattern = /\b([A-Za-z_$][\w$]*)(?:\.|::)([A-Za-z_$][\w$]*)\b/g;
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: standard regex loop
    while ((m = accessPattern.exec(text)) !== null) {
      const [fullMatch, ident, member] = m;
      const separator = fullMatch.includes("::") ? "::" : ".";
      const namespaceKey = resolveNamespace(ident, imports, language, cwd, path);
      if (!namespaceKey) continue;

      const members = lookupMembers(namespaceKey);
      if (!members) continue;

      if (!members.has(member)) {
        const suggestion = closestMatch(member, members);
        findings.push(
          buildFinding(path, lineNumber, ident, member, separator, namespaceKey, suggestion, text),
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

    if (language === "go") {
      const goSingle = /^\s*import\s+(?:(\w+)\s+)?"([^"]+)"/.exec(text);
      if (goSingle) {
        const alias = goSingle[1];
        const pkg = goSingle[2];
        const base = pkg.includes("/") ? pkg.slice(pkg.lastIndexOf("/") + 1) : pkg;
        record(alias ?? base, pkg);
        continue;
      }
      const goGrouped = /^\s*(?:(\w+)\s+)?"([^"]+)"/.exec(text);
      if (goGrouped) {
        const alias = goGrouped[1];
        const pkg = goGrouped[2];
        const base = pkg.includes("/") ? pkg.slice(pkg.lastIndexOf("/") + 1) : pkg;
        record(alias ?? base, pkg);
      }
      continue;
    }

    if (language === "java") {
      const javaImport = /^\s*import\s+(?:static\s+)?([\w.]+);/.exec(text);
      if (javaImport) {
        const pkg = javaImport[1];
        const parts = pkg.split(".");
        const base = parts[parts.length - 1];
        if (base === "*") {
          record("*", pkg.slice(0, -2));
        } else {
          record(base, pkg);
        }
      }
      continue;
    }

    if (language === "csharp") {
      const csUsing = /^\s*using\s+(?:static\s+)?([\w.]+);/.exec(text);
      if (csUsing) {
        const pkg = csUsing[1];
        const parts = pkg.split(".");
        const base = parts[parts.length - 1];
        record(base, pkg);
      }
      continue;
    }

    if (language === "php") {
      const phpUse = /^\s*use\s+(?:function\s+|const\s+)?([\w\\]+)(?:\s+as\s+(\w+))?;/i.exec(text);
      if (phpUse) {
        const pkg = phpUse[1];
        const alias = phpUse[2];
        const parts = pkg.split("\\");
        const base = parts[parts.length - 1];
        record(alias ?? base, pkg);
      }
      continue;
    }

    if (language === "rust") {
      const rustUse = /^\s*use\s+([\w:]+)(?:\s+as\s+(\w+))?;/.exec(text);
      if (rustUse) {
        const pkg = rustUse[1];
        const alias = rustUse[2];
        const parts = pkg.split("::");
        const base = parts[parts.length - 1];
        record(alias ?? base, pkg);
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

  if (language === "go") {
    const base = s.includes("/") ? s.slice(s.lastIndexOf("/") + 1) : s;
    if (GO_STDLIB_MEMBERS[base]) return `go:${base}`;
    return undefined;
  }

  if (language === "java") {
    if (JAVA_STDLIB_MEMBERS[s]) return `java:${s}`;
    const base = s.includes(".") ? s.slice(s.lastIndexOf(".") + 1) : s;
    if (JAVA_STDLIB_MEMBERS[base]) return `java:${base}`;
    return undefined;
  }

  if (language === "csharp") {
    if (CSHARP_STDLIB_MEMBERS[s]) return `cs:${s}`;
    const base = s.includes(".") ? s.slice(s.lastIndexOf(".") + 1) : s;
    if (CSHARP_STDLIB_MEMBERS[base]) return `cs:${base}`;
    return undefined;
  }

  if (language === "php") {
    const base = s.includes("\\") ? s.slice(s.lastIndexOf("\\") + 1) : s;
    if (PHP_STDLIB_MEMBERS[base]) return `php:${base}`;
    return undefined;
  }

  if (language === "rust") {
    const base = s.includes("::") ? s.slice(s.lastIndexOf("::") + 2) : s;
    if (RUST_STDLIB_MEMBERS[base]) return `rs:${base}`;
    return undefined;
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
  if (imports.locals.has(ident)) return imports.locals.get(ident);
  if (
    (language === "javascript" ||
      language === "typescript" ||
      language === "tsx" ||
      language === "jsx") &&
    NODE_BUILTINS[ident]
  ) {
    return ident;
  }

  if (language === "python" && ident === "json") return "JSON";

  if (language === "csharp" && CSHARP_STDLIB_MEMBERS[ident]) return `cs:${ident}`;
  if (language === "java" && JAVA_STDLIB_MEMBERS[ident]) return `java:${ident}`;
  if (language === "php" && PHP_STDLIB_MEMBERS[ident]) return `php:${ident}`;

  return resolveFromTypes(ident, cwd, filePath);
}

function lookupMembers(key: string): Set<string> | undefined {
  if (NODE_BUILTINS[key]) return NODE_BUILTINS[key];
  if (key.startsWith("py:")) return PYTHON_STDLIB_MEMBERS[key.slice(3)];
  if (key.startsWith("go:")) return GO_STDLIB_MEMBERS[key.slice(3)];
  if (key.startsWith("java:")) return JAVA_STDLIB_MEMBERS[key.slice(5)];
  if (key.startsWith("cs:")) return CSHARP_STDLIB_MEMBERS[key.slice(3)];
  if (key.startsWith("php:")) return PHP_STDLIB_MEMBERS[key.slice(4)];
  if (key.startsWith("rs:")) return RUST_STDLIB_MEMBERS[key.slice(3)];

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
  separator: string,
  namespaceKey: string,
  suggestion: string | undefined,
  source: string,
): Finding {
  const suspicious = SUSPICIOUS_GLOBAL_SUFFIXES.has(member.slice(member.length - 4));
  const title = `Possibly invented method: ${ident}${separator}${member}`;
  const hint = suggestion ? ` Did you mean \`${ident}${separator}${suggestion}\`?` : "";
  return {
    id: "hallucinated_api",
    category: "hallucinated_api",
    severity: "medium",
    detector: "hallucinated_apis",
    title,
    message: `\`${namespaceKey}\` does not export a member named \`${member}\`. This is a common LLM hallucination: the call looks plausible but will throw \`TypeError\` at runtime.${hint} If this is actually valid (e.g. added in a newer version, or from a custom augmentation), add an inline \`// haluguard: ignore\` comment.`,
    location: { file, startLine: line, endLine: line },
    snippet: truncate(snippet(source, ident, member, separator), 120),
    confidence: suggestion ? 0.8 : suspicious ? 0.6 : 0.5,
  };
}

function snippet(source: string, ident: string, member: string, separator: string): string {
  const idx = source.indexOf(`${ident}${separator}${member}`);
  if (idx === -1) return source.trim();
  const start = Math.max(0, idx - 20);
  const end = Math.min(source.length, idx + ident.length + member.length + separator.length + 20);
  return source.slice(start, end).trim();
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}

const PYTHON_STDLIB_MEMBERS: MemberDB = {
  os: new Set([
    "name",
    "environ",
    "getenv",
    "putenv",
    "makedirs",
    "removedirs",
    "mkdir",
    "remove",
    "rename",
    "replace",
    "rmdir",
    "chdir",
    "getcwd",
    "chmod",
    "link",
    "symlink",
    "readlink",
    "unlink",
    "stat",
    "urandom",
    "system",
    "popen",
    "cpu_count",
    "path",
    "listdir",
    "scandir",
    "walk",
  ]),
  json: new Set(["dump", "dumps", "load", "loads", "JSONDecoder", "JSONEncoder"]),
  math: new Set([
    "acos",
    "asin",
    "atan",
    "atan2",
    "ceil",
    "cos",
    "cosh",
    "degrees",
    "exp",
    "fabs",
    "floor",
    "fmod",
    "frexp",
    "hypot",
    "isclose",
    "isfinite",
    "isinf",
    "isnan",
    "ldexp",
    "log",
    "log10",
    "log1p",
    "log2",
    "modf",
    "pi",
    "pow",
    "radians",
    "sin",
    "sinh",
    "sqrt",
    "tan",
    "tanh",
    "trunc",
    "e",
    "tau",
    "inf",
    "nan",
    "comb",
    "perm",
  ]),
  re: new Set([
    "compile",
    "search",
    "match",
    "fullmatch",
    "split",
    "findall",
    "finditer",
    "sub",
    "subn",
    "escape",
    "purge",
  ]),
  sys: new Set([
    "argv",
    "executable",
    "exit",
    "modules",
    "path",
    "platform",
    "version",
    "version_info",
    "stdin",
    "stdout",
    "stderr",
    "getsizeof",
  ]),
  datetime: new Set([
    "date",
    "time",
    "datetime",
    "timedelta",
    "tzinfo",
    "timezone",
    "MINYEAR",
    "MAXYEAR",
  ]),
  random: new Set([
    "seed",
    "getstate",
    "setstate",
    "randrange",
    "randint",
    "choice",
    "choices",
    "shuffle",
    "sample",
    "random",
    "uniform",
    "triangular",
    "betavariate",
    "expovariate",
    "gammavariate",
    "gauss",
    "lognormvariate",
    "normalvariate",
    "vonmisesvariate",
    "paretovariate",
    "weibullvariate",
  ]),
  collections: new Set([
    "namedtuple",
    "deque",
    "ChainMap",
    "Counter",
    "OrderedDict",
    "defaultdict",
    "UserDict",
    "UserList",
    "UserString",
  ]),
  itertools: new Set([
    "count",
    "cycle",
    "repeat",
    "accumulate",
    "chain",
    "compress",
    "dropwhile",
    "filterfalse",
    "groupby",
    "islice",
    "starmap",
    "takewhile",
    "tee",
    "zip_longest",
    "product",
    "permutations",
    "combinations",
    "combinations_with_replacement",
  ]),
  functools: new Set([
    "cmp_to_key",
    "lru_cache",
    "total_ordering",
    "partial",
    "partialmethod",
    "reduce",
    "singledispatch",
    "update_wrapper",
    "wraps",
  ]),
  shutil: new Set([
    "copyfileobj",
    "copyfile",
    "copymode",
    "copystat",
    "copy",
    "copy2",
    "ignore_patterns",
    "copytree",
    "rmtree",
    "move",
    "disk_usage",
    "chown",
    "which",
    "make_archive",
    "get_archive_formats",
    "register_archive_format",
    "unregister_archive_format",
    "unpack_archive",
    "register_unpack_format",
    "unregister_unpack_format",
    "get_unpack_formats",
  ]),
  urllib: new Set(["request", "response", "parse", "error", "robotparser"]),
  pathlib: new Set([
    "Path",
    "PosixPath",
    "WindowsPath",
    "PurePath",
    "PurePosixPath",
    "PureWindowsPath",
  ]),
  subprocess: new Set([
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "PIPE",
    "STDOUT",
    "DEVNULL",
    "CalledProcessError",
    "TimeoutExpired",
    "SubprocessError",
  ]),
  threading: new Set([
    "active_count",
    "current_thread",
    "excepthook",
    "get_ident",
    "get_native_id",
    "enumerate",
    "main_thread",
    "settrace",
    "setprofile",
    "stack_size",
    "TIMEOUT_MAX",
    "Thread",
    "Timer",
    "Barrier",
    "BoundedSemaphore",
    "Condition",
    "Event",
    "Lock",
    "RLock",
    "Semaphore",
  ]),
};

const GO_STDLIB_MEMBERS: MemberDB = {
  fmt: new Set([
    "Print",
    "Println",
    "Printf",
    "Sprint",
    "Sprintf",
    "Sprintln",
    "Fprint",
    "Fprintf",
    "Fprintln",
    "Errorf",
    "Scan",
    "Scanf",
    "Scanln",
    "Sscan",
    "Sscanf",
    "Sscanln",
    "Fscan",
    "Fscanf",
    "Fscanln",
    "Stringer",
    "GoStringer",
    "Formatter",
  ]),
  os: new Set([
    "Open",
    "Create",
    "OpenFile",
    "ReadFile",
    "WriteFile",
    "Remove",
    "RemoveAll",
    "Mkdir",
    "MkdirAll",
    "Rename",
    "Stat",
    "Lstat",
    "Getenv",
    "Setenv",
    "Unsetenv",
    "LookupEnv",
    "Environ",
    "Exit",
    "Getwd",
    "Chdir",
    "TempDir",
    "UserHomeDir",
    "UserConfigDir",
    "UserCacheDir",
    "Hostname",
    "Getpid",
    "Getppid",
    "Getuid",
    "Getgid",
    "Args",
    "Stdin",
    "Stdout",
    "Stderr",
    "IsNotExist",
    "IsExist",
    "IsPermission",
    "Expand",
    "ExpandEnv",
  ]),
  strings: new Set([
    "Contains",
    "ContainsAny",
    "ContainsRune",
    "Count",
    "Cut",
    "EqualFold",
    "Fields",
    "HasPrefix",
    "HasSuffix",
    "Index",
    "IndexAny",
    "IndexByte",
    "IndexFunc",
    "IndexRune",
    "Join",
    "Map",
    "Repeat",
    "Replace",
    "ReplaceAll",
    "Split",
    "SplitAfter",
    "SplitAfterN",
    "SplitN",
    "Title",
    "ToLower",
    "ToTitle",
    "ToUpper",
    "Trim",
    "TrimFunc",
    "TrimLeft",
    "TrimLeftFunc",
    "TrimPrefix",
    "TrimRight",
    "TrimRightFunc",
    "TrimSpace",
    "TrimSuffix",
    "NewReader",
    "NewReplacer",
    "Builder",
  ]),
  strconv: new Set([
    "Atoi",
    "Itoa",
    "ParseBool",
    "ParseFloat",
    "ParseInt",
    "ParseUint",
    "FormatBool",
    "FormatFloat",
    "FormatInt",
    "FormatUint",
    "AppendBool",
    "AppendFloat",
    "AppendInt",
    "AppendUint",
    "Quote",
    "QuoteRune",
    "Unquote",
    "UnquoteChar",
  ]),
  json: new Set([
    "Marshal",
    "MarshalIndent",
    "Unmarshal",
    "NewDecoder",
    "NewEncoder",
    "Compact",
    "HTMLEscape",
    "Indent",
    "Valid",
  ]),
  http: new Set([
    "Get",
    "Post",
    "PostForm",
    "Head",
    "ListenAndServe",
    "ListenAndServeTLS",
    "Handle",
    "HandleFunc",
    "Serve",
    "ServeTLS",
    "NewRequest",
    "NewRequestWithContext",
    "NewServeMux",
    "FileServer",
    "StripPrefix",
    "NotFound",
    "Redirect",
    "Error",
    "MaxBytesReader",
    "StatusText",
    "CanonicalHeaderKey",
    "DetectContentType",
    "ParseHTTPVersion",
    "ProxyFromEnvironment",
    "ProxyURL",
  ]),
  filepath: new Set([
    "Abs",
    "Base",
    "Clean",
    "Dir",
    "Ext",
    "FromSlash",
    "Glob",
    "HasPrefix",
    "IsAbs",
    "IsLocal",
    "Join",
    "Match",
    "Rel",
    "Split",
    "SplitList",
    "ToSlash",
    "VolumeName",
    "Walk",
    "WalkDir",
    "Separator",
    "ListSeparator",
  ]),
  io: new Set([
    "Copy",
    "CopyBuffer",
    "CopyN",
    "ReadAll",
    "ReadAtLeast",
    "ReadFull",
    "WriteString",
    "Pipe",
    "NopCloser",
    "LimitReader",
    "MultiReader",
    "MultiWriter",
    "TeeReader",
    "NewSectionReader",
    "NewOffsetWriter",
    "Discard",
    "EOF",
  ]),
  sync: new Set([
    "Mutex",
    "RWMutex",
    "WaitGroup",
    "Once",
    "OnceFunc",
    "OnceValue",
    "OnceValues",
    "Pool",
    "Map",
    "Cond",
    "NewCond",
  ]),
};

const JAVA_STDLIB_MEMBERS: MemberDB = {
  String: new Set([
    "length",
    "charAt",
    "substring",
    "indexOf",
    "lastIndexOf",
    "equals",
    "equalsIgnoreCase",
    "compareTo",
    "compareToIgnoreCase",
    "toLowerCase",
    "toUpperCase",
    "trim",
    "replace",
    "replaceAll",
    "replaceFirst",
    "split",
    "join",
    "format",
    "valueOf",
    "isEmpty",
    "isBlank",
    "lines",
    "repeat",
  ]),
  Math: new Set([
    "abs",
    "max",
    "min",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "toRadians",
    "toDegrees",
    "exp",
    "log",
    "log10",
    "sqrt",
    "cbrt",
    "IEEEremainder",
    "ceil",
    "floor",
    "rint",
    "atan2",
    "pow",
    "round",
    "random",
    "addExact",
    "subtractExact",
    "multiplyExact",
    "incrementExact",
    "decrementExact",
    "negateExact",
    "toIntExact",
    "floorDiv",
    "floorMod",
    "nextAfter",
    "nextUp",
    "nextDown",
    "scalb",
  ]),
  List: new Set([
    "size",
    "isEmpty",
    "contains",
    "iterator",
    "toArray",
    "add",
    "remove",
    "containsAll",
    "addAll",
    "removeAll",
    "retainAll",
    "clear",
    "equals",
    "hashCode",
    "get",
    "set",
    "add",
    "remove",
    "indexOf",
    "lastIndexOf",
    "listIterator",
    "subList",
    "replaceAll",
    "sort",
    "spliterator",
    "of",
    "copyOf",
  ]),
  Map: new Set([
    "size",
    "isEmpty",
    "containsKey",
    "containsValue",
    "get",
    "put",
    "remove",
    "putAll",
    "clear",
    "keySet",
    "values",
    "entrySet",
    "equals",
    "hashCode",
    "getOrDefault",
    "forEach",
    "replaceAll",
    "putIfAbsent",
    "remove",
    "replace",
    "computeIfAbsent",
    "computeIfPresent",
    "compute",
    "merge",
    "of",
    "ofEntries",
    "copyOf",
  ]),
  Collections: new Set([
    "sort",
    "binarySearch",
    "reverse",
    "shuffle",
    "swap",
    "fill",
    "copy",
    "min",
    "max",
    "rotate",
    "replaceAll",
    "indexOfSubList",
    "lastIndexOfSubList",
    "unmodifiableCollection",
    "unmodifiableSet",
    "unmodifiableSortedSet",
    "unmodifiableNavigableSet",
    "unmodifiableList",
    "unmodifiableMap",
    "unmodifiableSortedMap",
    "unmodifiableNavigableMap",
    "synchronizedCollection",
    "synchronizedSet",
    "synchronizedSortedSet",
    "synchronizedNavigableSet",
    "synchronizedList",
    "synchronizedMap",
    "synchronizedSortedMap",
    "synchronizedNavigableMap",
    "checkedCollection",
    "checkedQueue",
    "checkedSet",
    "checkedSortedSet",
    "checkedNavigableSet",
    "checkedList",
    "checkedMap",
    "checkedSortedMap",
    "checkedNavigableMap",
    "emptyIterator",
    "emptyListIterator",
    "emptyEnumeration",
    "emptySet",
    "emptySortedSet",
    "emptyNavigableSet",
    "emptyList",
    "emptyMap",
    "emptySortedMap",
    "emptyNavigableMap",
    "singleton",
    "singletonIterator",
    "singletonSpliterator",
    "singletonList",
    "singletonMap",
    "nCopies",
    "reverseOrder",
    "enumeration",
    "list",
    "frequency",
    "disjoint",
    "addAll",
    "newSetFromMap",
    "asLifoQueue",
  ]),
  Arrays: new Set([
    "sort",
    "parallelSort",
    "parallelPrefix",
    "binarySearch",
    "equals",
    "fill",
    "copyOf",
    "copyOfRange",
    "asList",
    "hashCode",
    "deepHashCode",
    "deepEquals",
    "toString",
    "deepToString",
    "setAll",
    "parallelSetAll",
    "spliterator",
    "stream",
    "compare",
    "compareUnsigned",
    "mismatch",
  ]),
  File: new Set([
    "getName",
    "getParent",
    "getParentFile",
    "getPath",
    "isAbsolute",
    "getAbsolutePath",
    "getAbsoluteFile",
    "getCanonicalPath",
    "getCanonicalFile",
    "toURI",
    "canRead",
    "canWrite",
    "exists",
    "isDirectory",
    "isFile",
    "isHidden",
    "lastModified",
    "length",
    "createNewFile",
    "delete",
    "deleteOnExit",
    "list",
    "listFiles",
    "mkdir",
    "mkdirs",
    "renameTo",
    "setLastModified",
    "setReadOnly",
    "setWritable",
    "setReadable",
    "setExecutable",
    "canExecute",
    "getTotalSpace",
    "getFreeSpace",
    "getUsableSpace",
    "createTempFile",
    "compareTo",
  ]),
  Files: new Set([
    "newInputStream",
    "newOutputStream",
    "newByteChannel",
    "newDirectoryStream",
    "createFile",
    "createDirectory",
    "createDirectories",
    "createTempFile",
    "createTempDirectory",
    "createSymbolicLink",
    "createLink",
    "delete",
    "deleteIfExists",
    "copy",
    "move",
    "readSymbolicLink",
    "getFileStore",
    "isSameFile",
    "isHidden",
    "probeContentType",
    "getFileAttributeView",
    "readAttributes",
    "setAttribute",
    "getAttribute",
    "readAllBytes",
    "readString",
    "readAllLines",
    "write",
    "writeString",
    "lines",
    "exists",
    "notExists",
    "isReadable",
    "isWritable",
    "isExecutable",
    "isRegularFile",
    "isDirectory",
    "isSymbolicLink",
    "size",
    "walkFileTree",
    "walk",
    "find",
    "list",
  ]),
  System: new Set([
    "setIn",
    "setOut",
    "setErr",
    "console",
    "inheritedChannel",
    "setSecurityManager",
    "getSecurityManager",
    "currentTimeMillis",
    "nanoTime",
    "arraycopy",
    "identityHashCode",
    "getProperties",
    "lineSeparator",
    "setProperties",
    "getProperty",
    "setProperty",
    "clearProperty",
    "getenv",
    "exit",
    "gc",
    "runFinalization",
    "load",
    "loadLibrary",
    "mapLibraryName",
  ]),
};

const RUST_STDLIB_MEMBERS: MemberDB = {
  fs: new Set([
    "read",
    "read_dir",
    "read_link",
    "read_to_string",
    "remove_dir",
    "remove_dir_all",
    "remove_file",
    "rename",
    "set_permissions",
    "symlink_metadata",
    "write",
    "copy",
    "create_dir",
    "create_dir_all",
    "hard_link",
    "metadata",
    "canonicalize",
    "File",
    "DirBuilder",
    "DirEntry",
    "FileType",
    "Metadata",
    "OpenOptions",
    "Permissions",
    "ReadDir",
  ]),
  io: new Set([
    "copy",
    "empty",
    "repeat",
    "sink",
    "stderr",
    "stdin",
    "stdout",
    "BufReader",
    "BufWriter",
    "Cursor",
    "Error",
    "ErrorKind",
    "IntoInnerError",
    "LineWriter",
    "Result",
    "SeekFrom",
    "BufRead",
    "Read",
    "Seek",
    "Write",
  ]),
  path: new Set([
    "is_separator",
    "MAIN_SEPARATOR",
    "Path",
    "PathBuf",
    "Prefix",
    "PrefixComponent",
    "Component",
    "Components",
    "Iter",
    "Display",
  ]),
  env: new Set([
    "args",
    "args_os",
    "current_dir",
    "current_exe",
    "home_dir",
    "join_paths",
    "remove_var",
    "set_current_dir",
    "set_var",
    "split_paths",
    "temp_dir",
    "var",
    "var_os",
    "vars",
    "vars_os",
    "Args",
    "ArgsOs",
    "JoinPathsError",
    "SplitPaths",
    "VarError",
    "Vars",
    "VarsOs",
    "consts",
  ]),
  cmp: new Set([
    "max",
    "max_by",
    "max_by_key",
    "min",
    "min_by",
    "min_by_key",
    "Eq",
    "Ord",
    "PartialEq",
    "PartialOrd",
    "Ordering",
    "Reverse",
  ]),
  collections: new Set([
    "BTreeMap",
    "BTreeSet",
    "BinaryHeap",
    "HashMap",
    "HashSet",
    "LinkedList",
    "VecDeque",
    "hash_map",
    "hash_set",
    "btree_map",
    "btree_set",
    "binary_heap",
    "linked_list",
    "vec_deque",
  ]),
  thread: new Set([
    "available_parallelism",
    "current",
    "park",
    "park_timeout",
    "park_timeout_ms",
    "panicking",
    "sleep",
    "sleep_ms",
    "spawn",
    "yield_now",
    "Builder",
    "JoinHandle",
    "LocalKey",
    "Thread",
    "ThreadId",
    "Result",
  ]),
  sync: new Set([
    "Arc",
    "Barrier",
    "BarrierWaitResult",
    "Condvar",
    "Mutex",
    "MutexGuard",
    "Once",
    "OnceState",
    "PoisonError",
    "RwLock",
    "RwLockReadGuard",
    "RwLockWriteGuard",
    "WaitTimeoutResult",
    "Weak",
    "atomic",
    "mpsc",
  ]),
  time: new Set(["Duration", "Instant", "SystemTime", "SystemTimeError", "UNIX_EPOCH"]),
  fmt: new Set([
    "format",
    "write",
    "Alignment",
    "Arguments",
    "DebugList",
    "DebugMap",
    "DebugSet",
    "DebugStruct",
    "DebugTuple",
    "Error",
    "Formatter",
    "Result",
    "Binary",
    "Debug",
    "Display",
    "LowerExp",
    "LowerHex",
    "Octal",
    "Pointer",
    "UpperExp",
    "UpperHex",
    "Write",
  ]),
  str: new Set([
    "from_utf8",
    "from_utf8_mut",
    "from_utf8_unchecked",
    "from_utf8_unchecked_mut",
    "Bytes",
    "CharIndices",
    "Chars",
    "EncodeUtf16",
    "EscapeDebug",
    "EscapeDefault",
    "EscapeUnicode",
    "Lines",
    "MatchIndices",
    "Matches",
    "ParseBoolError",
    "RMatchIndices",
    "RMatches",
    "RSplit",
    "RSplitN",
    "RSplitTerminator",
    "Split",
    "SplitAsciiWhitespace",
    "SplitInclusive",
    "SplitN",
    "SplitTerminator",
    "SplitWhitespace",
    "Utf8Error",
    "FromStr",
  ]),
  string: new Set(["String", "Drain", "FromUtf16Error", "FromUtf8Error", "ParseError"]),
  vec: new Set(["Vec", "Drain", "IntoIter", "Splice"]),
  option: new Set(["Option"]),
  result: new Set(["Result"]),
};

const CSHARP_STDLIB_MEMBERS: MemberDB = {
  Console: new Set([
    "Write",
    "WriteLine",
    "Read",
    "ReadLine",
    "ReadKey",
    "Clear",
    "Beep",
    "SetCursorPosition",
    "ResetColor",
  ]),
  Math: new Set([
    "Abs",
    "Ceiling",
    "Floor",
    "Round",
    "Truncate",
    "Max",
    "Min",
    "Pow",
    "Sqrt",
    "Exp",
    "Log",
    "Log10",
    "Sin",
    "Cos",
    "Tan",
    "Asin",
    "Acos",
    "Atan",
    "Atan2",
    "Sinh",
    "Cosh",
    "Tanh",
    "Clamp",
    "Sign",
  ]),
  String: new Set([
    "IsNullOrEmpty",
    "IsNullOrWhiteSpace",
    "Compare",
    "Concat",
    "Format",
    "Join",
    "Split",
    "Substring",
    "ToLower",
    "ToUpper",
    "Trim",
    "TrimStart",
    "TrimEnd",
    "Replace",
    "Contains",
    "StartsWith",
    "EndsWith",
    "IndexOf",
    "LastIndexOf",
  ]),
  File: new Set([
    "Exists",
    "Create",
    "Delete",
    "Copy",
    "Move",
    "ReadAllText",
    "WriteAllText",
    "AppendAllText",
    "ReadAllLines",
    "WriteAllLines",
    "ReadAllBytes",
    "WriteAllBytes",
    "Open",
    "OpenRead",
    "OpenWrite",
    "OpenText",
  ]),
  Directory: new Set([
    "Exists",
    "CreateDirectory",
    "Delete",
    "Move",
    "GetFiles",
    "GetDirectories",
    "GetFileSystemEntries",
    "GetCurrentDirectory",
    "SetCurrentDirectory",
    "GetParent",
  ]),
  Path: new Set([
    "GetFileName",
    "GetFileNameWithoutExtension",
    "GetExtension",
    "GetDirectoryName",
    "GetFullPath",
    "Combine",
    "ChangeExtension",
    "HasExtension",
    "IsPathRooted",
    "GetTempPath",
    "GetTempFileName",
    "GetRandomFileName",
  ]),
  Convert: new Set([
    "ToInt32",
    "ToDouble",
    "ToBoolean",
    "ToString",
    "ToDateTime",
    "ToBase64String",
    "FromBase64String",
    "ChangeType",
  ]),
  DateTime: new Set([
    "Now",
    "UtcNow",
    "Today",
    "AddDays",
    "AddMonths",
    "AddYears",
    "AddHours",
    "AddMinutes",
    "AddSeconds",
    "Parse",
    "TryParse",
    "ParseExact",
    "TryParseExact",
    "ToShortDateString",
    "ToLongDateString",
    "ToShortTimeString",
    "ToLongTimeString",
  ]),
  Task: new Set([
    "Run",
    "Delay",
    "WhenAll",
    "WhenAny",
    "WaitAll",
    "WaitAny",
    "FromResult",
    "Yield",
  ]),
  JsonSerializer: new Set(["Serialize", "Deserialize", "SerializeAsync", "DeserializeAsync"]),
};

const PHP_STDLIB_MEMBERS: MemberDB = {
  DateTime: new Set([
    "__construct",
    "add",
    "createFromFormat",
    "createFromImmutable",
    "createFromInterface",
    "diff",
    "format",
    "getLastErrors",
    "getOffset",
    "getTimestamp",
    "getTimezone",
    "modify",
    "setDate",
    "setISODate",
    "setTime",
    "setTimestamp",
    "setTimezone",
    "sub",
  ]),
  PDO: new Set([
    "__construct",
    "beginTransaction",
    "commit",
    "errorCode",
    "errorInfo",
    "exec",
    "getAttribute",
    "getAvailableDrivers",
    "inTransaction",
    "lastInsertId",
    "prepare",
    "query",
    "quote",
    "rollBack",
    "setAttribute",
  ]),
  Exception: new Set([
    "__construct",
    "getMessage",
    "getPrevious",
    "getCode",
    "getFile",
    "getLine",
    "getTrace",
    "getTraceAsString",
    "__toString",
  ]),
};

export { KNOWN_HALLUCINATIONS };
