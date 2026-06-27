import process from "node:process";

export interface ParsedArgs {
  help: boolean;
  version: boolean;

  inputs: string[];

  stdin: boolean;

  format: "pretty" | "json" | "sarif";

  minSeverity: "info" | "low" | "medium" | "high" | "critical";

  detectors?: string[];

  ignore: string[];

  failOn: "never" | "low" | "medium" | "high" | "critical";

  config?: string;

  initHook: boolean;
}

const HELP = `
   _   _       _         ___                     _ 
  | | | | __ _| |_   _  / _ \\_   _  __ _ _ __ __| |
  | |_| |/ _\` | | | | |/ /_\\/ | | |/ _\` | '__/ _\` |
  |  _  | (_| | | |_| / /_\\\\| |_| | (_| | | | (_| |
  |_| |_|\\__,_|_|\\__,_\\____/ \\__,_|\\__,_|_|  \\__,_|
                                                   
      Catch AI hallucinations before they ship.

  USAGE
    haluguard <diff-or-files...>      Scan files or a unified diff
    git diff main...HEAD | haluguard   Scan a diff piped on stdin
    haluguard --help                   Show this help
    haluguard --version                Print version

  OPTIONS
    --format <pretty|json|sarif>   Output format (default: pretty)
    --min-severity <level>         info | low | medium | high | critical
    --detectors <id,id,...>        Only run these detectors
    --ignore <glob>                Ignore paths (repeatable)
    --fail-on <level>              Exit non-zero at/above severity (default: high)
    --stdin                        Read diff from stdin
    --config <path>                Path to .haluguard.yml config file
    --init-hook                    Install a pre-commit git hook
    -h, --help                     Show help
    -v, --version                  Print version

  EXAMPLES
    haluguard src/auth.ts
    haluguard --format sarif $(git diff --name-only main) > results.sarif
    git diff origin/main | haluguard --stdin --format json

  Detects: hallucinated_apis, secrets, stubs, malicious_packages
`;

export function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = {
    help: false,
    version: false,
    inputs: [],
    stdin: false,
    format: "pretty",
    minSeverity: "info",
    ignore: [],
    failOn: "high",
    initHook: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];

    switch (a) {
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "-v":
      case "--version":
        args.version = true;
        break;
      case "--stdin":
        args.stdin = true;
        break;
      case "--format": {
        const v = next();
        if (v !== "pretty" && v !== "json" && v !== "sarif") {
          throwUsage(`--format must be pretty|json|sarif, got "${v}"`);
        }
        args.format = v;
        break;
      }
      case "--min-severity": {
        const v = next();
        if (!isSeverity(v)) throwUsage(`--min-severity invalid: "${v}"`);
        args.minSeverity = v;
        break;
      }
      case "--fail-on": {
        const v = next();
        if (v !== "never" && !isSeverity(v)) {
          throwUsage(`--fail-on invalid: "${v}"`);
        }
        args.failOn = v as ParsedArgs["failOn"];
        break;
      }
      case "--detectors": {
        args.detectors = (next() ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      }
      case "--ignore":
        args.ignore.push(next() ?? "");
        break;
      case "--config":
        args.config = next() ?? "";
        break;
      case "--init-hook":
        args.initHook = true;
        break;
      default:
        if (a.startsWith("--")) throwUsage(`unknown option "${a}"`);
        args.inputs.push(a);
    }
  }

  if (!args.help && !args.version && !args.stdin && args.inputs.length === 0) {
    args.help = true;
  }

  return args;
}

export function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    process.stdin.on("error", reject);
    if (process.stdin.isTTY) resolve("");
  });
}

function isSeverity(v: unknown): v is ParsedArgs["minSeverity"] {
  return v === "info" || v === "low" || v === "medium" || v === "high" || v === "critical";
}

function throwUsage(msg: string): never {
  process.stderr.write(`haluguard: ${msg}\n\n${HELP}\n`);
  process.exit(2);
}

export { HELP };
