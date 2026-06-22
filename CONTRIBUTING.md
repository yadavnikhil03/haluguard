# Contributing to HaluGuard

Thanks for your interest in HaluGuard! This guide will help you get set up and contributing quickly.

## Development Setup

```sh
git clone https://github.com/yadavnikhil03/haluguard.git
cd haluguard
npm install
npm test        # 42+ tests, <1s
npm run build   # produces dist/
```

## Project Structure

```
src/
  cli/           CLI entry point and argument parsing
  core/          Engine, config loader, diff parser, language detection
  detectors/     Individual detector implementations
  reporters/     Output formatters (CLI pretty-print, SARIF)
  types.ts       Shared type definitions
  index.ts       Public API exports
tests/           Vitest test suites
examples/        Demo files for manual testing
scripts/         Helper scripts (pre-commit hook)
```

## Adding a Detector

1. Create a new file in `src/detectors/` (e.g. `my-detector.ts`)
2. Implement the `Detector` interface from `src/detectors/registry.ts`:

```typescript
import type { Detector, DetectorContext } from "./registry.js";

export const myDetector: Detector = {
  id: "my_detector",
  name: "My Detector",
  run(ctx: DetectorContext) {
    const start = Date.now();
    const findings = [];
    // scan ctx.files and populate findings
    return { detector: "my_detector", findings, durationMs: Date.now() - start };
  },
};
```

3. Register it in `src/core/engine.ts`:

```typescript
import { myDetector } from "../detectors/my-detector.js";
// in registerBuiltinDetectors():
registerDetector({ create: () => myDetector });
```

4. Export it from `src/index.ts`
5. Add tests in `tests/`

## Running Tests

```sh
npm test            # run all tests once
npm run test:watch  # re-run on file changes
```

## Code Quality

```sh
npm run typecheck   # TypeScript compiler check
npm run lint        # Biome linter + formatter check
npm run format      # Auto-fix formatting
```

## Code Style

- We use [Biome](https://biomejs.dev/) for linting and formatting
- Run `npm run format` before committing
- No comments in source code (keep it readable through naming and structure)
- Match existing patterns when in doubt

## Pull Request Guidelines

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure all checks pass: `npm run typecheck && npm run lint && npm run build && npm test`
4. Keep PRs focused — one feature or fix per PR
5. Update the README if you add user-facing features

## Configuration

HaluGuard supports a `.haluguard.yml` config file in the project root. See the README for the full schema.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
