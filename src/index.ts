export { parseDiff, parseFileContent } from "./core/parse-diff.js";
export { detectLanguage, isSupportedLanguage } from "./core/language.js";
export { runScan } from "./core/engine.js";
export {
  registerDetector,
  listDetectors,
  getDetector,
  type Detector,
  type DetectorContext,
  type DetectorModule,
} from "./detectors/registry.js";
export { secretsDetector } from "./detectors/secrets.js";
export { hallucinatedApiDetector } from "./detectors/hallucinated-apis.js";
export { stubsDetector } from "./detectors/stubs.js";
export { renderReport } from "./reporters/cli-reporter.js";
export { renderSarif } from "./reporters/sarif-reporter.js";
export {
  Severity,
  type FileChange,
  type FileLanguage,
  type Finding,
  type FindingCategory,
  type Location,
  type ScanOptions,
  type ScanReport,
  type SeverityLevel,
} from "./types.js";
