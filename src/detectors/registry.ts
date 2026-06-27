import type { DetectorResult, FileChange, ScanOptions } from "../types.js";

export interface Detector {
  id: string;

  name: string;
  run(ctx: DetectorContext): Promise<DetectorResult> | DetectorResult;
}

export interface DetectorContext {
  files: FileChange[];
  options: ScanOptions;
}

export interface DetectorModule {
  create(): Detector;
}

const registry = new Map<string, Detector>();

export function registerDetector(mod: DetectorModule): void {
  const detector = mod.create();
  if (registry.has(detector.id)) {
    throw new Error(`Detector "${detector.id}" is already registered`);
  }
  registry.set(detector.id, detector);
}

export function listDetectors(): Detector[] {
  return Array.from(registry.values());
}

export function getDetector(id: string): Detector | undefined {
  return registry.get(id);
}
