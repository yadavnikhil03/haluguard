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

const modules: DetectorModule[] = [];

export function registerDetector(mod: DetectorModule): void {
  if (modules.some((m) => m.create().id === mod.create().id)) {
    throw new Error(`Detector "${mod.create().id}" is already registered`);
  }
  modules.push(mod);
}

export function listDetectors(): Detector[] {
  return modules.map((m) => m.create());
}

export function getDetector(id: string): Detector | undefined {
  return listDetectors().find((d) => d.id === id);
}
