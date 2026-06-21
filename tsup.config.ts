import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    cli: "src/cli/index.ts",
    index: "src/index.ts",
  },
  format: ["esm"],
  target: "node18",
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  shims: true,
});
