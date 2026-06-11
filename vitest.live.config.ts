import { defineConfig } from "vitest/config";

/** Live integration run against deadrop.dev — see test/live/live.test.ts. */
export default defineConfig({
  test: {
    include: ["test/live/**/*.test.ts"],
    // Live tests share the per-IP create rate limit — never parallelize.
    fileParallelism: false,
    maxConcurrency: 1,
    sequence: { concurrent: false },
  },
});
