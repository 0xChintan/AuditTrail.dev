import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server for the container image (deploy/docker/dashboard.Dockerfile
  // sets NEXT_OUTPUT=standalone); `next start` keeps working everywhere else.
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
  // pnpm monorepo: trace workspace packages (@audittrail/core) from the repo root.
  outputFileTracingRoot: path.join(__dirname, "../.."),
};

export default nextConfig;
