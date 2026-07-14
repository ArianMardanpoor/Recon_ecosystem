import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";
import {
  defineConfig,
  loadEnv,
  type Plugin,
  type ViteDevServer,
} from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";

const PROJECT_ROOT = import.meta.dirname;
const LOG_DIR = path.join(PROJECT_ROOT, ".manus-logs");
const MAX_LOG_SIZE_BYTES = 1024 * 1024;
const TRIM_TARGET_BYTES = Math.floor(MAX_LOG_SIZE_BYTES * 0.6);

type LogSource = "browserConsole" | "networkRequests" | "sessionReplay";

function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function trimLogFile(logPath: string, maxSize: number) {
  try {
    if (!fs.existsSync(logPath)) return;

    const stat = fs.statSync(logPath);
    if (stat.size <= maxSize) return;

    const lines = fs.readFileSync(logPath, "utf8").split("\n");

    const kept: string[] = [];
    let size = 0;

    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];
      const bytes = Buffer.byteLength(line + "\n");

      if (size + bytes > TRIM_TARGET_BYTES) break;

      kept.unshift(line);
      size += bytes;
    }

    fs.writeFileSync(logPath, kept.join("\n"), "utf8");
  } catch {}
}

function writeToLogFile(source: LogSource, entries: unknown[]) {
  if (!entries.length) return;

  ensureLogDir();

  const logFile = path.join(LOG_DIR, `${source}.log`);

  const lines = entries.map((entry) => {
    return `[${new Date().toISOString()}] ${JSON.stringify(entry)}`;
  });

  fs.appendFileSync(logFile, lines.join("\n") + "\n");

  trimLogFile(logFile, MAX_LOG_SIZE_BYTES);
}

function vitePluginManusDebugCollector(): Plugin {
  return {
    name: "manus-debug-collector",

    transformIndexHtml(html) {
      if (process.env.NODE_ENV === "production") {
        return html;
      }

      return {
        html,
        tags: [
          {
            tag: "script",
            attrs: {
              src: "/__manus__/debug-collector.js",
              defer: true,
            },
            injectTo: "head",
          },
        ],
      };
    },

    configureServer(server) {
      server.middlewares.use("/__manus__/logs", (req, res, next) => {
        if (req.method !== "POST") {
          return next();
        }

        const handlePayload = (payload: any) => {
          if (payload.consoleLogs?.length) {
            writeToLogFile("browserConsole", payload.consoleLogs);
          }

          if (payload.networkRequests?.length) {
            writeToLogFile("networkRequests", payload.networkRequests);
          }

          if (payload.sessionEvents?.length) {
            writeToLogFile("sessionReplay", payload.sessionEvents);
          }

          res.writeHead(200, {
            "Content-Type": "application/json",
          });

          res.end(JSON.stringify({ success: true }));
        };

        let body = "";

        req.on("data", (chunk) => {
          body += chunk.toString();
        });

        req.on("end", () => {
          try {
            handlePayload(JSON.parse(body));
          } catch (e) {
            res.writeHead(400, {
              "Content-Type": "application/json",
            });

            res.end(
              JSON.stringify({
                success: false,
                error: String(e),
              }),
            );
          }
        });
      });
    },
  };
}

function vitePluginStorageProxy(): Plugin {
  return {
    name: "manus-storage-proxy",

    configureServer(server) {
      server.middlewares.use("/manus-storage", async (req, res) => {
        const key = req.url?.replace(/^\//, "");

        if (!key) {
          res.writeHead(400);
          res.end("Missing storage key");
          return;
        }

        const forgeBaseUrl = (
          process.env.BUILT_IN_FORGE_API_URL || ""
        ).replace(/\/+$/, "");

        const forgeKey = process.env.BUILT_IN_FORGE_API_KEY;

        if (!forgeBaseUrl || !forgeKey) {
          res.writeHead(500);
          res.end("Storage proxy not configured");
          return;
        }

        try {
          const forgeUrl = new URL(
            "v1/storage/presign/get",
            forgeBaseUrl + "/",
          );

          forgeUrl.searchParams.set("path", key);

          const forgeResp = await fetch(forgeUrl, {
            headers: {
              Authorization: `Bearer ${forgeKey}`,
            },
          });

          if (!forgeResp.ok) {
            res.writeHead(502);
            res.end("Storage backend error");
            return;
          }

          const { url } = await forgeResp.json();

          res.writeHead(307, {
            Location: url,
            "Cache-Control": "no-store",
          });

          res.end();
        } catch {
          res.writeHead(502);
          res.end("Storage proxy error");
        }
      });
    },
  };
}

const plugins = [
  react(),
  tailwindcss(),
  jsxLocPlugin(),
  vitePluginManusRuntime(),
  vitePluginManusDebugCollector(),
  vitePluginStorageProxy(),
];

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, PROJECT_ROOT, "");

  console.log("Loaded env:", env);

  return {
    plugins,

    envDir: PROJECT_ROOT,

    root: path.join(PROJECT_ROOT, "client"),

    resolve: {
      alias: {
        "@": path.join(PROJECT_ROOT, "client", "src"),
        "@shared": path.join(PROJECT_ROOT, "shared"),
        "@assets": path.join(PROJECT_ROOT, "attached_assets"),
      },
    },

    build: {
      outDir: path.join(PROJECT_ROOT, "dist/public"),
      emptyOutDir: true,
    },

    server: {
      port: 3000,
      host: true,
      strictPort: false,

      allowedHosts: [
        ".manuspre.computer",
        ".manus.computer",
        ".manus-asia.computer",
        ".manuscomputer.ai",
        ".manusvm.computer",
        "localhost",
        "127.0.0.1",
      ],

      fs: {
        strict: true,
        deny: ["**/.*"],
      },

      proxy: {
        "/api": {
          target: env.VITE_API_URL || "http://localhost:3131",
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api/, "/api"),
          timeout: 30000,
        },
      },
    },
  };
});