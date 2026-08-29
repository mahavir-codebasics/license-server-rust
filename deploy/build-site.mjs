// Builds the static public site (landing page + docs) into deploy/site/.
// Usage: node build-site.mjs [--base-url http://100.87.14.61]
//
// The output is fully self-contained static HTML — served by the nginx
// container on the server, no runtime dependencies.

import { marked } from "marked";
import { mkdirSync, readFileSync, writeFileSync, cpSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "deploy", "site");

const BASE_URL =
  process.argv.includes("--base-url")
    ? process.argv[process.argv.indexOf("--base-url") + 1]
    : "http://100.87.14.61";

// Docs pages: [slug, title, source path]
const DOCS = [
  ["getting-started", "Getting Started", "docs/getting-started.md"],
  ["api-reference", "API Reference", "docs/api-reference.md"],
  ["sdk-guide", "SDK Guide", "docs/sdk-guide.md"],
  ["webhooks", "Webhooks", "docs/webhooks.md"],
  ["architecture", "Architecture", "docs/architecture.md"],
  ["deployment", "Deployment", "docs/deployment.md"],
  ["security-audit", "Security & Performance Audit", "docs/security-audit.md"],
  [
    "design-spec",
    "Design Specification",
    "docs/superpowers/specs/2026-07-25-license-server-rust-design.md",
  ],
];

marked.setOptions({ gfm: true, breaks: false });

// Rewrite repo-relative links so the GitHub markdown links work on the site.
function rewriteLinks(html) {
  let out = html;
  for (const [slug, , src] of DOCS) {
    out = out.replaceAll(`href="${src}"`, `href="/docs/${slug}/"`);
  }
  // Repo-root links that have no page on the site → point at GitHub.
  out = out.replaceAll('href=".env.example"', 'href="https://github.com/keygen-sh/keygen-api" ').trim();
  out = out.replace(/href="(docs\/[^"]+)"/g, "href=\"#\"");
  return out;
}

const SIDEBAR = DOCS.map(
  ([slug, title]) =>
    `<a href="/docs/${slug}/" class="${slug === "getting-started" ? "" : ""}">${title}</a>`,
).join("\n");

function page(title, body, extraHead = "") {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — license-server</title>
<link rel="stylesheet" href="/style.css">
${extraHead}
</head>
<body>
${body}
</body>
</html>`;
}

function docsPage(title, bodyHtml) {
  return page(
    `${title} — Docs`,
    `<header class="topbar">
  <a class="brand" href="/"><span class="brand-mark">◆</span> license-server</a>
  <nav>
    <a href="/docs/getting-started/">Docs</a>
    <a href="/admin/">Admin Console</a>
    <a href="/healthz" data-api>API</a>
  </nav>
</header>
<div class="banner">
  Live instance — REST base <code>${BASE_URL}/v1</code> · Admin console <a href="/admin/">${BASE_URL}/admin/</a> · gRPC <code>${BASE_URL}:9090</code>
</div>
<div class="docs-layout">
  <aside class="sidebar">
    <div class="sidebar-title">Documentation</div>
    <nav class="sidebar-nav">
${SIDEBAR}
    </nav>
  </aside>
  <main class="docs-main">
    <article class="md">
${bodyHtml}
    </article>
  </main>
</div>
<footer class="footer">
  license-server-rust · Apache-2.0 · <a href="/healthz">status</a>
</footer>`,
  );
}

// ── Build ─────────────────────────────────────────────────────────────
mkdirSync(path.join(OUT, "docs"), { recursive: true });

for (const [slug, title, src] of DOCS) {
  const md = readFileSync(path.join(ROOT, src), "utf8");
  const html = rewriteLinks(marked.parse(md));
  const dir = path.join(OUT, "docs", slug);
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "index.html"), docsPage(title, html));
  console.log(`  docs/${slug}/index.html`);
}

cpSync(path.join(ROOT, "deploy", "assets"), path.join(OUT), { recursive: true });
console.log(`  index.html, style.css (from deploy/assets)`);
console.log(`Site built → deploy/site (base URL: ${BASE_URL})`);
