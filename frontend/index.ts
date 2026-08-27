import { serve } from 'bun';
import { join } from 'path';
import { existsSync } from 'fs';

const PUBLIC_DIR = join(import.meta.dir, 'public');
const PORT = 5173;

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

serve({
  port: PORT,
  fetch(req) {
    const url = new URL(req.url);
    let pathname = url.pathname === '/' ? '/index.html' : url.pathname;
    const filepath = join(PUBLIC_DIR, pathname);

    if (existsSync(filepath)) {
      const ext = pathname.substring(pathname.lastIndexOf('.'));
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      console.log(`[GET] ${pathname}`);
      const file = Bun.file(filepath);
      return new Response(file, {
        headers: { 'Content-Type': contentType },
      });
    }

    // SPA fallback
    console.log(`[SPA] ${pathname} → index.html`);
    const indexFile = Bun.file(join(PUBLIC_DIR, 'index.html'));
    return new Response(indexFile, {
      headers: { 'Content-Type': 'text/html' },
    });
  },
});

console.log(`🚀 Email Threat Forensics UI running at http://localhost:${PORT}`);