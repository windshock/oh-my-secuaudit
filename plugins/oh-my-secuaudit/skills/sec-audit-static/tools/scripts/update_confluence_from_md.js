const https = require('https');
const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const cur = argv[i];
    if (!cur.startsWith('--')) continue;
    const key = cur.slice(2);
    const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true;
    args[key] = val;
    if (val !== true) i += 1;
  }
  return args;
}

function normalizeTitle(title) {
  return title.replace(/\\s+/g, '').replace(/-/g, '');
}

function normalizeHeading(heading) {
  return heading.replace(/\\s+/g, '');
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
}

function extractHeadings(md) {
  const headings = [];
  const lines = md.split(/\\r?\\n/);
  for (const line of lines) {
    const m = line.match(/^(#{2,6})\\s+(.+)$/);
    if (!m) continue;
    headings.push(m[2].trim());
  }
  return headings;
}

function buildAnchorMap(md, pageTitle) {
  const headings = extractHeadings(md);
  const map = {};
  const prefix = normalizeTitle(pageTitle);

  const summary = headings.find(h => /^2\\.?\\s*진단\\s*결과\\s*요약/.test(h));
  if (summary) {
    map['summary-table'] = `${prefix}-${normalizeHeading(summary)}`;
  }
  const summaryAnchor = headings.find(h => /^summary-table$/i.test(normalizeHeading(h)));
  if (summaryAnchor) {
    map['summary-table'] = `${prefix}-${normalizeHeading(summaryAnchor)}`;
  }

  for (const h of headings) {
    const m = h.match(/취약점\\s+([0-9]+-[0-9]+)/);
    if (m) {
      map[`finding-${m[1]}`] = `${prefix}-${normalizeHeading(h)}`;
    }
    const m2 = h.match(/finding-([0-9]+-[0-9]+)/i);
    if (m2) {
      map[`finding-${m2[1]}`] = `${prefix}-${normalizeHeading(h)}`;
    }
  }

  const appendix = headings.find(h => /appendix-instances/i.test(h));
  if (appendix) {
    map['appendix-instances'] = `${prefix}-${normalizeHeading(appendix)}`;
  }

  return map;
}

function requestJson({ baseUrl, method, path, token, body, headers = {} }) {
  const data = body ? JSON.stringify(body) : null;
  const url = new URL(baseUrl);
  const options = {
    hostname: url.hostname,
    path,
    method,
    headers: {
      'Accept': 'application/json',
      ...(data ? { 'Content-Type': 'application/json; charset=utf-8' } : {}),
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...headers
    }
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let buf = '';
      res.on('data', c => { buf += c; });
      res.on('end', () => {
        if (!buf) return resolve({ status: res.statusCode, json: {} });
        try {
          resolve({ status: res.statusCode, json: JSON.parse(buf) });
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function requestText({ baseUrl, method, path, token, body, headers = {} }) {
  const data = body ? JSON.stringify(body) : null;
  const url = new URL(baseUrl);
  const options = {
    hostname: url.hostname,
    path,
    method,
    headers: {
      'Accept': 'text/plain, */*',
      ...(data ? { 'Content-Type': 'application/json; charset=utf-8' } : {}),
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...headers
    }
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let buf = '';
      res.on('data', c => { buf += c; });
      res.on('end', () => resolve({ status: res.statusCode, text: buf }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const mdPath = args.md;
  const title = args.title;
  const spaceKey = args.space || process.env.CONFLUENCE_SPACE_KEY;
  const baseUrl = (args['base-url'] || process.env.CONFLUENCE_BASE_URL || 'https://wiki.skplanet.com').replace(/\/$/, '');
  const token = process.env.CONFLUENCE_PAT || process.env.CONFLUENCE_TOKEN;
  const pageIdArg = args['page-id'];

  if (!mdPath || !title || !spaceKey) {
    console.error('Usage: node tools/scripts/update_confluence_from_md.js --md <file> --title <title> --space <spaceKey> [--page-id <id>] [--base-url <url>]');
    process.exit(1);
  }
  if (!token) {
    console.error('Missing CONFLUENCE_PAT/CONFLUENCE_TOKEN');
    process.exit(1);
  }

  const md = fs.readFileSync(mdPath, 'utf-8');

  const conv = await requestText({
    baseUrl,
    method: 'POST',
    path: '/rest/tinymce/1/markdownxhtmlconverter',
    token,
    body: { wiki: md, entityId: pageIdArg || '0', spaceKey }
  });
  if (conv.status >= 300) {
    console.error('Converter failed', conv.status, conv.text.slice(0, 200));
    process.exit(1);
  }
  let xhtml = conv.text;

  // Fix common invalid XHTML issues
  xhtml = xhtml.replace(/<li>(.*?)(?=<li>|<\/ul>)/gs, '<li>$1</li>');
  xhtml = xhtml.replace(/<\/li>\s*<\/li>/g, '</li>');
  xhtml = xhtml.replace(/<hr>/g, '<hr />');
  xhtml = xhtml.replace(/<br>/g, '<br />');
  // Convert anchor placeholders to Confluence anchor macros
  xhtml = xhtml.replace(
    /\[\[ANCHOR:([A-Za-z0-9_\-]+)\]\]/g,
    '<ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">$1</ac:parameter></ac:structured-macro>'
  );

  // Rewrite in-page anchor links to Confluence-generated heading ids
  const anchorMap = buildAnchorMap(md, title);
  for (const [from, to] of Object.entries(anchorMap)) {
    xhtml = xhtml.replaceAll(`href="#${from}"`, `href="#${to}"`);
  }
  // Ensure explicit anchor targets exist for summary/finding links without changing heading text
  const prefix = normalizeTitle(title);
  const anchorTargets = new Map();
  for (const h of extractHeadings(md)) {
    const normalized = normalizeHeading(h);
    if (/^summary-table$/i.test(normalized) || /appendix-instances/i.test(normalized) || /finding-([0-9]+-[0-9]+)/i.test(normalized)) {
      anchorTargets.set(h, `${prefix}-${normalized}`);
    }
  }
  for (const [headingText, targetId] of anchorTargets.entries()) {
    const escaped = escapeRegExp(headingText);
    const re = new RegExp(`<h([2-6])([^>]*)>${escaped}</h\\\\1>`, 'g');
    const anchorMacro = `<ac:structured-macro ac:name=\"anchor\"><ac:parameter ac:name=\"\">${targetId}</ac:parameter></ac:structured-macro>`;
    xhtml = xhtml.replace(re, `${anchorMacro}<h$1$2>${headingText}</h$1>`);
  }

  let pageId = pageIdArg;
  let page;
  if (!pageId) {
    const params = new URLSearchParams({ title, spaceKey, expand: 'version,space' }).toString();
    const find = await requestJson({
      baseUrl,
      method: 'GET',
      path: `/rest/api/content?${params}`,
      token
    });
    page = (find.json.results || [])[0];
    if (!page) {
      console.error('Page not found for title/space', { title, spaceKey });
      process.exit(1);
    }
    pageId = page.id;
  } else {
    const found = await requestJson({
      baseUrl,
      method: 'GET',
      path: `/rest/api/content/${pageId}?expand=version,space`,
      token
    });
    page = found.json;
  }

  const nextVersion = (page?.version?.number || 0) + 1;
  const payload = {
    id: pageId,
    type: 'page',
    title,
    space: { key: page?.space?.key || spaceKey },
    version: { number: nextVersion },
    body: {
      storage: {
        value: xhtml,
        representation: 'storage'
      }
    }
  };

  const update = await requestJson({
    baseUrl,
    method: 'PUT',
    path: `/rest/api/content/${pageId}`,
    token,
    body: payload
  });

  console.log(JSON.stringify({
    converterStatus: conv.status,
    updateStatus: update.status,
    pageId,
    nextVersion,
    xhtmlLength: xhtml.length
  }, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
