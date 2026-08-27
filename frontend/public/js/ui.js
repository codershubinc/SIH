/**
 * ui.js — UI Rendering Functions
 * SIH26106 Email Threat Forensics
 */

import { flagEmoji } from './map.js';

/* ════════════════════════════════════════════════
   MAIN DISPATCHER
   ════════════════════════════════════════════════ */

/**
 * Render all results panels from API response.
 * @param {Object} data  — full API response object
 * @param {L.Map}  map   — Leaflet map instance
 */
export function renderResults(data, map) {
  const analysis = data.analysis ?? data;

  // Subject in toolbar
  const subject = analysis.subject ?? analysis.headers?.subject ?? data.subject ?? '(no subject)';
  safeText('email-subject-label', subject);

  // Sections
  renderScoreCard(analysis);
  renderAuthPills(analysis.security_checks ?? analysis.authentication ?? {});
  renderDomainAlignment(analysis.domain_alignment ?? null);
  renderNLPCard(analysis.nlp ?? analysis.nlp_analysis ?? null);
  renderIndicators(analysis.indicators ?? analysis.threat_indicators ?? []);

  const hops = analysis.routing?.hops ?? analysis.hops ?? [];
  renderHopsTable(hops);
  safeText('hop-count', `${hops.length} hop${hops.length !== 1 ? 's' : ''}`);

  const urls = analysis.urls ?? analysis.extracted_urls ?? [];
  renderURLsTable(urls);
  safeText('url-count', String(urls.length));

  const attachments = analysis.attachments ?? [];
  renderAttachmentsTable(attachments);
  safeText('attachment-count', String(attachments.length));

  renderRawHeaders(analysis.raw_headers ?? analysis.headers?.raw ?? null);

  // Map routing
  if (map && typeof window.renderHopMap === 'function') {
    window.renderHopMap(map, hops);
  } else if (map) {
    import('./map.js').then(m => m.renderHopMap(map, hops));
  }
}

/* ════════════════════════════════════════════════
   SCORE CARD
   ════════════════════════════════════════════════ */

export function renderScoreCard(data) {
  const score     = Math.round(data.risk_score ?? data.score ?? 0);
  const riskLevel = (data.risk_level ?? data.verdict ?? 'unknown').toLowerCase().replace(/\s+/g, '_');

  const numEl  = document.getElementById('score-number');
  const badge  = document.getElementById('risk-badge');
  const label  = document.getElementById('score-label');
  const ring   = document.getElementById('score-ring-fill');

  if (!numEl) return;

  // Animated counter
  let current = 0;
  const target = score;
  const step   = Math.max(1, Math.ceil(target / 60));
  const interval = setInterval(() => {
    current = Math.min(current + step, target);
    numEl.textContent = current;
    if (current >= target) clearInterval(interval);
  }, 18);

  // Ring fill  (circumference = 2π × 52 ≈ 326.73)
  const circumference = 326.73;
  const dashOffset    = circumference - (score / 100) * circumference;
  if (ring) {
    setTimeout(() => {
      ring.style.strokeDashoffset = dashOffset;
      ring.className = 'ring-fill ring-' + riskLevel;
    }, 100);
  }

  // Badge
  if (badge) {
    badge.textContent  = riskLevelLabel(riskLevel);
    badge.className    = `risk-badge badge-${riskLevel}`;
  }

  // Label
  if (label) {
    label.textContent = scoreDescription(riskLevel, score);
  }
}

function riskLevelLabel(level) {
  const map = {
    clean:      'CLEAN',
    low_risk:   'LOW RISK',
    suspicious: 'SUSPICIOUS',
    malicious:  'MALICIOUS',
  };
  return map[level] ?? level.toUpperCase().replace(/_/g, ' ');
}

function scoreDescription(level, score) {
  if (level === 'clean')      return `Score ${score}/100 — No significant threats detected.`;
  if (level === 'low_risk')   return `Score ${score}/100 — Minor anomalies found. Monitor.`;
  if (level === 'suspicious') return `Score ${score}/100 — Multiple warning signs detected.`;
  if (level === 'malicious')  return `Score ${score}/100 — High confidence threat. Do not interact.`;
  return `Composite risk score: ${score}/100`;
}

/* ════════════════════════════════════════════════
   AUTH PILLS (SPF / DKIM / DMARC)
   ════════════════════════════════════════════════ */

export function renderAuthPills(security_checks) {
  const container = document.getElementById('auth-pills');
  if (!container) return;

  const checks = [
    { key: 'spf',   label: 'SPF',   value: security_checks.spf   ?? security_checks.SPF  },
    { key: 'dkim',  label: 'DKIM',  value: security_checks.dkim  ?? security_checks.DKIM },
    { key: 'dmarc', label: 'DMARC', value: security_checks.dmarc ?? security_checks.DMARC },
  ];

  container.innerHTML = checks.map(({ key, label, value }) => {
    const status  = (value?.result ?? value?.status ?? value ?? 'none').toLowerCase();
    const pilClass = pillClass(status);
    const icon     = pillIcon(status);
    const detail   = value?.details ?? value?.explanation ?? '';

    return `
      <div class="auth-pill ${pilClass}" title="${detail || status.toUpperCase()}">
        <i class="fa-solid ${icon} pill-icon"></i>
        <span>${label}</span>
        <strong>${status.toUpperCase()}</strong>
      </div>
    `;
  }).join('');
}

function pillClass(status) {
  if (status === 'pass')     return 'pill-pass';
  if (status === 'fail')     return 'pill-fail';
  if (status === 'softfail') return 'pill-softfail';
  return 'pill-none';
}

function pillIcon(status) {
  if (status === 'pass')     return 'fa-circle-check';
  if (status === 'fail')     return 'fa-circle-xmark';
  if (status === 'softfail') return 'fa-circle-exclamation';
  return 'fa-circle-minus';
}

/* ════════════════════════════════════════════════
   DOMAIN ALIGNMENT
   ════════════════════════════════════════════════ */

export function renderDomainAlignment(domain_alignment) {
  const wrap = document.getElementById('domain-alignment-wrap');
  if (!wrap) return;
  if (!domain_alignment) { wrap.innerHTML = ''; return; }

  const rows = [
    { label: 'From Domain',         value: domain_alignment.from_domain       ?? domain_alignment.from       ?? '—', match: null },
    { label: 'Return-Path',         value: domain_alignment.return_path_domain ?? domain_alignment.return_path ?? '—', match: domain_alignment.return_path_match },
    { label: 'Reply-To',            value: domain_alignment.reply_to_domain   ?? domain_alignment.reply_to   ?? '—', match: domain_alignment.reply_to_match },
    { label: 'DKIM Domain',         value: domain_alignment.dkim_domain       ?? '—',                               match: domain_alignment.dkim_match },
  ];

  wrap.innerHTML = rows.map(r => `
    <div class="domain-row">
      <span class="domain-label">${r.label}</span>
      <span class="domain-value">${escHtml(r.value)}</span>
      ${r.match === null ? '' :
        r.match
          ? '<span class="domain-match"><i class="fa-solid fa-check"></i> MATCH</span>'
          : '<span class="domain-mismatch"><i class="fa-solid fa-xmark"></i> MISMATCH</span>'
      }
    </div>
  `).join('');
}

/* ════════════════════════════════════════════════
   INDICATORS
   ════════════════════════════════════════════════ */

export function renderIndicators(indicators) {
  const list  = document.getElementById('indicators-list');
  const count = document.getElementById('indicator-count');
  if (!list) return;

  if (count) count.textContent = String(indicators.length);

  if (indicators.length === 0) {
    list.innerHTML = emptyState('fa-shield-check', 'No threat indicators detected');
    return;
  }

  // Sort: critical → high → medium → low → info
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...indicators].sort((a, b) => {
    const sa = (a.severity ?? 'info').toLowerCase();
    const sb = (b.severity ?? 'info').toLowerCase();
    return (order[sa] ?? 5) - (order[sb] ?? 5);
  });

  list.innerHTML = sorted.map(ind => {
    const severity = (ind.severity ?? 'info').toLowerCase();
    const name     = ind.name        ?? ind.title       ?? 'Unknown Indicator';
    const desc     = ind.description ?? ind.detail      ?? '';
    const mitre    = ind.mitre_id    ?? ind.mitre_attack ?? '';

    return `
      <div class="indicator-card">
        <div class="indicator-top">
          <span class="severity-badge sev-${severity}">${severity.toUpperCase()}</span>
          <span class="indicator-name">${escHtml(name)}</span>
        </div>
        ${desc ? `<p class="indicator-desc">${escHtml(desc)}</p>` : ''}
        ${mitre ? `
          <a class="mitre-link"
             href="https://attack.mitre.org/techniques/${mitre.replace('.', '/')}"
             target="_blank" rel="noopener noreferrer">
            <i class="fa-solid fa-arrow-up-right-from-square"></i> ${mitre}
          </a>` : ''}
      </div>
    `;
  }).join('');
}

/* ════════════════════════════════════════════════
   HOPS TABLE
   ════════════════════════════════════════════════ */

export function renderHopsTable(hops) {
  const tbody = document.getElementById('hops-tbody');
  if (!tbody) return;

  if (!hops || hops.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No routing hops available</td></tr>`;
    return;
  }

  tbody.innerHTML = hops.map((hop, idx) => {
    const ip       = hop.ip        ?? hop.IP        ?? '—';
    const country  = hop.geo?.country   ?? hop.Country ?? '—';
    const cc       = hop.geo?.country_code ?? hop.CountryCode ?? '';
    const city     = hop.geo?.city    ?? hop.City    ?? '—';
    const org      = hop.geo?.org     ?? hop.Org     ?? '—';
    const protocol = hop.protocol  ?? hop.Protocol ?? '—';
    const transit  = hop.transit_time ?? hop.TransitTime ?? null;
    const isTor    = hop.is_tor    ?? hop.IsTor    ?? false;
    const isPriv   = hop.is_private ?? hop.IsPrivate ?? false;

    const flag      = flagEmoji(cc);
    const torHtml   = isTor  ? '<span class="tor-badge"><i class="fa-solid fa-mask"></i> TOR</span>' : '';
    const privHtml  = isPriv ? '<span class="tor-badge" style="border-color:#94a3b8;color:#94a3b8">PRIV</span>' : '';
    const transitStr = transit ? `${transit}ms` : '—';

    return `
      <tr>
        <td><strong>${idx + 1}</strong></td>
        <td style="font-family:monospace;color:var(--accent-cyan)">${escHtml(ip)}</td>
        <td>${flag} ${escHtml(country)}</td>
        <td>${escHtml(city)}</td>
        <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${escHtml(org)}">${escHtml(org)}</td>
        <td><span class="proto-badge">${escHtml(protocol)}</span></td>
        <td style="color:var(--text-secondary)">${transitStr}</td>
        <td>${torHtml}${privHtml}</td>
      </tr>
    `;
  }).join('');
}

/* ════════════════════════════════════════════════
   NLP CARD
   ════════════════════════════════════════════════ */

export function renderNLPCard(nlp) {
  const container = document.getElementById('nlp-content');
  if (!container) return;

  if (!nlp) {
    container.innerHTML = emptyState('fa-brain', 'No NLP data available');
    return;
  }

  const urgency    = Math.round((nlp.urgency_score ?? nlp.urgency ?? 0) * 100) / 100;
  const urgencyPct = Math.min(100, Math.max(0, urgency));
  const keywords   = nlp.keywords ?? nlp.urgency_keywords ?? [];
  const hasFin     = nlp.financial_request ?? nlp.has_financial ?? false;
  const hasCred    = nlp.credential_request ?? nlp.has_credentials ?? false;
  const hasThreat  = nlp.threat_language   ?? nlp.has_threats      ?? false;
  const hasImperson= nlp.impersonation     ?? nlp.has_impersonation ?? false;
  const sentiment  = nlp.sentiment         ?? null;
  const lang       = nlp.language          ?? null;

  const booleans = [
    { label: 'Financial Request',  val: hasFin },
    { label: 'Credential Phishing',val: hasCred },
    { label: 'Threat Language',    val: hasThreat },
    { label: 'Impersonation',      val: hasImperson },
  ];

  container.innerHTML = `
    <div class="nlp-urgency-label">
      <span>Urgency Score</span>
      <strong style="color:var(--accent-orange)">${urgencyPct}/100</strong>
    </div>
    <div class="nlp-bar-track">
      <div class="nlp-bar-fill" id="urgency-bar" style="width:0%"></div>
    </div>
    ${keywords.length > 0 ? `
    <p style="font-size:0.75rem;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.06em">Keywords</p>
    <div class="nlp-keywords">
      ${keywords.slice(0, 15).map(k => `<span class="nlp-keyword">${escHtml(String(k))}</span>`).join('')}
    </div>` : ''}
    <div class="nlp-booleans">
      ${booleans.map(b => `
        <span class="nlp-bool ${b.val ? 'bool-true' : 'bool-false'}">
          <i class="fa-solid ${b.val ? 'fa-circle-exclamation' : 'fa-circle-check'}"></i>
          ${b.label}
        </span>
      `).join('')}
    </div>
    ${sentiment ? `<p style="margin-top:10px;font-size:0.78rem;color:var(--text-secondary)">Sentiment: <strong>${escHtml(sentiment)}</strong></p>` : ''}
    ${lang ? `<p style="font-size:0.78rem;color:var(--text-secondary)">Language: <strong>${escHtml(lang)}</strong></p>` : ''}
  `;

  // Animate urgency bar after paint
  requestAnimationFrame(() => {
    setTimeout(() => {
      const bar = document.getElementById('urgency-bar');
      if (bar) bar.style.width = urgencyPct + '%';
    }, 200);
  });
}

/* ════════════════════════════════════════════════
   URLS TABLE
   ════════════════════════════════════════════════ */

export function renderURLsTable(urls) {
  const tbody = document.getElementById('urls-tbody');
  if (!tbody) return;

  if (!urls || urls.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No URLs found</td></tr>`;
    return;
  }

  tbody.innerHTML = urls.map(u => {
    const risk        = (u.risk_level ?? u.risk ?? 'unknown').toLowerCase();
    const url         = u.url         ?? u.href    ?? '—';
    const displayText = u.display_text ?? u.text   ?? '—';
    const deceptive   = u.is_deceptive ?? u.deceptive ?? false;

    const riskClass = riskBadgeClass(risk);
    const deceptHtml = deceptive
      ? `<span class="deceptive-warn"><i class="fa-solid fa-triangle-exclamation"></i> Deceptive</span>`
      : '';

    return `
      <tr>
        <td><span class="url-risk-badge ${riskClass}">${risk.toUpperCase()}</span></td>
        <td class="wrap" style="max-width:320px">
          <a href="${escHtml(url)}" target="_blank" rel="noopener noreferrer"
             style="color:var(--accent-cyan);text-decoration:none;font-family:monospace;font-size:0.78rem"
             title="${escHtml(url)}">
            ${escHtml(truncate(url, 60))}
          </a>
        </td>
        <td style="color:var(--text-secondary);font-size:0.82rem">${escHtml(displayText)}</td>
        <td>${deceptHtml}</td>
      </tr>
    `;
  }).join('');
}

/* ════════════════════════════════════════════════
   ATTACHMENTS TABLE
   ════════════════════════════════════════════════ */

export function renderAttachmentsTable(attachments) {
  const tbody = document.getElementById('attachments-tbody');
  if (!tbody) return;

  if (!attachments || attachments.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No attachments</td></tr>`;
    return;
  }

  tbody.innerHTML = attachments.map(att => {
    const name     = att.filename    ?? att.name    ?? 'unknown';
    const type     = att.mime_type   ?? att.type    ?? '—';
    const size     = att.size        ?? att.file_size ?? null;
    const isDanger = att.is_dangerous ?? att.dangerous ?? false;
    const riskLvl  = att.risk_level  ?? (isDanger ? 'dangerous' : 'safe');

    const sizeStr  = size ? formatBytes(size) : '—';
    const riskHtml = isDanger
      ? `<span class="att-danger"><i class="fa-solid fa-skull-crossbones"></i> ${riskLvl.toUpperCase()}</span>`
      : `<span class="att-safe"><i class="fa-solid fa-shield-check"></i> SAFE</span>`;

    return `
      <tr>
        <td style="font-weight:600;color:${isDanger ? 'var(--accent-red)' : 'var(--text-primary)'}">${escHtml(name)}</td>
        <td style="font-family:monospace;font-size:0.78rem;color:var(--text-secondary)">${escHtml(type)}</td>
        <td style="color:var(--text-secondary)">${sizeStr}</td>
        <td>${riskHtml}</td>
      </tr>
    `;
  }).join('');
}

/* ════════════════════════════════════════════════
   RAW HEADERS
   ════════════════════════════════════════════════ */

export function renderRawHeaders(rawHeaders) {
  const pre     = document.getElementById('raw-headers-pre');
  const toggle  = document.getElementById('raw-headers-toggle');
  const body    = document.getElementById('raw-headers-body');
  const chevron = document.getElementById('headers-chevron');

  if (!pre) return;

  if (!rawHeaders) {
    if (toggle) toggle.style.display = 'none';
    return;
  }

  // Syntax-highlight: colour keys vs values
  const highlighted = String(rawHeaders)
    .split('\n')
    .map(line => {
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0 && !line.startsWith(' ') && !line.startsWith('\t')) {
        const key = escHtml(line.substring(0, colonIdx));
        const val = escHtml(line.substring(colonIdx + 1));
        return `<span class="hdr-key">${key}</span><span class="hdr-colon">:</span><span class="hdr-val">${val}</span>`;
      }
      return `<span class="hdr-val">${escHtml(line)}</span>`;
    })
    .join('\n');

  pre.innerHTML = highlighted;

  // Toggle behaviour
  if (toggle) {
    toggle.addEventListener('click', () => {
      const isHidden = body.classList.contains('hidden');
      body.classList.toggle('hidden', !isHidden);
      if (chevron) chevron.classList.toggle('open', isHidden);
    });

    toggle.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggle.click();
      }
    });
  }
}

/* ════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════ */

function riskBadgeClass(risk) {
  if (risk === 'malicious')  return 'risk-malicious';
  if (risk === 'suspicious') return 'risk-suspicious';
  if (risk === 'clean' || risk === 'safe') return 'risk-clean';
  return 'risk-unknown';
}

function emptyState(icon, text) {
  return `<div class="empty-state"><i class="fa-solid ${icon}"></i>${text}</div>`;
}

function escHtml(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(String(str)));
  return div.innerHTML;
}

function safeText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function truncate(str, len) {
  return str.length > len ? str.slice(0, len) + '…' : str;
}

function formatBytes(bytes) {
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1048576)     return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}
