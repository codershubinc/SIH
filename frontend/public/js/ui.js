/**
 * ui.js — UI Rendering Functions for Modern Mail
 * SIH26106 Email Threat Forensics
 */

import { renderHopMap } from './map.js';

export function renderResults(data, map) {
  const meta = data.metadata || {};
  
  renderScoreCard(data.risk_score, data.risk_level, data.verdict);
  renderAuthPills(data.security_checks);
  renderIndicators(data.threat_indicators);
  renderNLP(data.nlp_analysis);
  renderURLsTable(data.extracted_urls);
  renderAttachmentsTable(data.attachments);
  
  if (map && data.hops) {
      renderHopMap(map, data.hops);
  }
}

function renderScoreCard(score = 0, level = 'UNKNOWN', verdict = 'No analysis') {
    const scoreVal = document.getElementById('score-value');
    const badge = document.getElementById('risk-level-badge');
    const verdictEl = document.getElementById('verdict-text');
    const circle = document.getElementById('score-circle');
    
    if (scoreVal) scoreVal.textContent = score;
    if (badge) badge.textContent = level;
    if (verdictEl) verdictEl.textContent = verdict.replace(/_/g, ' ');
    
    let color = '#10b981'; // green
    if (score > 30) color = '#f59e0b'; // orange
    if (score > 60) color = '#ef4444'; // red
    
    if (circle) {
        circle.style.stroke = color;
        setTimeout(() => {
            circle.style.strokeDasharray = `${score}, 100`;
        }, 100);
    }
}

function renderAuthPills(security) {
    if (!security) return;
    
    const container = document.querySelector('.pills-container');
    const alignEl = document.getElementById('domain-alignment');
    
    if (container) {
        container.innerHTML = ['spf', 'dkim', 'dmarc'].map(type => {
            if (!security[type]) return '';
            const res = (security[type].result || 'NONE').toLowerCase();
            const icon = res === 'pass' ? 'fa-check' : res === 'fail' ? 'fa-times' : 'fa-minus';
            return `<div class="pill ${res}"><i class="fas ${icon}"></i> ${type.toUpperCase()}: ${res.toUpperCase()}</div>`;
        }).join('');
    }
    
    if (alignEl && security.domain_alignment) {
        alignEl.textContent = security.domain_alignment.details || '';
        if (!security.domain_alignment.is_aligned) {
            alignEl.style.color = '#ef4444';
        } else {
            alignEl.style.color = '#10b981';
        }
    }
}

function renderIndicators(indicators) {
    const list = document.getElementById('indicators-list');
    if (!list) return;
    
    if (!indicators || indicators.length === 0) {
        list.innerHTML = `<div style="color:var(--text-muted);font-size:13px;">No threat indicators found.</div>`;
        return;
    }
    
    list.innerHTML = indicators.map(ind => {
        const severity = (ind.severity || 'info').toLowerCase();
        return `
            <div class="indicator-item ${severity}">
                <h4>${escHtml(ind.title)}</h4>
                <p>${escHtml(ind.description)}</p>
            </div>
        `;
    }).join('');
}

function renderNLP(nlp) {
    if (!nlp) return;
    
    const bar = document.getElementById('urgency-bar');
    const summary = document.getElementById('nlp-summary');
    const keywords = document.getElementById('nlp-keywords');
    
    if (bar) {
        setTimeout(() => {
            bar.style.width = Math.min(nlp.urgency_score || 0, 100) + '%';
        }, 100);
    }
    if (summary) summary.textContent = nlp.summary || '';
    if (keywords && nlp.urgency_keywords) {
        keywords.innerHTML = nlp.urgency_keywords.map(kw => `<span class="tag">${escHtml(kw)}</span>`).join('');
    }
}

function renderURLsTable(urls) {
    const tbody = document.querySelector('#urls-table tbody');
    if (!tbody) return;
    
    if (!urls || urls.length === 0) {
        tbody.innerHTML = `<tr><td colspan="2" style="color:var(--text-muted);text-align:center;">No URLs extracted</td></tr>`;
        return;
    }
    
    tbody.innerHTML = urls.map(u => {
        let riskClass = 'pill pass';
        let icon = 'fa-check-circle';
        if (u.risk_level === 'MALICIOUS') { riskClass = 'pill fail'; icon = 'fa-exclamation-triangle'; }
        if (u.risk_level === 'SUSPICIOUS') { riskClass = 'pill neutral'; icon = 'fa-exclamation-circle'; }
        
        return `
            <tr>
                <td><span class="${riskClass}" style="width:fit-content"><i class="fas ${icon}"></i> ${u.risk_level}</span></td>
                <td style="word-break:break-all;"><a href="#" style="color:#3b82f6;">${escHtml(u.url)}</a></td>
            </tr>
        `;
    }).join('');
}

function renderAttachmentsTable(attachments) {
    const tbody = document.querySelector('#attachments-table tbody');
    if (!tbody) return;
    
    if (!attachments || attachments.length === 0) {
        tbody.innerHTML = `<tr><td colspan="2" style="color:var(--text-muted);text-align:center;">No attachments</td></tr>`;
        return;
    }
    
    tbody.innerHTML = attachments.map(a => {
        return `
            <tr>
                <td style="color:${a.is_dangerous ? '#ef4444' : '#10b981'}"><i class="fas ${a.is_dangerous ? 'fa-times-circle' : 'fa-check-circle'}"></i> ${a.is_dangerous ? 'DANGEROUS' : 'SAFE'}</td>
                <td>${escHtml(a.filename)}</td>
            </tr>
        `;
    }).join('');
}

function escHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}
