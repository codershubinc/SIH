import { renderHopMap } from './map.js';

export function renderResults(data, map) {
  renderVerdict(data.risk_score, data.risk_level, data.verdict);
  renderAuthPills(data.security_checks);
  renderFindings(data.threat_indicators);
  
  if (map && data.hops) {
      renderHopMap(map, data.hops);
  }
}

function renderVerdict(score = 0, level = 'UNKNOWN', verdict = '') {
    const scoreVal = document.getElementById('score-value');
    const badge = document.getElementById('risk-level-badge');
    const verdictEl = document.getElementById('verdict-text');
    
    if (scoreVal) scoreVal.textContent = score;
    
    if (badge) {
        badge.textContent = level;
        let bg = 'rgba(16,185,129,0.2)'; let col = '#10b981';
        if (score > 30) { bg = 'rgba(245,158,11,0.2)'; col = '#f59e0b'; }
        if (score > 60) { bg = 'rgba(239,68,68,0.2)'; col = '#ef4444'; }
        badge.style.background = bg;
        badge.style.color = col;
        scoreVal.style.color = col;
    }
    
    if (verdictEl) verdictEl.textContent = verdict.replace(/_/g, ' ');
}

function renderAuthPills(security) {
    if (!security) return;
    
    const container = document.getElementById('auth-pills');
    const alignEl = document.getElementById('domain-alignment');
    
    if (container) {
        container.innerHTML = ['spf', 'dkim', 'dmarc'].map(type => {
            if (!security[type]) return '';
            const res = (security[type].result || 'NONE').toLowerCase();
            return `<div class="pill ${res}">${type.toUpperCase()}: ${res.toUpperCase()}</div>`;
        }).join('');
    }
    
    if (alignEl && security.domain_alignment) {
        alignEl.textContent = security.domain_alignment.details || '';
        alignEl.style.color = security.domain_alignment.is_aligned ? '#10b981' : '#ef4444';
    }
}

function renderFindings(indicators) {
    const list = document.getElementById('indicators-list');
    if (!list) return;
    
    if (!indicators || indicators.length === 0) {
        list.innerHTML = `<div style="color:var(--text-muted);font-size:12px;">No threats found.</div>`;
        return;
    }
    
    list.innerHTML = indicators.map(ind => {
        const severity = (ind.severity || 'info').toLowerCase();
        let icon = 'fa-info-circle c-blue';
        if (severity === 'high' || severity === 'critical') icon = 'fa-exclamation-triangle c-red';
        else if (severity === 'medium') icon = 'fa-exclamation-circle c-orange';
        
        return `
            <div class="finding-item">
                <div class="finding-icon"><i class="fas ${icon}"></i></div>
                <div class="finding-text">
                    <h5>${escHtml(ind.title)}</h5>
                    <p>${escHtml(ind.description)}</p>
                </div>
            </div>
        `;
    }).join('');
}

function escHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}
