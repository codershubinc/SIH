/**
 * app.js — Main App Controller (ES Module)
 * SIH26106 Email Threat Forensics
 */

import { initMap, renderHopMap } from './map.js';
import { renderResults } from './ui.js';

/* ════════════════════════════════════════════════
   CONFIG
   ════════════════════════════════════════════════ */
const API_BASE = 'http://localhost:8080';

/* ════════════════════════════════════════════════
   STATE
   ════════════════════════════════════════════════ */
let leafletMap    = null;
let lastResult    = null;
let isAnalysing   = false;

/* ════════════════════════════════════════════════
   DOM REFS
   ════════════════════════════════════════════════ */
const uploadSection  = document.getElementById('upload-section');
const resultsSection = document.getElementById('results-section');
const spinnerOverlay = document.getElementById('spinner-overlay');
const dropZone       = document.getElementById('drop-zone');
const fileInput      = document.getElementById('file-input');
const backBtn        = document.getElementById('back-btn');
const exportBtn      = document.getElementById('export-btn');
const toast          = document.getElementById('toast');

/* ════════════════════════════════════════════════
   INITIALISATION
   ════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  initLeafletMap();
  bindEvents();
  checkApiStatus();
});

function initLeafletMap() {
  leafletMap = initMap('map-container');
}

/* ════════════════════════════════════════════════
   API CALLS
   ════════════════════════════════════════════════ */

/**
 * Upload and analyse an .eml file.
 * @param {FormData} formData
 */
async function analyzeFile(formData) {
  if (isAnalysing) return;
  isAnalysing = true;
  showSpinner(true);

  try {
    const res = await fetch(`${API_BASE}/api/v1/analyze`, {
      method: 'POST',
      body:   formData,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error ?? err.message ?? `Server error ${res.status}`);
    }

    const data = await res.json();
    lastResult  = data;
    handleSuccess(data);
  } catch (err) {
    showToast(`Analysis failed: ${err.message}`, 'error');
    console.error('[analyzeFile]', err);
  } finally {
    showSpinner(false);
    isAnalysing = false;
  }
}

/**
 * Load a built-in sample threat.
 * @param {string} sampleId
 */
async function loadSample(sampleId) {
  if (isAnalysing) return;
  isAnalysing = true;
  showSpinner(true);

  try {
    const res = await fetch(`${API_BASE}/api/v1/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ sample_id: sampleId }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error ?? err.message ?? `Server error ${res.status}`);
    }

    const data = await res.json();
    lastResult  = data;
    handleSuccess(data);
  } catch (err) {
    showToast(`Failed to load sample: ${err.message}`, 'error');
    console.error('[loadSample]', err);
  } finally {
    showSpinner(false);
    isAnalysing = false;
  }
}

/* ════════════════════════════════════════════════
   RESULT HANDLER
   ════════════════════════════════════════════════ */

function handleSuccess(data) {
  // Switch panels
  uploadSection.classList.add('hidden');
  resultsSection.classList.remove('hidden');

  // Render all UI panels
  renderResults(data, leafletMap);

  // Render map hops
  const analysis = data.analysis ?? data;
  const hops     = analysis.routing?.hops ?? analysis.hops ?? [];
  renderHopMap(leafletMap, hops);

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });
  showToast('Analysis complete!', 'success');
}

/* ════════════════════════════════════════════════
   EVENT BINDINGS
   ════════════════════════════════════════════════ */

function bindEvents() {
  // ── Drag & Drop ──
  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.add('highlight');
  });

  dropZone.addEventListener('dragleave', e => {
    e.preventDefault();
    dropZone.classList.remove('highlight');
  });

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('highlight');

    const files = e.dataTransfer?.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    if (!isValidEml(file)) {
      showToast('Please upload a valid .eml or .msg file.', 'error');
      return;
    }

    const fd = new FormData();
    fd.append('file', file);
    analyzeFile(fd);
  });

  // ── Click to open file picker ──
  dropZone.addEventListener('click', e => {
    if (e.target === fileInput) return;
    fileInput.click();
  });

  dropZone.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  // ── File input change ──
  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (!file) return;

    if (!isValidEml(file)) {
      showToast('Please upload a valid .eml or .msg file.', 'error');
      fileInput.value = '';
      return;
    }

    const fd = new FormData();
    fd.append('file', file);
    analyzeFile(fd);
    fileInput.value = '';
  });

  // ── Sample buttons ──
  document.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleId = btn.dataset.sample;
      if (sampleId) loadSample(sampleId);
    });
  });

  // ── Back / Reset ──
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      resultsSection.classList.add('hidden');
      uploadSection.classList.remove('hidden');
      lastResult = null;
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // ── Export JSON ──
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      if (!lastResult) {
        showToast('No analysis result to export.', 'error');
        return;
      }

      const json  = JSON.stringify(lastResult, null, 2);
      const blob  = new Blob([json], { type: 'application/json' });
      const url   = URL.createObjectURL(blob);
      const a     = document.createElement('a');
      const subject = (lastResult.analysis ?? lastResult).subject ?? 'email-analysis';
      const fname   = `forensics-${slugify(subject)}-${Date.now()}.json`;

      a.href     = url;
      a.download = fname;
      a.click();
      URL.revokeObjectURL(url);
      showToast('JSON exported!', 'success');
    });
  }
}

/* ════════════════════════════════════════════════
   API STATUS CHECK
   ════════════════════════════════════════════════ */

async function checkApiStatus() {
  const dotEl = document.querySelector('.status-dot');
  const lblEl = document.querySelector('.api-status');

  try {
    const res = await fetch(`${API_BASE}/api/v1/health`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      if (dotEl) dotEl.classList.remove('offline');
      if (lblEl) lblEl.title = 'Backend API is reachable';
    } else {
      throw new Error(`${res.status}`);
    }
  } catch {
    if (dotEl) dotEl.classList.add('offline');
    if (lblEl) {
      lblEl.innerHTML = `<i class="fa-solid fa-circle status-dot offline"></i> API Offline`;
      lblEl.title     = `Cannot reach ${API_BASE}`;
    }
  }
}

/* ════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════ */

function showSpinner(show) {
  spinnerOverlay?.classList.toggle('hidden', !show);
}

let toastTimer = null;
function showToast(message, type = 'info') {
  if (!toast) return;

  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.className   = `toast ${type}`;
  toast.classList.remove('hidden');

  toastTimer = setTimeout(() => {
    toast.classList.add('hidden');
  }, 4000);
}

function isValidEml(file) {
  const name = (file.name ?? '').toLowerCase();
  return name.endsWith('.eml') || name.endsWith('.msg') ||
         file.type === 'message/rfc822';
}

function slugify(str) {
  return String(str)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
}
