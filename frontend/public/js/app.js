import { initMap } from './map.js';
import { renderResults } from './ui.js';

const API_BASE = 'http://localhost:8080';
let mapInstance = null;
let currentSampleId = null;
let currentAnalysisData = null; // Store fetched data
let loadedSamples = [];

document.addEventListener('DOMContentLoaded', () => {
    fetchSamples();
    setupEventListeners();
});

async function fetchSamples() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/samples`);
        if (!res.ok) throw new Error('Failed to fetch samples');
        const data = await res.json();
        loadedSamples = data.samples || [];
        renderInbox(loadedSamples);
    } catch (e) {
        showToast('Error loading inbox: ' + e.message, 'error');
    }
}

function renderInbox(samples) {
    const list = document.getElementById('inbox-list');
    list.innerHTML = '';
    
    samples.forEach(s => {
        const row = document.createElement('div');
        row.className = 'email-row';
        row.dataset.id = s.id;
        row.innerHTML = `
            <div class="row-header">
                <div class="row-sender">${s.name}</div>
                <div class="row-date">10:45 AM</div>
            </div>
            <div class="row-subject">${s.category}</div>
            <div class="row-snippet">${s.description}</div>
        `;
        row.addEventListener('click', () => openEmail(s, row));
        list.appendChild(row);
    });
}

async function openEmail(sample, rowElement) {
    currentSampleId = sample.id;
    currentAnalysisData = null; // reset
    
    // Highlight selected row
    document.querySelectorAll('.email-row').forEach(r => r.classList.remove('active'));
    if (rowElement) rowElement.classList.add('active');
    
    // Show reading pane
    document.getElementById('empty-state').classList.add('hidden');
    document.getElementById('email-view').classList.remove('hidden');
    
    // Reset banner to un-scanned state
    const banner = document.getElementById('integration-banner');
    const scanBtn = document.getElementById('btn-analyze-threat');
    banner.style.background = 'rgba(59,130,246,0.1)';
    banner.style.borderColor = 'rgba(59,130,246,0.2)';
    banner.querySelector('span').textContent = "Threat Engine Ready";
    scanBtn.className = 'scan-btn';
    scanBtn.innerHTML = '<i class="fas fa-bolt"></i> Scan Email';
    
    // Close sidebar if open from previous email
    document.getElementById('threat-sidebar').classList.remove('open');
    
    // Show quick placeholder metadata while loading real data
    document.getElementById('read-subject').textContent = sample.category;
    document.getElementById('read-sender-name').textContent = sample.name;
    document.getElementById('read-sender-email').textContent = `<${sample.id}@example.com>`;
    document.getElementById('read-avatar').textContent = sample.name.charAt(0);
    
    document.getElementById('read-body').innerHTML = `
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
            <i class="fas fa-circle-notch fa-spin fa-2x mb-3"></i>
            <p style="margin-top: 10px;">Loading email content...</p>
        </div>
    `;

    // Fetch the actual email seamlessly
    try {
        const res = await fetch(`${API_BASE}/api/v1/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sample_id: sample.id })
        });
        
        if (!res.ok) throw new Error('Analysis failed');
        currentAnalysisData = await res.json();
        const meta = currentAnalysisData.metadata;
        
        // Update reading pane with actual email data
        document.getElementById('read-subject').textContent = meta.subject;
        document.getElementById('read-sender-name').textContent = meta.sender_name || meta.from;
        document.getElementById('read-sender-email').textContent = `<${meta.sender_address}>`;
        
        if (meta.body_html) {
            document.getElementById('read-body').innerHTML = meta.body_html;
        } else if (meta.raw_body) {
            document.getElementById('read-body').innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin:0;">${meta.raw_body}</pre>`;
        } else {
            document.getElementById('read-body').innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin:0;">${meta.body_preview}</pre>`;
        }
        
    } catch (e) {
        document.getElementById('read-body').innerHTML = `
            <div style="color:var(--danger)">Error loading email content: ${e.message}</div>
        `;
    }
}

function setupEventListeners() {
    document.getElementById('btn-analyze-threat').addEventListener('click', () => {
        analyzeSample();
    });

    document.getElementById('btn-close-threat').addEventListener('click', () => {
        document.getElementById('threat-sidebar').classList.remove('open');
    });
}

function analyzeSample() {
    // If we haven't finished background loading yet, ignore click or show spinner
    if (!currentAnalysisData) {
        showToast("Still downloading email data, please wait...", "error");
        return;
    }
    
    const data = currentAnalysisData;
    
    // Open the integration sidebar
    const sidebar = document.getElementById('threat-sidebar');
    sidebar.classList.add('open');
    
    // Initialize map only when sidebar is visible so Leaflet sizes correctly
    setTimeout(() => {
        if (!mapInstance) {
            mapInstance = initMap('map-container');
        } else {
            mapInstance.invalidateSize();
        }
        renderResults(data, mapInstance);
    }, 300); // Wait for transition
    
    // Update Banner Style
    const banner = document.getElementById('integration-banner');
    const scanBtn = document.getElementById('btn-analyze-threat');
    
    if (data.risk_level === 'MALICIOUS') {
        banner.style.background = 'rgba(239,68,68,0.1)';
        banner.style.borderColor = 'rgba(239,68,68,0.2)';
        banner.querySelector('span').textContent = "Threat Engine: CRITICAL ALERT";
        banner.querySelector('span').style.color = "#fca5a5";
        banner.querySelector('.shield-icon').style.color = "var(--danger)";
        scanBtn.className = 'scan-btn scanned-danger';
        scanBtn.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Threats Detected';
    } else {
        banner.style.background = 'rgba(16,185,129,0.1)';
        banner.style.borderColor = 'rgba(16,185,129,0.2)';
        banner.querySelector('span').textContent = "Threat Engine: NO THREATS FOUND";
        banner.querySelector('span').style.color = "#6ee7b7";
        banner.querySelector('.shield-icon').style.color = "var(--success)";
        scanBtn.className = 'scan-btn scanned';
        scanBtn.innerHTML = '<i class="fas fa-check-circle"></i> Clean';
    }
}

function showToast(msg, type) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    setTimeout(() => toast.classList.add('hidden'), 3000);
}
