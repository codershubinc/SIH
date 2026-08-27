import { initMap, renderHopMap } from './map.js';
import { renderResults } from './ui.js';

const API_BASE = 'http://localhost:8080';
let mapInstance = null;
let currentSampleId = null;
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
        row.innerHTML = `
            <div class="controls">
                <i class="far fa-square"></i>
                <i class="far fa-star"></i>
            </div>
            <div class="sender">${s.name}</div>
            <div class="subject-snippet">
                <span class="subject">${s.category}</span>
                <span class="snippet">- ${s.description}</span>
            </div>
            <div class="date">Aug 27</div>
        `;
        row.addEventListener('click', () => openEmail(s));
        list.appendChild(row);
    });
}

function openEmail(sample) {
    currentSampleId = sample.id;
    document.getElementById('inbox-list').classList.add('hidden');
    document.getElementById('reading-pane').classList.remove('hidden');
    
    document.getElementById('read-subject').textContent = sample.category;
    document.getElementById('read-sender-name').textContent = sample.name;
    document.getElementById('read-sender-email').textContent = `<${sample.id}@example.com>`;
    
    document.getElementById('read-avatar').textContent = sample.name.charAt(0);
    
    // Quick fake body based on description, but ideally we'd fetch the raw EML body.
    // For MVP, we'll display a generic message or description.
    document.getElementById('read-body').innerHTML = `
        <p><strong>Category:</strong> ${sample.category}</p>
        <p><strong>Description:</strong> ${sample.description}</p>
        <hr style="margin: 20px 0; border:0; border-top:1px solid #ccc;">
        <p style="color:#555;">[Raw email content preview hidden. Click Analyze to see forensic details.]</p>
    `;
}

function setupEventListeners() {
    document.getElementById('btn-back-to-inbox').addEventListener('click', () => {
        document.getElementById('reading-pane').classList.add('hidden');
        document.getElementById('inbox-list').classList.remove('hidden');
    });

    document.getElementById('btn-analyze-threat').addEventListener('click', () => {
        if (currentSampleId) analyzeSample(currentSampleId);
    });

    document.getElementById('btn-close-analysis').addEventListener('click', () => {
        document.getElementById('analysis-overlay').classList.add('hidden');
    });
}

async function analyzeSample(sampleId) {
    showSpinner();
    try {
        const res = await fetch(`${API_BASE}/api/v1/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sample_id: sampleId })
        });
        
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Analysis failed');
        }
        
        const data = await res.json();
        
        document.getElementById('analysis-overlay').classList.remove('hidden');
        
        if (!mapInstance) {
            mapInstance = initMap('map-container');
        }
        
        // Update reading pane with actual email body/subject now that we have it
        if(data.metadata) {
            document.getElementById('read-subject').textContent = data.metadata.subject;
            document.getElementById('read-sender-name').textContent = data.metadata.sender_name || data.metadata.from;
            document.getElementById('read-sender-email').textContent = `<${data.metadata.sender_address}>`;
            
            if (data.metadata.body_html) {
                document.getElementById('read-body').innerHTML = data.metadata.body_html;
            } else {
                document.getElementById('read-body').innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit;">${data.metadata.body_preview}</pre>`;
            }
        }
        
        renderResults(data, mapInstance);
        
    } catch (e) {
        showToast(e.message, 'error');
    } finally {
        hideSpinner();
    }
}

function showSpinner() {
    document.getElementById('loading-spinner').classList.remove('hidden');
}

function hideSpinner() {
    document.getElementById('loading-spinner').classList.add('hidden');
}

function showToast(msg, type) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    setTimeout(() => toast.classList.add('hidden'), 3000);
}
