/**
 * map.js — Leaflet.js Map Integration
 * SIH26106 Email Threat Forensics
 */

const CARTO_DARK = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
const CARTO_ATTR = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>';

/**
 * Initialise a Leaflet map on the given container ID.
 * @param {string} containerId
 * @returns {L.Map}
 */
export function initMap(containerId) {
  // Destroy existing map instance if any
  const container = document.getElementById(containerId);
  if (container && container._leaflet_id) {
    container._leaflet_map?.remove();
  }

  const map = L.map(containerId, {
    center: [20, 0],
    zoom: 2,
    zoomControl: true,
    attributionControl: true,
  });

  L.tileLayer(CARTO_DARK, {
    attribution: CARTO_ATTR,
    subdomains: 'abcd',
    maxZoom: 19,
  }).addTo(map);

  // Store ref on container for cleanup
  container._leaflet_map = map;
  return map;
}

/**
 * Render hop route on the map.
 * @param {L.Map} map
 * @param {Array} hops  — Array of hop objects from backend
 */
export function renderHopMap(map, hops) {
  // Clear non-tile layers
  map.eachLayer(layer => {
    if (!(layer instanceof L.TileLayer)) map.removeLayer(layer);
  });

  if (!hops || hops.length === 0) return;

  // Filter valid hops: must have lat/lon, not 0,0, not private
  const validHops = hops.filter(h => {
    const lat = h.geo?.lat ?? h.lat ?? 0;
    const lon = h.geo?.lon ?? h.lon ?? 0;
    const isPrivate = h.is_private ?? h.IsPrivate ?? false;
    return !isPrivate && (lat !== 0 || lon !== 0);
  });

  if (validHops.length === 0) return;

  const latLngs = [];

  validHops.forEach((hop, idx) => {
    const lat = hop.geo?.lat ?? hop.lat;
    const lon = hop.geo?.lon ?? hop.lon;
    const ll  = [lat, lon];
    latLngs.push(ll);

    const ip       = hop.ip        ?? hop.IP        ?? '—';
    const country  = hop.geo?.country ?? hop.Country ?? '—';
    const city     = hop.geo?.city    ?? hop.City    ?? '—';
    const org      = hop.geo?.org     ?? hop.Org     ?? '—';
    const isTor    = hop.is_tor    ?? hop.IsTor    ?? false;
    const isSusp   = hop.suspicious ?? false;

    // Colour scheme
    let colour = '#00d4ff';  // normal cyan
    let radius = 8;
    if (isTor) {
      colour = '#ff3b3b';  // Tor = red
      radius = 10;
    } else if (isSusp) {
      colour = '#ffb347';  // suspicious = orange
      radius = 9;
    }

    // Circle marker
    const circle = L.circleMarker(ll, {
      radius,
      fillColor:   colour,
      color:       colour,
      weight:      2,
      opacity:     1,
      fillOpacity: 0.75,
      className:   isTor ? 'pulsing-marker' : '',
    });

    // Popup content
    const flagStr = flagEmoji(hop.geo?.country_code ?? hop.CountryCode ?? '');
    const torTag  = isTor   ? '<span style="color:#ff3b3b;font-weight:700"> ⚠ TOR EXIT NODE</span>' : '';
    const suspTag = isSusp  ? '<span style="color:#ffb347;font-weight:700"> ⚠ SUSPICIOUS</span>'   : '';

    circle.bindPopup(`
      <div style="min-width:200px">
        <div style="font-weight:700;margin-bottom:6px;color:#00d4ff">
          Hop ${idx + 1} ${torTag}${suspTag}
        </div>
        <table style="border-spacing:4px 2px;width:100%">
          <tr><td style="color:#94a3b8">IP</td><td><code>${ip}</code></td></tr>
          <tr><td style="color:#94a3b8">Country</td><td>${flagStr} ${country}</td></tr>
          <tr><td style="color:#94a3b8">City</td><td>${city}</td></tr>
          <tr><td style="color:#94a3b8">Org</td><td>${org}</td></tr>
        </table>
      </div>
    `);

    circle.addTo(map);

    // Numbered div icon overlay
    const numIcon = L.divIcon({
      html: `<div class="hop-marker-label">${idx + 1}</div>`,
      className: '',
      iconSize:  [22, 22],
      iconAnchor:[11, 11],
    });

    L.marker(ll, { icon: numIcon, interactive: false }).addTo(map);
  });

  // Animated polyline
  if (latLngs.length > 1) {
    const poly = L.polyline(latLngs, {
      color:     '#00d4ff',
      weight:    2,
      opacity:   0.6,
      dashArray: '8 6',
    }).addTo(map);

    // Animate dashes
    let offset = 0;
    const animateLine = () => {
      offset = (offset + 1) % 14;
      poly.setStyle({ dashOffset: String(-offset) });
      requestAnimationFrame(animateLine);
    };
    requestAnimationFrame(animateLine);
  }

  // Fit bounds
  if (latLngs.length > 0) {
    map.fitBounds(L.latLngBounds(latLngs), { padding: [40, 40] });
  }
}

/**
 * Convert ISO 3166-1 alpha-2 country code to flag emoji.
 * @param {string} code
 * @returns {string}
 */
export function flagEmoji(code) {
  if (!code || code.length !== 2) return '🌐';
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + offset) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + offset);
}
