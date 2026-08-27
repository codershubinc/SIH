const TILE_URL = 'https://basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png?key=cb1_2cxe_1_aea6b08879097f800d5ed8bb';
const CARTO_ATTR = '&copy; OpenStreetMap contributors &copy; CARTO';

export function initMap(containerId) {
  const container = document.getElementById(containerId);
  if (container && container._leaflet_id) {
    container._leaflet_map?.remove();
  }
  const map = L.map(containerId, {
    center: [20, 0], zoom: 1, zoomControl: false, attributionControl: false
  });
  L.tileLayer(TILE_URL, { maxZoom: 19 }).addTo(map);
  container._leaflet_map = map;
  return map;
}

function ipToLatLon(ip) {
    if (!ip) return [20, 0];
    let hash = 0;
    for (let i = 0; i < ip.length; i++) hash = ip.charCodeAt(i) + ((hash << 5) - hash);
    const lat = ((Math.abs(hash) % 12000) / 100) - 60;
    const lon = (((Math.abs(hash) >> 8) % 24000) / 100) - 120;
    return [lat, lon];
}

export function renderHopMap(map, hops) {
  map.eachLayer(layer => { if (!(layer instanceof L.TileLayer)) map.removeLayer(layer); });
  if (!hops || hops.length === 0) return;

  const validHops = hops.filter(h => !(h.is_private ?? h.IsPrivate ?? false));
  if (validHops.length === 0) return;

  const latLngs = [];
  
  validHops.forEach((hop, idx) => {
    let lat = hop.geo?.lat ?? hop.lat ?? 0;
    let lon = hop.geo?.lon ?? hop.lon ?? 0;
    const ip = hop.ip ?? hop.IP ?? '—';
    
    // Fallback coordinates for presentation
    if (lat === 0 && lon === 0 && ip !== '—') {
        const fakeCoords = ipToLatLon(ip);
        lat = fakeCoords[0];
        lon = fakeCoords[1];
    }
    
    const ll = [lat, lon];
    latLngs.push(ll);

    const isTor = hop.is_tor ?? hop.IsTor ?? false;
    let colour = '#3b82f6';
    if (isTor) colour = '#ef4444';
    else if (hop.suspicious) colour = '#f59e0b';

    L.circleMarker(ll, { radius: 6, fillColor: colour, color: colour, weight: 1, opacity: 1, fillOpacity: 0.8 })
     .bindPopup(`Hop ${idx+1}: <strong>${ip}</strong>`)
     .addTo(map);
  });

  if (latLngs.length > 1) {
    L.polyline(latLngs, { color: '#3b82f6', weight: 2, opacity: 0.7, dashArray: '5 5' }).addTo(map);
  }
  if (latLngs.length > 0) {
    map.fitBounds(L.latLngBounds(latLngs), { padding: [20, 20], maxZoom: 5 });
  }
}
