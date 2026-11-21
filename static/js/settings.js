/* LogScope - editor de presets */

var LS = window.LOGSCOPE;
let catalog = { models: [], presets: [], meta: {} };

function modelOptions() {
  return catalog.models.map((m) => m.full_id);
}

function renderPresets() {
  const container = document.getElementById('presets-list');
  const presets = catalog.presets || [];
  container.innerHTML = presets.map((preset, index) => `
    <div class="row" style="margin-bottom:9px" data-index="${index}">
      <input type="text" class="preset-label" value="${LS.escape(preset.label)}" placeholder="alias" style="width:130px">
      <select class="preset-model" style="flex:1">
        ${catalog.models.map((m) => {
          const selected = m.full_id === preset.model ? ' selected' : '';
          return `<option value="${LS.escape(m.full_id)}"${selected}>${LS.escape(m.full_id)}${m.tier === 'free' ? ' (gratis)' : ''}</option>`;
        }).join('')}
        ${catalog.models.some((m) => m.full_id === preset.model) ? '' : `<option value="${LS.escape(preset.model)}" selected>${LS.escape(preset.model)} (no disponible)</option>`}
      </select>
      <input type="text" class="preset-desc" value="${LS.escape(preset.description || '')}" placeholder="descripcion" style="width:220px">
      <button class="btn btn-sm btn-danger" data-remove="${index}">&times;</button>
    </div>`).join('');

  container.querySelectorAll('[data-remove]').forEach((button) => {
    button.addEventListener('click', () => {
      catalog.presets.splice(Number(button.dataset.remove), 1);
      renderPresets();
    });
  });
}

function collectPresets() {
  const rows = document.querySelectorAll('#presets-list [data-index]');
  const presets = [];
  rows.forEach((row) => {
    const label = row.querySelector('.preset-label').value.trim();
    const model = row.querySelector('.preset-model').value;
    const description = row.querySelector('.preset-desc').value.trim();
    if (label && model) presets.push({ label, model, description });
  });
  return presets;
}

async function savePresets() {
  const status = document.getElementById('preset-status');
  try {
    await LS.api('/api/presets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ presets: collectPresets() })
    });
    status.textContent = 'guardado';
    status.className = 'small muted';
    setTimeout(() => { status.textContent = ''; }, 2200);
  } catch (err) {
    status.textContent = err.message;
    status.className = 'small';
    status.style.color = 'var(--critical)';
  }
}

async function boot() {
  catalog = await LS.loadCatalog();
  const meta = document.getElementById('catalog-meta');
  if (catalog.meta && catalog.meta.status === 'ok') {
    meta.innerHTML = `
      <div class="spread"><span>Proveedor <b>${LS.escape(catalog.meta.provider)}</b></span>
      <span class="badge ok">${catalog.meta.total} modelos</span></div>
      <div class="mt-1 faint">${Object.entries(catalog.meta.by_tier || {})
        .map(([tier, count]) => `${tier}: ${count}`).join(' · ')}</div>`;
  } else {
    meta.innerHTML = `<div class="notice warn">${LS.escape((catalog.meta && catalog.meta.message) || 'catalogo no disponible')}</div>`;
  }
  renderPresets();
  document.getElementById('preset-add').addEventListener('click', () => {
    const first = catalog.models[0];
    catalog.presets.push({
      label: `preset-${catalog.presets.length + 1}`,
      model: first ? first.full_id : '',
      description: ''
    });
    renderPresets();
  });
  document.getElementById('preset-save').addEventListener('click', savePresets);
}

boot().catch((err) => console.error(err));
