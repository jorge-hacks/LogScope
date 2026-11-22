/* LogScope - pagina de inicio: subida de logs, catalogo de modelos y arranque */

var LS = window.LOGSCOPE;
let catalog = { models: [], presets: [], meta: {} };
let selectedFiles = [];

/* ------------------------------------------------------------------ modelos */
async function loadCatalog() {
  const select = document.getElementById('model-select');
  const hint = document.getElementById('model-hint');
  try {
    catalog = await LS.api('/api/models');
  } catch (err) {
    catalog = { models: [], presets: [], meta: { status: 'error', message: String(err.message || err) } };
  }

  LS.populateModelSelect(select, catalog, LS.defaultModel);

  const presets = document.getElementById('preset-select');
  presets.innerHTML = '';
  if (!catalog.presets || !catalog.presets.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'sin presets';
    presets.appendChild(option);
  } else {
    catalog.presets.forEach((preset) => {
      const option = document.createElement('option');
      option.value = preset.label;
      option.textContent = `${preset.label} → ${preset.model}${preset.available ? '' : ' (no disponible)'}`;
      if (preset.model === select.value) option.selected = true;
      presets.appendChild(option);
    });
  }

  const meta = catalog.meta || {};
  if (meta.status !== 'ok') {
    hint.innerHTML = `<span style="color:var(--medium)">${LS.escape(meta.message || 'catalogo no disponible')}</span>`;
  } else {
    const free = (meta.by_tier && meta.by_tier.free) || 0;
    const low = (meta.by_tier && meta.by_tier.low) || 0;
    hint.innerHTML = `${meta.total} modelos de <b>${LS.escape(meta.provider)}</b> con tool calling `
      + `(${free} gratis, ${low} economicos). Solo se listan los que el servidor de opencode `
      + `reconoce ahora mismo, asi que la lista se actualiza sola cuando el proveedor rota modelos.`;
  }
}

/* ------------------------------------------------------------------ ficheros */
function renderFiles() {
  const list = document.getElementById('file-list');
  list.innerHTML = selectedFiles.map((file) =>
    `<span class="file-chip">${LS.escape(file.name)} · ${(file.size / 1024).toFixed(1)} KB</span>`
  ).join('');
  const ready = selectedFiles.length > 0;
  document.getElementById('upload-btn').disabled = !ready;
  document.getElementById('upload-only-btn').disabled = !ready;
}

function addFiles(fileList) {
  const incoming = Array.from(fileList || []);
  const known = new Set(selectedFiles.map((f) => `${f.name}:${f.size}`));
  for (const file of incoming) {
    const key = `${file.name}:${file.size}`;
    if (!known.has(key)) {
      selectedFiles.push(file);
      known.add(key);
    }
  }
  renderFiles();
}

/* ------------------------------------------------------------------ subida */
async function upload(runAnalysis) {
  if (!selectedFiles.length) return;

  const button = document.getElementById(runAnalysis ? 'upload-btn' : 'upload-only-btn');
  const status = document.getElementById('upload-status');
  const form = new FormData();
  form.append('name', document.getElementById('analysis-name').value.trim());
  selectedFiles.forEach((file) => form.append('files', file, file.name));

  button.disabled = true;
  status.innerHTML = '<span class="spinner"></span> indexando logs...';

  try {
    const result = await LS.api('/api/upload', { method: 'POST', body: form });
    const detail = result.files.map((f) => `${f.profile}:${f.rows}`).join(' · ');
    status.innerHTML = `<span style="color:var(--success)">${result.events} eventos indexados (${detail})</span>`;

    if (runAnalysis) {
      status.innerHTML += ' <span class="spinner"></span> lanzando el analisis...';
      await LS.api(`/api/analysis/${result.analysis_id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: document.getElementById('model-select').value })
      });
      window.location.href = `/analysis/${result.analysis_id}`;
      return;
    }
    window.location.href = `/analysis/${result.analysis_id}`;
  } catch (err) {
    status.innerHTML = `<span style="color:var(--critical)">${LS.escape(err.message)}</span>`;
    button.disabled = false;
  }
}

/* ------------------------------------------------------------------ wiring */
function wire() {
  const dropzone = document.getElementById('dropzone');
  const input = document.getElementById('file-input');

  dropzone.addEventListener('click', () => input.click());
  input.addEventListener('change', () => { addFiles(input.files); });

  ['dragenter', 'dragover'].forEach((type) => {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.add('drag');
    });
  });
  ['dragleave', 'drop'].forEach((type) => {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.remove('drag');
    });
  });
  dropzone.addEventListener('drop', (event) => {
    if (event.dataTransfer && event.dataTransfer.files) addFiles(event.dataTransfer.files);
  });

  document.getElementById('upload-btn').addEventListener('click', () => upload(true));
  document.getElementById('upload-only-btn').addEventListener('click', () => upload(false));

  document.getElementById('preset-select').addEventListener('change', (event) => {
    const preset = (catalog.presets || []).find((p) => p.label === event.target.value);
    if (preset && preset.available) {
      const select = document.getElementById('model-select');
      if ([...select.options].some((o) => o.value === preset.model)) select.value = preset.model;
    }
  });

  // Eliminar un analisis desde la lista.
  document.querySelectorAll('[data-delete]').forEach((button) => {
    button.addEventListener('click', async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const id = button.dataset.delete;
      const name = button.dataset.name || id;
      const confirmado = window.confirm(
        `¿Eliminar el análisis "${name}"?\n\n` +
        `Se borrarán de forma permanente los logs cargados, las métricas, ` +
        `el informe y los archivos exportados.`
      );
      if (!confirmado) return;
      button.disabled = true;
      try {
        await LS.api(`/api/analysis/${id}`, { method: 'DELETE' });
        button.closest('.analysis-row')?.remove();
        const restante = document.querySelectorAll('.analysis-row').length;
        if (!restante) {
          const lista = document.getElementById('analyses-list');
          if (lista) {
            lista.innerHTML =
              '<div class="empty">Todavia no hay analisis.<br>Sube un conjunto de logs para empezar.</div>';
          }
        }
      } catch (err) {
        button.disabled = false;
        window.alert(`No se pudo eliminar: ${err.message}`);
      }
    });
  });
}

loadCatalog().then(wire);
