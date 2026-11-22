/* LogScope - logica de la pagina de analisis */

var LS = window.LOGSCOPE;
const analysisId = LS.analysisId;

let eventsOffset = 0;
let eventsLimit = 200;
let eventsTotal = 0;
let report = null;

/* ------------------------------------------------------------------ arranque */
async function boot() {
  const catalog = await LS.loadCatalog();
  LS.populateModelSelect(document.getElementById('model-select'), catalog, LS.defaultModel);
  LS.populateModelSelect(document.getElementById('chat-model'), catalog, LS.defaultModel);
  await loadData();
  await loadTimeline();
  await loadEvents(true);
  await loadConcordance();
  await loadVerificacion();
  await loadTrazabilidad();
  wire();
  wireConcordance();
}

/* -------------------------------------------------------------------- datos */
async function loadData() {
  const data = await LS.api(`/api/analysis/${analysisId}`);
  const metrics = data.metrics || {};
  const integrity = data.integrity || {};
  const meta = data.meta || {};

  document.getElementById('s-events').textContent = (metrics.events ?? 0).toLocaleString('es-ES');
  document.getElementById('s-events-note').textContent =
    Object.entries(metrics.by_source || {}).map(([k, v]) => `${k} ${v}`).join(' · ');

  const detection = metrics.detection || {};
  document.getElementById('s-mttd').textContent = detection.mttd_median_human || 'n/d';
  document.getElementById('s-mttd-note').textContent =
    `${detection.alerts_with_correlated_signal ?? 0}/${detection.alerts ?? 0} alertas con senal correlacionada`;

  document.getElementById('s-dwell').textContent = (metrics.dwell && metrics.dwell.human) || 'n/d';
  document.getElementById('s-dwell-note').textContent = (metrics.dwell && metrics.dwell.first_signal)
    ? `desde ${metrics.dwell.first_signal.slice(0, 16).replace('T', ' ')}` : '&nbsp;';

  const off = metrics.off_hours || {};
  document.getElementById('s-night').textContent = `${Math.round((off.ratio || 0) * 100)}%`;
  document.getElementById('s-night-note').textContent = `${off.total ?? 0} eventos entre 00:00 y 06:59`;

  const badge = document.getElementById('sev-badge');
  badge.textContent = meta.severity || 'INFO';
  badge.className = `badge ${meta.severity || 'INFO'}`;

  const runBadge = document.getElementById('run-badge');
  const runStatus = (data.run && data.run.status) || meta.status || 'idle';
  runBadge.textContent = runStatus;
  runBadge.className = `badge ${runStatus === 'done' ? 'ok' : (runStatus === 'running' ? 'running' : (runStatus === 'error' ? 'failed' : 'pending'))}`;

  const runButton = document.getElementById('run-btn');
  if (runButton) {
    const busy = runStatus === 'running';
    runButton.disabled = busy;
    runButton.textContent = busy ? 'Analizando...' : 'Ejecutar analisis';
  }

  const sources = Object.entries(metrics.by_source || {});
  const select = document.getElementById('f-source');
  sources.forEach(([name, count]) => {
    const option = document.createElement('option');
    option.value = name;
    option.textContent = `${name} (${count})`;
    select.appendChild(option);
  });

  if (data.report) {
    report = data.report;
    renderReport(report);
  }
  renderIntegrity(integrity);
  renderState(data);
}

async function loadTimeline() {
  const data = await LS.api(`/api/analysis/${analysisId}/timeline`);
  LS.renderTimelineChart(document.getElementById('chart-timeline'), data.timeline);
  LS.renderHoursChart(document.getElementById('chart-hours'), data.hours);
}

/* ------------------------------------------------------------------ eventos */
async function loadEvents(reset) {
  if (reset) { eventsOffset = 0; }
  const params = new URLSearchParams({
    source: document.getElementById('f-source').value,
    severity: document.getElementById('f-severity').value,
    off_hours: document.getElementById('f-night').checked ? 'true' : 'false',
    query: document.getElementById('f-query').value,
    limit: String(eventsLimit),
    offset: String(eventsOffset)
  });
  const data = await LS.api(`/api/analysis/${analysisId}/events?${params}`);
  eventsTotal = data.total;
  const tbody = document.querySelector('#events-table tbody');
  if (reset) tbody.innerHTML = '';
  for (const event of data.events) {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="ts">${LS.escape((event.iso_local || event.iso_utc || '').replace('T', ' '))}</td>
      <td><span class="tag">${LS.escape(event.source_type)}</span></td>
      <td class="mono">${LS.escape(event.event_id)}</td>
      <td><span class="badge ${LS.escape(event.severity)}">${LS.escape(event.severity)}</span></td>
      <td class="mono">${LS.escape(event.actor || '-')}</td>
      <td class="mono">${LS.escape(event.src_ip || '-')}</td>
      <td class="mono">${LS.escape(event.dst_ip || event.host || '-')}${event.dst_port ? ':' + event.dst_port : ''}</td>
      <td class="small">${LS.escape(event.event_type || '-')}</td>
      <td class="small muted">${LS.escape(event.detail || '')}</td>`;
    tbody.appendChild(row);
  }
  eventsOffset += data.events.length;
  document.getElementById('c-events').textContent = eventsTotal;
  document.getElementById('events-count').textContent =
    `${eventsOffset} de ${eventsTotal} eventos mostrados`;
  document.getElementById('events-more').classList.toggle('hide', eventsOffset >= eventsTotal);
}

/* ------------------------------------------------------------- integridad */
function renderIntegrity(integrity) {
  const correlation = (integrity.siem_correlation) || {};
  const container = document.getElementById('quality');
  const blocks = [];

  const add = (title, items) => {
    if (!items || !items.length) return;
    blocks.push(`<h3 class="mt-2">${LS.escape(title)}</h3><ul class="small muted">${
      items.map((i) => `<li>${LS.escape(typeof i === 'string' ? i : JSON.stringify(i))}</li>`).join('')}</ul>`);
  };

  add('Referencias de alerta sin resolver', (correlation.unresolved_placeholders || [])
    .map((u) => `${u.alert_id} -> ${u.reference}`));
  add('Referencias a eventos inexistentes', (correlation.missing_references || [])
    .map((u) => `${u.alert_id} -> ${u.reference}`));
  add('Referencias a eventos benignos', (correlation.benign_citations || [])
    .map((u) => `${u.alert_id} -> ${u.reference} (${u.referenced_event_type})`));
  add('Tactica incoherente con la tecnica', ((integrity.tactic_technique || {}).mismatches || [])
    .map((m) => `${m.alert_id}: ${m.technique_id} ${m.technique_name} declarado ${m.declared_tactic}, esperado ${m.expected_tactics.join('/')}`));
  add('Flujos imposibles (origen = destino)', (integrity.self_flows || [])
    .map((f) => `${f.event_id} en ${f.ip}`));
  add('Direcciones internas sin activo en el inventario', (integrity.asset_inventory || {}).orphan_internal_ips || []);
  add('Detecciones sin usuario atribuido', (integrity.unattributed_detections || [])
    .map((u) => `${u.event_id} (${u.severity})`));
  add('Direcciones IP con varios usuarios', (integrity.shared_source_ips || [])
    .map((s) => `${s.ip}: ${s.users.join(', ')}`));

  container.innerHTML = blocks.length ? blocks.join('') : '<div class="empty">Sin incidencias de calidad.</div>';
}

/* ------------------------------------------------------------------ estado */
function renderState(data) {
  const banner = document.getElementById('state-banner');
  if (!banner) return;
  const run = data.run || {};
  const hasReport = Boolean(data.report);
  const meta = data.meta || {};

  banner.classList.remove('hide', 'warn', 'err', 'ok');

  if (run.status === 'running') {
    if (hasReport) {
      banner.classList.add('ok');
      banner.innerHTML = `<b>Informe ya disponible</b> (severidad `
        + `<b>${LS.escape((data.report && data.report.severity_overall) || 'INFO')}</b>). `
        + `El agente sigue afinandolo; la vista se actualizara sola.`;
    } else {
      banner.classList.add('warn');
      banner.innerHTML = `<span class="spinner"></span> <b>Analisis en curso</b> con el modelo `
        + `<code>${LS.escape(run.model || '')}</code>. El agente esta leyendo los logs; `
        + `puede tardar varios minutos. Las pestañas de hallazgos se rellebaran al terminar.`;
    }
    return;
  }
  if (run.status === 'error') {
    banner.classList.add('err');
    banner.innerHTML = `<b>El analisis termino con error:</b> ${LS.escape(run.error || 'sin detalle')}`
      + `<br>Puedes volver a lanzarlo con el boton de arriba.`;
    return;
  }
  if (!hasReport) {
    banner.classList.add('warn');
    banner.innerHTML = `<b>Todavia no hay informe.</b> Los ${meta.events || 0} eventos ya estan `
      + `indexados y las metricas calculadas, pero los hallazgos, el mapeo ATT&amp;CK, la revision `
      + `de las reglas SIEM y los IOCs los genera el agente de opencode: pulsa `
      + `<b>Ejecutar analisis</b>.`;
    return;
  }
  if (meta.status === 'done') {
    banner.classList.add('ok');
    const modelo = meta.model ? ` por <code>${LS.escape(meta.model)}</code>` : '';
    banner.innerHTML = `Informe generado${modelo}. Severidad global `
      + `<b>${LS.escape(meta.severity || 'INFO')}</b>.`;
  }
}

/* ------------------------------------------------------------- trazabilidad */
async function loadTrazabilidad() {
  let data;
  try {
    data = await LS.api(`/api/analysis/${analysisId}/traceability`);
  } catch (err) {
    return;
  }
  renderTrazabilidad(data);
}

function renderTrazabilidad(data) {
  const resumen = data.resumen || {};
  document.getElementById('c-trazabilidad').textContent = resumen.alertas_con_hallazgo || 0;

  const tarjetas = [
    { k: 'Alertas del SIEM', v: resumen.alertas || 0, n: `${resumen.alertas_sin_hallazgo || 0} sin hallazgo asociado` },
    { k: 'Verdaderas', v: resumen.verdaderos_positivos || 0, n: 'con señal que las respalda' },
    { k: 'Falsos positivos', v: resumen.falsos_positivos || 0, n: 'sin señal en los registros' },
    { k: 'Hallazgos', v: resumen.hallazgos || 0, n: `${resumen.hallazgos_sin_alerta || 0} sin alerta que los sustente` },
  ];
  document.getElementById('tra-stats').innerHTML = tarjetas.map((t) => `
    <div class="stat">
      <div class="stat-label">${LS.escape(t.k)}</div>
      <div class="stat-value">${LS.escape(String(t.v))}</div>
      <div class="stat-note">${LS.escape(t.n)}</div>
    </div>`).join('');

  const estadoClase = {
    'válida': 'ok', 'evento benigno': 'pending', 'no resoluble': 'failed', 'inexistente': 'failed', 'no encontrada': 'failed',
  };
  const cuerpo = document.querySelector('#tra-table tbody');
  cuerpo.innerHTML = (data.alertas || []).map((f) => {
    const refs = (f.referencias || []).map((r) => `
      <span class="tag ${estadoClase[r.estado] || 'info'}" title="${LS.escape(r.tipo || '')} ${LS.escape(r.instante || '')}">${LS.escape(r.referencia)}</span>
      <span class="small muted">${LS.escape(r.estado)}</span>`).join('<br>');
    const hall = (f.hallazgos || []).map((h) => `
      <span class="tag evidence">${LS.escape(h.id)}</span>
      <span class="small muted">${LS.escape(h.por_que)}</span>`).join('<br>') || '<span class="small muted">—</span>';
    const noal = (f.hechos_no_alertados || []).map((c) => `
      <span class="tag">${LS.escape(c.evento)}</span>
      <span class="small muted">+${c.minutos} min · ${LS.escape(c.tipo)}</span>`).join('<br>') || '<span class="small muted">—</span>';
    const veredicto = f.veredicto || '';
    const clase = { 'VERDADERO POSITIVO': 'ok', 'VERDADERO POSITIVO CON EVIDENCIA DEFICIENTE': 'pending', 'FALSO POSITIVO': 'failed' }[veredicto] || 'info';
    const etiqueta = veredicto ? `<span class="badge ${clase}">${LS.escape(veredicto)}</span>` : '<span class="small muted">—</span>';
    const motivos = (f.motivos || []).length
      ? `<div class="small muted" style="margin-top:3px">${LS.escape((f.motivos || []).join('; '))}</div>`
      : '';
    const noalMarcado = (f.hechos_no_alertados || []).map((c) => `
      <span class="badge failed" style="margin-right:4px">falso negativo</span>
      <span class="tag">${LS.escape(c.evento)}</span>
      <span class="small muted">+${c.minutos} min · ${LS.escape(c.tipo)}</span>`).join('<br>') || '<span class="small muted">—</span>';
    return `<tr>
      <td class="mono">${LS.escape(f.alerta)}<div class="small muted">${LS.escape(f.tecnica || '')}</div></td>
      <td class="small">${etiqueta}${motivos}</td>
      <td class="small">${refs}</td>
      <td class="small">${hall}</td>
      <td class="small">${noalMarcado}</td>
    </tr>`;
  }).join('');

  document.querySelector('#tra-hallazgos tbody').innerHTML = (data.hallazgos || []).map((h) => `
    <tr>
      <td class="mono">${LS.escape(h.id)}</td>
      <td><span class="badge ${h.severidad === 'CRITICAL' ? 'CRITICAL' : (h.severidad === 'HIGH' ? 'HIGH' : (h.severidad === 'MEDIUM' ? 'MEDIUM' : 'INFO'))}">${LS.escape(h.severidad)}</span></td>
      <td class="small">${LS.escape(h.titulo)}</td>
      <td class="small mono">${(h.alertas || []).map(LS.escape).join(', ') || '—'}</td>
    </tr>`).join('');
}

/* ------------------------------------------------------------- verificacion */
const VEREDICTO_CLASE = {
  'VERDADERO POSITIVO': 'ok',
  'VERDADERO POSITIVO CON EVIDENCIA DEFICIENTE': 'pending',
  'FALSO POSITIVO': 'failed',
};

async function loadVerificacion() {
  let data;
  try {
    data = await LS.api(`/api/analysis/${analysisId}/verification`);
  } catch (err) {
    return;
  }
  renderVerificacion(data);
}

function renderVerificacion(data) {
  const resumen = data.alertas || {};
  document.getElementById('c-verificacion').textContent = resumen.falsos_positivos || 0;

  const tarjetas = [
    { k: 'Alertas analizadas', v: resumen.total || 0, n: 'del SIEM' },
    { k: 'Verdaderos positivos', v: resumen.verdaderos_positivos || 0, n: 'con señal y evidencia válida' },
    {
      k: 'Con evidencia deficiente',
      v: resumen.verdaderos_con_evidencia_deficiente || 0,
      n: 'verdaderas, pero mal correlacionadas',
    },
    { k: 'Falsos positivos', v: resumen.falsos_positivos || 0, n: 'sin señal que las respalde' },
  ];
  document.getElementById('ver-stats').innerHTML = tarjetas.map((t) => `
    <div class="stat">
      <div class="stat-label">${LS.escape(t.k)}</div>
      <div class="stat-value">${LS.escape(String(t.v))}</div>
      <div class="stat-note">${LS.escape(t.n)}</div>
    </div>`).join('');

  const cuerpo = document.querySelector('#ver-table tbody');
  cuerpo.innerHTML = (data.detalle || []).map((f) => {
    const clase = VEREDICTO_CLASE[f.veredicto] || 'info';
    let refs = `${f.referencias_validas.length} válida(s)`;
    if (f.referencias_no_resolubles.length) {
      refs += ` · ${f.referencias_no_resolubles.length} sin resolver`;
    }
    if (f.referencias_benignas.length) {
      refs += ` · ${f.referencias_benignas.length} benigna(s)`;
    }
    return `<tr>
      <td class="mono">${LS.escape(f.alerta)}</td>
      <td><span class="badge ${clase}">${LS.escape(f.veredicto)}</span></td>
      <td class="mono">${LS.escape(f.severidad_declarada)}</td>
      <td class="small">${f.senal ? `<span class="tag evidence">${LS.escape(f.senal_tipo)}</span> ${LS.escape(f.senal_evento)}` : '<span class="tag">ninguna</span>'}</td>
      <td class="small mono">${LS.escape(refs)}</td>
      <td class="small muted">${LS.escape((f.motivos || []).join('; ') || '—')}</td>
    </tr>`;
  }).join('');
  document.getElementById('ver-verdict-sub').textContent =
    `${resumen.tasa_verificacion !== undefined ? Math.round(resumen.tasa_verificacion * 100) : 0} % de las alertas tienen respaldo en los registros`;

  const fn = data.falsos_negativos || [];
  document.querySelector('#ver-fn tbody').innerHTML = fn.map((f) => `
    <tr>
      <td class="mono">${LS.escape(f.evento)}</td>
      <td class="ts">${LS.escape((f.instante || '').replace('T', ' '))}</td>
      <td><span class="badge ${f.severidad === 'CRITICAL' ? 'CRITICAL' : (f.severidad === 'HIGH' ? 'HIGH' : 'INFO')}">${LS.escape(f.severidad)}</span></td>
      <td class="small">${LS.escape(f.tipo)}</td>
      <td class="small muted">${LS.escape(f.detalle || '')}</td>
      <td class="small muted">${LS.escape(f.motivo || '')}</td>
    </tr>`).join('');
  document.getElementById('ver-fn-sub').textContent = `${fn.length} hechos sin alerta`;
}

/* ------------------------------------------------------------ conciliacion */
async function loadConcordance() {
  try {
    const data = await LS.api(`/api/analysis/${analysisId}/concordance`);
    if (!data.ok) {
      document.getElementById('concordance-empty').classList.remove('hide');
      document.getElementById('concordance-result').classList.add('hide');
      return;
    }
    renderConcordance(data);
  } catch (err) {
    /* sin conciliacion: se mantiene el estado vacio */
  }
}

function renderConcordance(data) {
  const resumen = data.resumen || {};
  document.getElementById('concordance-empty').classList.add('hide');
  document.getElementById('concordance-result').classList.remove('hide');
  document.getElementById('c-concordance').textContent = resumen.concordantes || 0;
  if (typeof activarDescarga === 'function') activarDescarga();

  const porcentaje = Math.round((resumen.tasa_concordancia || 0) * 100);
  const delta = resumen.delta_maximo;
  const tarjetas = [
    { k: 'Combinaciones del IDS', v: resumen.combinaciones_ids || 0, n: `${resumen.alertas_ids || 0} alertas en total` },
    { k: 'Concordantes', v: `${resumen.concordantes || 0} (${porcentaje} %)`, n: `${resumen.firmas_concordantes || 0} de ${resumen.firmas_ids || 0} firmas` },
    { k: 'Desfase máximo', v: delta === null || delta === undefined ? 'n/d' : `${delta} s`, n: `ventana de ${resumen.ventana_concordancia || 120} s` },
    { k: 'Solo en el registro', v: (data.anomalias_solo_logscope || []).length, n: 'anomalías que el IDS no puede ver' },
  ];
  document.getElementById('conc-stats').innerHTML = tarjetas.map((t) => `
    <div class="stat">
      <div class="stat-label">${LS.escape(t.k)}</div>
      <div class="stat-value">${LS.escape(String(t.v))}</div>
      <div class="stat-note">${LS.escape(t.n)}</div>
    </div>`).join('');

  const cuerpo = document.querySelector('#conc-table tbody');
  cuerpo.innerHTML = (data.por_firma || []).map((f) => `
    <tr>
      <td class="mono">${LS.escape(f.firma)}</td>
      <td>${LS.escape(f.nombre || '')}</td>
      <td class="small muted">${LS.escape(f.criterio || '')}</td>
      <td class="mono">${f.combinaciones}</td>
      <td class="mono">${f.concordantes}</td>
      <td class="mono">${f.alertas}</td>
      <td><span class="badge ${f.estado === 'coincide' ? 'ok' : 'pending'}">${LS.escape(f.estado)}</span></td>
    </tr>`).join('');

  const detalle = document.querySelector('#conc-detail tbody');
  detalle.innerHTML = (data.detalle || []).map((d) => `
    <tr>
      <td class="mono">${LS.escape(d.firma)}</td>
      <td class="mono">${LS.escape(d.origen)}</td>
      <td class="mono">${LS.escape(d.destino)}</td>
      <td class="mono small">${LS.escape(d.primera_deteccion_ids || '')}</td>
      <td class="mono small">${LS.escape(d.evento_log || '-')}</td>
      <td class="mono small">${LS.escape((d.instante_log || '').replace('T', ' '))}</td>
      <td class="mono">${d.delta_segundos === null || d.delta_segundos === undefined ? '-' : d.delta_segundos + ' s'}</td>
      <td class="small">${LS.escape(d.estado)}</td>
    </tr>`).join('');
  document.getElementById('conc-detail-sub').textContent =
    `${data.fichero || 'log del IDS'} · formato ${data.formato || '-'}`;

  const sinConcordar = (resumen.firmas_sin_concordancia || []);
  document.getElementById('conc-caveat').innerHTML =
    '<b>Alcance de la validación.</b> La concordancia entre ambos instrumentos ' +
    'acredita la coherencia interna de dos metodologías de análisis sobre el mismo ' +
    'material, no una confirmación independiente del hecho: el origen de los datos es común. ' +
    'La validación tampoco es simétrica: el IDS coincide en todo lo que ocurre en la red, ' +
    'pero no puede ver los hallazgos de registro —flujos imposibles, direcciones sin ' +
    'activo asociado, correlaciones no resolubles del SIEM o saltos sin evidencia entre ' +
    'hosts—, que son precisamente los que aporta el análisis del registro.' +
    (sinConcordar.length ? ` Firmas del IDS sin concordancia: ${sinConcordar.join(', ')}.` : '');
}

function activarDescarga() {
  const botonCopiar = document.getElementById('ids-copy');
  const botonMd = document.getElementById('ids-md');
  if (!botonCopiar || !botonMd) return;
  botonCopiar.disabled = false;
  botonMd.hidden = false;
  botonMd.href = `/api/analysis/${analysisId}/concordance.md`;
  botonMd.download = `${analysisId}-conciliacion.md`;
}

function wireConcordance() {
  const input = document.getElementById('ids-file');
  const boton = document.getElementById('ids-upload');
  const estado = document.getElementById('ids-status');
  const botonCopiar = document.getElementById('ids-copy');
  const botonMd = document.getElementById('ids-md');

  document.getElementById('ids-pick').addEventListener('click', () => input.click());
  input.addEventListener('change', () => {
    const archivo = input.files && input.files[0];
    boton.disabled = !archivo;
    document.getElementById('ids-file-name').textContent = archivo ? archivo.name : '';
  });

  botonCopiar.addEventListener('click', async () => {
    try {
      const respuesta = await fetch(`/api/analysis/${analysisId}/concordance.md`);
      const texto = await respuesta.text();
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(texto);
        estado.innerHTML = '<span style="color:var(--success)">informe copiado al portapapeles</span>';
      } else {
        // Sin portapapeles seguro: se muestra el texto para copiar a mano.
        const area = document.createElement('textarea');
        area.value = texto;
        area.style.cssText = 'width:100%;height:220px;margin-top:8px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:var(--mono);font-size:12px';
        area.id = 'ids-textarea';
        document.getElementById('ids-file-name').after(area);
        area.focus();
        area.select();
        estado.innerHTML = '<span style="color:var(--medium)">texto seleccionado: copiala con Ctrl+C</span>';
      }
    } catch (err) {
      estado.innerHTML = `<span style="color:var(--critical)">${LS.escape(err.message)}</span>`;
    }
  });

  boton.addEventListener('click', async () => {
    const archivo = input.files && input.files[0];
    if (!archivo) return;
    const form = new FormData();
    form.append('file', archivo, archivo.name);
    boton.disabled = true;
    estado.innerHTML = '<span class="spinner"></span> conciliando...';
    try {
      const data = await LS.api(`/api/analysis/${analysisId}/concordance`, {
        method: 'POST',
        body: form,
      });
      renderConcordance(data);
      const r = data.resumen || {};
      estado.innerHTML =
        `<span style="color:var(--success)">${r.concordantes}/${r.combinaciones_ids} combinaciones concordantes ` +
        `(${Math.round((r.tasa_concordancia || 0) * 100)} %)</span>`;
      activarDescarga();
    } catch (err) {
      estado.innerHTML = `<span style="color:var(--critical)">${LS.escape(err.message)}</span>`;
    }
    boton.disabled = false;
  });
}

/* ---------------------------------------------------------------- informe */
function renderReport(data) {
  report = data;

  document.getElementById('c-findings').textContent = (data.findings || []).length;
  document.getElementById('c-attack').textContent = (data.mitre_attack || []).length;
  document.getElementById('c-siem').textContent = (data.siem_rule_review || []).length;
  document.getElementById('c-iocs').textContent = (data.iocs || []).length;
  document.getElementById('findings-sub').textContent = `${(data.findings || []).length} hallazgos`;
  document.getElementById('chain-count').textContent = `${(data.attack_chain || []).length} fases`;

  // Cadena
  const chain = document.getElementById('chain');
  if ((data.attack_chain || []).length) {
    chain.innerHTML = data.attack_chain.map((step) => `
      <div class="timeline-row">
        <div class="timeline-when"><span class="ts">${LS.escape((step.ts || '').slice(0, 16).replace('T', ' '))}</span></div>
        <div class="timeline-phase"><span class="badge INFO">${LS.escape(step.phase || '')}</span></div>
        <div class="timeline-body">
          <h4>${LS.escape(step.title || '')}</h4>
          <div class="small muted">${LS.escape(step.description || '')}</div>
          <div class="row row-tight mt-1">
            ${(step.techniques || []).map((t) => `<span class="tag technique">${LS.escape(t)}</span>`).join('')}
            ${(step.evidence || []).map((e) => `<span class="tag evidence">${LS.escape(e)}</span>`).join('')}
          </div>
        </div>
      </div>`).join('');
  }

  // Hallazgos
  const findings = document.getElementById('findings');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const sorted = [...(data.findings || [])].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  findings.innerHTML = sorted.length ? sorted.map((f) => `
    <div class="finding ${LS.escape(f.severity)}">
      <div class="finding-head">
        <span class="badge ${LS.escape(f.severity)}">${LS.escape(f.severity)}</span>
        <span class="finding-title">${LS.escape(f.id || '')} ${LS.escape(f.title || '')}</span>
        ${f.category ? `<span class="tag">${LS.escape(f.category)}</span>` : ''}
      </div>
      <div class="finding-body">${LS.renderMarkdown(f.description || '')}</div>
      <dl class="kv">
        ${f.impact ? `<dt>Impacto</dt><dd>${LS.escape(f.impact)}</dd>` : ''}
        ${f.recommendation ? `<dt>Recomendacion</dt><dd>${LS.escape(f.recommendation)}</dd>` : ''}
        ${(f.techniques || []).length ? `<dt>ATT&amp;CK</dt><dd>${f.techniques.map(LS.escape).join(', ')}</dd>` : ''}
        ${(f.evidence || []).length ? `<dt>Evidencia</dt><dd>${f.evidence.map((e) => `<span class="tag evidence">${LS.escape(e)}</span>`).join(' ')}</dd>` : ''}
      </dl>
    </div>`).join('') : '<div class="empty">Sin hallazgos.</div>';

  // Recomendaciones
  const recs = document.getElementById('recommendations');
  const sortedRecs = [...(data.recommendations || [])].sort((a, b) => (a.priority || 99) - (b.priority || 99));
  recs.innerHTML = sortedRecs.length ? sortedRecs.map((r) => `
    <div class="finding INFO">
      <div class="finding-head">
        <span class="badge INFO">${LS.escape(String(r.priority || ''))}</span>
        <span class="finding-title">${LS.escape(r.action || '')}</span>
        <span class="tag">esfuerzo: ${LS.escape(r.effort || '')}</span>
      </div>
      <div class="finding-body">${LS.renderMarkdown(r.rationale || '')}</div>
      ${(r.references || []).length ? `<div class="row row-tight mt-1">${r.references.map((x) => `<span class="tag evidence">${LS.escape(x)}</span>`).join('')}</div>` : ''}
    </div>`).join('') : '<div class="empty">Sin recomendaciones.</div>';

  // ATT&CK
  const attackBody = document.querySelector('#attack-table tbody');
  attackBody.innerHTML = (data.mitre_attack || []).map((entry) => `
    <tr><td class="mono">${LS.escape(entry.technique_id)}</td><td>${LS.escape(entry.technique_name || '')}</td>
    <td>${LS.escape((entry.tactics || []).join(', '))}</td>
    <td>${(entry.evidence || []).map((e) => `<span class="tag evidence">${LS.escape(e)}</span>`).join(' ')}</td>
    <td>${LS.escape(entry.confidence || '')}</td></tr>`).join('')
    || '<tr><td colspan="5" class="empty">Sin mapeo.</td></tr>';

  // SIEM
  const siemBody = document.querySelector('#siem-table tbody');
  siemBody.innerHTML = (data.siem_rule_review || []).map((issue) => `
    <tr><td class="mono">${LS.escape(issue.alert_id || '')}</td>
    <td class="small">${LS.escape(issue.issue || '')}</td>
    <td><span class="badge ${LS.escape(issue.severity || 'MEDIUM')}">${LS.escape(issue.severity || '')}</span></td>
    <td class="mono small">${LS.escape(issue.suggested_technique || '')} ${LS.escape(issue.suggested_tactic || '')}</td>
    <td>${(issue.evidence || []).map((e) => `<span class="tag evidence">${LS.escape(e)}</span>`).join(' ')}</td></tr>`).join('')
    || '<tr><td colspan="5" class="empty">Sin revisiones.</td></tr>';

  // IOCs
  const iocBody = document.querySelector('#iocs-table tbody');
  iocBody.innerHTML = (data.iocs || []).map((ioc) => `
    <tr><td>${LS.escape(ioc.type || '')}</td><td class="mono">${LS.escape(ioc.value || '')}</td>
    <td class="small muted">${LS.escape(ioc.context || '')}</td>
    <td class="ts">${LS.escape((ioc.first_seen || '').slice(0, 16).replace('T', ' '))}</td>
    <td>${LS.escape(ioc.confidence || '')}</td></tr>`).join('')
    || '<tr><td colspan="5" class="empty">Sin IOCs.</td></tr>';

  // Huecos y calidad
  const gaps = document.getElementById('gaps');
  gaps.innerHTML = (data.telemetry_gaps || []).length
    ? `<ul class="small muted">${data.telemetry_gaps.map((g) => `<li>${LS.escape(g)}</li>`).join('')}</ul>`
    : '<div class="empty">Sin huecos documentados.</div>';

  const summary = document.getElementById('summary-text');
  summary.innerHTML = LS.renderMarkdown(
    `${data.summary || ''}\n\n${data.executive_summary || ''}\n\n${(data.metrics_review && data.metrics_review.comment) || ''}`
  );

  const sev = document.getElementById('sev-badge');
  sev.textContent = data.severity_overall || 'INFO';
  sev.className = `badge ${data.severity_overall || 'INFO'}`;
}

/* ------------------------------------------------------------- ejecucion */
async function runAnalysis() {
  const button = document.getElementById('run-btn');
  const panel = document.getElementById('run-panel');
  const consoleBox = document.getElementById('console');
  const model = document.getElementById('model-select').value;

  button.disabled = true;
  button.textContent = 'Analizando...';
  panel.classList.remove('hide');
  consoleBox.innerHTML = '';
  const write = (cls, text) => {
    const line = document.createElement('div');
    line.className = cls;
    line.textContent = text;
    consoleBox.appendChild(line);
    consoleBox.scrollTop = consoleBox.scrollHeight;
  };
  write('info', `> modelo: ${model}`);
  write('info', `> conectando con el stream de opencode...`);

  const source = new EventSource(`/api/analysis/${analysisId}/stream`);

  source.addEventListener('status', (event) => {
    const data = JSON.parse(event.data);
    write('info', data.text);
    if (data.text && data.text.includes('modelo')) {
      document.getElementById('run-model').textContent = data.text;
    }
  });
  source.addEventListener('warning', (event) => {
    const data = JSON.parse(event.data);
    write('warn', `! ${data.text}`);
  });
  source.addEventListener('report', async (event) => {
    const data = JSON.parse(event.data);
    write('ok', `> ${data.text}`);
    // El informe ya es valido: se recargan los datos para pintarlo.
    await loadData();
  });
  source.addEventListener('error', (event) => {
    try {
      const data = JSON.parse(event.data);
      write('err', `x ${data.text}`);
    } catch (err) { write('err', 'x error en el stream'); }
  });
  source.addEventListener('assistant', (event) => {
    const data = JSON.parse(event.data);
    write('', data.text);
  });
  source.addEventListener('done', async () => {
    source.close();
    write('ok', '> analisis completado, recargando datos...');
    button.disabled = false;
    button.textContent = 'Ejecutar analisis';
    await loadData();
    await loadTimeline();
  });
  source.addEventListener('done', async (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.status === 'error') write('err', '> el analisis termino con error');
    } catch (err) { /* ignorar */ }
  });

  try {
    await LS.api(`/api/analysis/${analysisId}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model })
    });
  } catch (err) {
    write('err', `x ${err.message}`);
    button.disabled = false;
    button.textContent = 'Ejecutar analisis';
    source.close();
  }
}

/* ------------------------------------------------------------------- chat */
async function sendChat() {
  const input = document.getElementById('chat-text');
  const chat = document.getElementById('chat');
  const text = input.value.trim();
  if (!text) return;

  const user = document.createElement('div');
  user.className = 'msg user';
  user.textContent = text;
  chat.appendChild(user);
  input.value = '';

  const bot = document.createElement('div');
  bot.className = 'msg bot';
  chat.appendChild(bot);
  chat.scrollTop = chat.scrollHeight;

  const model = document.getElementById('chat-model').value;
  try {
    const response = await fetch(`/api/analysis/${analysisId}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, model })
    });
    if (!response.ok) throw new Error(`${response.status}`);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let accumulated = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const chunks = buffer.split('\n\n');
      buffer = chunks.pop() || '';
      for (const chunk of chunks) {
        const line = chunk.split('\n').find((l) => l.startsWith('data: '));
        if (!line) continue;
        const payload = JSON.parse(line.slice(6));
        if (payload.kind === 'assistant') {
          accumulated = payload.text;
          bot.innerHTML = LS.renderMarkdown(accumulated);
          chat.scrollTop = chat.scrollHeight;
        } else if (payload.error) {
          bot.textContent = `Error: ${payload.error}`;
        }
      }
    }
  } catch (err) {
    bot.textContent = `Error: ${err.message}`;
  }
}

/* ------------------------------------------------------------------ wiring */
function activateTab(name) {
  const tab = document.querySelector(`#tabs .tab[data-tab="${name}"]`);
  if (!tab) return;
  document.querySelectorAll('#tabs .tab').forEach((t) => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
  tab.classList.add('active');
  const panel = document.getElementById(`panel-${name}`);
  if (panel) panel.classList.add('active');
}

function wire() {
  document.querySelectorAll('#tabs .tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      activateTab(tab.dataset.tab);
      // Enlace profundo: permite compartir una pestana concreta.
      window.history.replaceState(null, '', `#${tab.dataset.tab}`);
    });
  });

  // Pestana inicial desde el hash de la URL.
  const initial = (window.location.hash || '').replace('#', '');
  if (initial) activateTab(initial);
  window.addEventListener('hashchange', () => {
    const name = (window.location.hash || '').replace('#', '');
    if (name) activateTab(name);
  });

  document.getElementById('run-btn').addEventListener('click', runAnalysis);
  document.getElementById('events-more').addEventListener('click', () => loadEvents(false));

  ['f-source', 'f-severity'].forEach((id) => {
    document.getElementById(id).addEventListener('change', () => loadEvents(true));
  });
  document.getElementById('f-night').addEventListener('change', () => loadEvents(true));
  let timer = null;
  document.getElementById('f-query').addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => loadEvents(true), 320);
  });

  document.getElementById('chat-send').addEventListener('click', sendChat);
  document.getElementById('chat-text').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) sendChat();
  });

  const deleteButton = document.getElementById('delete-btn');
  if (deleteButton) {
    deleteButton.addEventListener('click', async () => {
      const name = document.querySelector('h1')?.textContent?.trim() || analysisId;
      const confirmado = window.confirm(
        `¿Eliminar el análisis "${name}"?\n\n` +
        `Se borrarán de forma permanente los logs cargados, las métricas, ` +
        `el informe y los archivos exportados. Esta acción no se puede deshacer.`
      );
      if (!confirmado) return;
      deleteButton.disabled = true;
      try {
        await LS.api(`/api/analysis/${analysisId}`, { method: 'DELETE' });
        window.location.href = '/';
      } catch (err) {
        deleteButton.disabled = false;
        window.alert(`No se pudo eliminar: ${err.message}`);
      }
    });
  }
}

boot().catch((err) => {
  console.error(err);
  const panel = document.getElementById('run-panel');
  if (panel) {
    panel.classList.remove('hide');
    panel.querySelector('.console').innerHTML =
      `<div class="err">No se pudo cargar el analisis: ${LS.escape(err.message)}</div>`;
  }
});
