/* LogScope - utilidades compartidas */

var LS = (window.LOGSCOPE = window.LOGSCOPE || {});

LS.api = async function (url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body && body.detail) detail = body.detail;
    } catch (err) { /* respuesta no JSON */ }
    throw new Error(detail);
  }
  return response.json();
};

LS.escape = function (value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
};

LS.fmtBytes = function (bytes) {
  const value = Number(bytes || 0);
  const units = ['B', 'KB', 'MB', 'GB'];
  let index = 0, size = value;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
  return `${size.toLocaleString('es-ES', { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
};

LS.severityColor = function (severity) {
  return {
    CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)',
    LOW: 'var(--low)', INFO: 'var(--info)'
  }[String(severity || 'INFO').toUpperCase()] || 'var(--info)';
};

LS.severityRank = function (severity) {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }[String(severity || 'INFO').toUpperCase()] || 0;
};

/* ------------------------------------------------------------------ health */
LS.refreshHealth = async function () {
  const dot = document.querySelector('#oc-status .status-dot');
  const text = document.getElementById('oc-status-text');
  if (!dot || !text) return;
  try {
    const health = await LS.api('/api/health');
    if (health.opencode.healthy) {
      dot.className = 'status-dot ok';
      text.textContent = `opencode ${health.opencode.version || ''} en marcha`;
    } else {
      dot.className = 'status-dot bad';
      text.textContent = 'opencode no disponible';
    }
  } catch (err) {
    dot.className = 'status-dot bad';
    text.textContent = 'sin conexion con el backend';
  }
};

/* ------------------------------------------------------------------ modelos */
LS.loadCatalog = async function () {
  try {
    return await LS.api('/api/models');
  } catch (err) {
    return { models: [], presets: [], meta: { status: 'error', message: String(err.message || err) } };
  }
};

LS.populateModelSelect = function (select, catalog, selected) {
  if (!select) return;
  select.innerHTML = '';
  const models = catalog.models || [];
  if (!models.length) {
    const option = document.createElement('option');
    option.textContent = catalog.meta && catalog.meta.message
      ? catalog.meta.message : 'sin modelos disponibles';
    option.value = '';
    select.appendChild(option);
    return;
  }
  const tiers = [
    ['free', 'Gratis'], ['low', 'Economico'], ['medium', 'Medio'], ['high', 'Alto']
  ];
  for (const [tier, label] of tiers) {
    const group = models.filter((m) => m.tier === tier);
    if (!group.length) continue;
    const optgroup = document.createElement('optgroup');
    optgroup.label = `${label} (${group.length})`;
    for (const model of group) {
      const option = document.createElement('option');
      option.value = model.full_id;
      const ctx = model.context ? `${(model.context / 1e6).toFixed(2)}M ctx` : '';
      const cost = model.cost_in || model.cost_out ? `$${model.cost_in}/${model.cost_out}` : 'gratis';
      option.textContent = `${model.model_id} · ${cost}${ctx ? ' · ' + ctx : ''}`;
      if (model.full_id === selected) option.selected = true;
      optgroup.appendChild(option);
    }
    select.appendChild(optgroup);
  }
  if (!select.value && selected) select.value = selected;
};

/* --------------------------------------------------------------- markdown */
LS.renderMarkdown = function (text) {
  if (window.marked) return window.marked.parse(text);
  // Fallback minimo: escapado + parrafos y negritas.
  return LS.escape(text)
    .replace(/\n\n/g, '</p><p>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`(.+?)`/g, '<code>$1</code>');
};

LS.renderReport = function (container, report) {
  const part = (title, body) => body ? `<h2>${LS.escape(title)}</h2>${LS.renderMarkdown(body)}` : '';
  let html = '';
  html += `<p class="row row-tight"><span class="badge ${LS.escape(report.severity_overall || 'INFO')}">${LS.escape(report.severity_overall || 'INFO')}</span>`;
  if (report.incident_type) html += `<span class="muted">${LS.escape(report.incident_type)}</span>`;
  html += '</p>';
  html += part('Resumen', report.summary);
  html += part('Resumen ejecutivo', report.executive_summary);

  if ((report.attack_chain || []).length) {
    html += '<h2>Cronologia del incidente</h2>';
    for (const step of report.attack_chain) {
      html += `<div class="timeline-row">
        <div class="timeline-when"><span class="ts">${LS.escape(step.ts || '')}</span></div>
        <div class="timeline-phase"><span class="badge INFO">${LS.escape(step.phase || '')}</span></div>
        <div class="timeline-body">
          <h4>${LS.escape(step.title || '')}</h4>
          <div class="small muted">${LS.escape(step.description || '')}</div>
          <div class="row row-tight mt-1">
            ${(step.techniques || []).map((t) => `<span class="tag technique">${LS.escape(t)}</span>`).join('')}
            ${(step.evidence || []).map((e) => `<span class="tag evidence">${LS.escape(e)}</span>`).join('')}
            <span class="tag">${LS.escape(step.confidence || '')}</span>
          </div>
        </div>
      </div>`;
    }
  }

  if ((report.findings || []).length) {
    html += '<h2>Hallazgos</h2>';
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    const sorted = [...report.findings].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
    for (const finding of sorted) {
      html += `<div class="finding ${LS.escape(finding.severity)}">
        <div class="finding-head">
          <span class="badge ${LS.escape(finding.severity)}">${LS.escape(finding.severity)}</span>
          <span class="finding-title">${LS.escape(finding.id || '')} ${LS.escape(finding.title || '')}</span>
        </div>
        <div class="finding-body">${LS.renderMarkdown(finding.description || '')}</div>
        <dl class="kv">
          ${finding.impact ? `<dt>Impacto</dt><dd>${LS.escape(finding.impact)}</dd>` : ''}
          ${finding.recommendation ? `<dt>Recomendacion</dt><dd>${LS.escape(finding.recommendation)}</dd>` : ''}
          ${finding.control_domain ? `<dt>Control</dt><dd>${LS.escape(finding.control_domain)}</dd>` : ''}
          ${(finding.techniques || []).length ? `<dt>ATT&amp;CK</dt><dd>${finding.techniques.map(LS.escape).join(', ')}</dd>` : ''}
          ${(finding.evidence || []).length ? `<dt>Evidencia</dt><dd>${finding.evidence.map((e) => `<span class="tag evidence">${LS.escape(e)}</span>`).join(' ')}</dd>` : ''}
        </dl>
      </div>`;
    }
  }

  if ((report.mitre_attack || []).length) {
    html += '<h2>Mapeo MITRE ATT&amp;CK</h2><table><thead><tr><th>Tecnica</th><th>Tactica</th><th>Evidencia</th><th>Confianza</th></tr></thead><tbody>';
    for (const entry of report.mitre_attack) {
      html += `<tr><td class="mono">${LS.escape(entry.technique_id)}</td><td>${LS.escape(entry.technique_name || '')}</td>
        <td>${LS.escape((entry.tactics || []).join(', '))}</td>
        <td>${(entry.evidence || []).map((e) => `<span class="tag evidence">${LS.escape(e)}</span>`).join(' ')}</td>
        <td>${LS.escape(entry.confidence || '')}</td></tr>`;
    }
    html += '</tbody></table>';
  }

  if ((report.siem_rule_review || []).length) {
    html += '<h2>Revision de las reglas de deteccion</h2><table><thead><tr><th>Alerta</th><th>Problema</th><th>Severidad</th><th>Tecnica sugerida</th></tr></thead><tbody>';
    for (const issue of report.siem_rule_review) {
      html += `<tr><td class="mono">${LS.escape(issue.alert_id || '')}</td><td>${LS.escape(issue.issue || '')}</td>
        <td><span class="badge ${LS.escape(issue.severity || 'MEDIUM')}">${LS.escape(issue.severity || '')}</span></td>
        <td class="mono">${LS.escape(issue.suggested_technique || '')} ${LS.escape(issue.suggested_tactic || '')}</td></tr>`;
    }
    html += '</tbody></table>';
  }

  if ((report.iocs || []).length) {
    html += '<h2>Indicadores de compromiso</h2><table><thead><tr><th>Tipo</th><th>Valor</th><th>Contexto</th><th>Confianza</th></tr></thead><tbody>';
    for (const ioc of report.iocs) {
      html += `<tr><td>${LS.escape(ioc.type || '')}</td><td class="mono">${LS.escape(ioc.value || '')}</td>
        <td class="small muted">${LS.escape(ioc.context || '')}</td><td>${LS.escape(ioc.confidence || '')}</td></tr>`;
    }
    html += '</tbody></table>';
  }

  const list = (title, items) => items && items.length
    ? `<h2>${LS.escape(title)}</h2><ul>${items.map((i) => `<li>${LS.escape(i)}</li>`).join('')}</ul>` : '';
  html += list('Huecos de telemetria', report.telemetry_gaps);
  html += list('Calidad de los datos', report.data_quality_issues);

  if ((report.recommendations || []).length) {
    html += '<h2>Recomendaciones</h2><ol>';
    for (const rec of [...report.recommendations].sort((a, b) => (a.priority || 99) - (b.priority || 99))) {
      html += `<li><b>${LS.escape(rec.action || '')}</b><div class="small muted">${LS.escape(rec.rationale || '')}</div>
        <div class="row row-tight mt-1"><span class="tag">esfuerzo: ${LS.escape(rec.effort || '')}</span>
        ${(rec.references || []).map((r) => `<span class="tag evidence">${LS.escape(r)}</span>`).join('')}</div></li>`;
    }
    html += '</ol>';
  }

  container.innerHTML = html;
};

/* ------------------------------------------------------------------ charts */
LS.renderTimelineChart = function (container, buckets) {
  if (!container) return;
  if (!buckets || !buckets.length) { container.innerHTML = '<div class="empty">sin datos</div>'; return; }
  const width = 1000, height = 190, pad = 26;
  const max = Math.max(...buckets.map((b) => b.count), 1);
  const barWidth = (width - pad * 2) / buckets.length;
  let svg = `<svg viewBox="0 0 ${width} ${height + 30}" preserveAspectRatio="none">`;
  for (let i = 0; i <= 3; i += 1) {
    const y = pad + (height - pad) * (i / 3);
    svg += `<line class="chart-grid" x1="${pad}" y1="${y}" x2="${width - pad}" y2="${y}"/>`;
    svg += `<text class="chart-label" x="4" y="${y + 3}">${Math.round(max * (1 - i / 3))}</text>`;
  }
  buckets.forEach((bucket, index) => {
    const barHeight = Math.max(((height - pad) * bucket.count) / max, bucket.count ? 2 : 0);
    const x = pad + index * barWidth;
    const y = height - barHeight;
    const severities = bucket.severities || {};
    let color = 'var(--info)';
    for (const level of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
      if (severities[level]) { color = LS.severityColor(level); break; }
    }
    const title = `${bucket.start} · ${bucket.count} eventos`;
    svg += `<rect class="bar" x="${x + 1}" y="${y}" width="${Math.max(barWidth - 2, 1)}" height="${barHeight}" fill="${color}" opacity=".82"><title>${LS.escape(title)}</title></rect>`;
  });
  svg += `<line class="chart-axis" x1="${pad}" y1="${height}" x2="${width - pad}" y2="${height}"/>`;
  svg += `<text class="chart-label" x="${pad}" y="${height + 14}">${LS.escape(buckets[0].start.slice(0, 16).replace('T', ' '))}</text>`;
  svg += `<text class="chart-label" x="${width - pad}" y="${height + 14}" text-anchor="end">${LS.escape(buckets[buckets.length - 1].end.slice(0, 16).replace('T', ' '))}</text>`;
  svg += '</svg>';
  container.innerHTML = svg;
};

LS.renderHoursChart = function (container, hours) {
  if (!container) return;
  if (!hours || !hours.length) { container.innerHTML = '<div class="empty">sin datos</div>'; return; }
  const width = 1000, height = 170, pad = 24;
  const max = Math.max(...hours.map((h) => h.count), 1);
  const barWidth = (width - pad * 2) / hours.length;
  let svg = `<svg viewBox="0 0 ${width} ${height + 26}" preserveAspectRatio="none">`;
  svg += `<line class="chart-grid" x1="${pad}" y1="${pad}" x2="${width - pad}" y2="${pad}"/>`;
  hours.forEach((slot, index) => {
    const barHeight = ((height - pad) * slot.count) / max;
    const x = pad + index * barWidth;
    const y = height - barHeight;
    const night = slot.hour < 7;
    const color = slot.high_severity ? 'var(--high)' : (night ? 'var(--accent-alt)' : 'var(--info)');
    svg += `<rect class="bar" x="${x + 2}" y="${y}" width="${Math.max(barWidth - 4, 1)}" height="${Math.max(barHeight, slot.count ? 2 : 0)}" fill="${color}" opacity=".8"><title>${String(slot.hour).padStart(2, '0')}:00 · ${slot.count} eventos · ${slot.high_severity} severidad alta</title></rect>`;
    if (index % 3 === 0) {
      svg += `<text class="chart-label" x="${x + barWidth / 2}" y="${height + 14}" text-anchor="middle">${String(slot.hour).padStart(2, '0')}</text>`;
    }
  });
  svg += `<line class="chart-axis" x1="${pad}" y1="${height}" x2="${width - pad}" y2="${height}"/>`;
  svg += '</svg>';
  container.innerHTML = svg;
};

document.addEventListener('DOMContentLoaded', () => { LS.refreshHealth(); });
