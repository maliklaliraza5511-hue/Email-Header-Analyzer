const form = document.getElementById('analyze-form');
const fileInput = document.getElementById('email_file');
const fileName = document.getElementById('file-name');
const emptyState = document.getElementById('empty-state');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
let lastResult = null;

fileInput.addEventListener('change', () => {
  fileName.textContent = fileInput.files[0]?.name || 'No file selected';
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  data.set('dns', form.elements.dns.checked ? 'true' : 'false');
  data.set('dkim', form.elements.dkim.checked ? 'true' : 'false');
  emptyState.classList.add('hidden');
  results.classList.add('hidden');
  loading.classList.remove('hidden');
  try {
    const response = await fetch('/api/analyze', {method:'POST', body:data});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Analysis failed');
    lastResult = payload;
    render(payload);
    loading.classList.add('hidden');
    results.classList.remove('hidden');
  } catch (error) {
    loading.classList.add('hidden');
    emptyState.classList.remove('hidden');
    alert(error.message);
  }
});

function render(data) {
  const score = data.risk_score ?? 0;
  document.getElementById('score').textContent = score;
  document.getElementById('ring-number').textContent = score;
  document.getElementById('verdict').textContent = `${data.risk_level} RISK · HEURISTIC`;
  document.getElementById('score-ring').style.background = `conic-gradient(${score >= 50 ? '#ff647c' : score >= 25 ? '#f4c66a' : '#48d7ce'} ${score*3.6}deg,#26394d 0deg)`;
  const auth = data.authentication || {};
  document.getElementById('auth-grid').innerHTML = ['spf','dkim','dmarc'].map(key => {
    const values = auth[key] || [];
    const latest = values.length ? values[values.length-1].toUpperCase() : 'NOT REPORTED';
    const cls = latest === 'PASS' ? 'pass' : ['FAIL','PERMERROR'].includes(latest) ? 'fail' : '';
    return `<div class="auth-card"><small>${key.toUpperCase()}</small><strong class="${cls}">${latest}</strong></div>`;
  }).join('');
  const findings = data.findings || [];
  document.getElementById('finding-count').textContent = `${findings.length} ITEMS`;
  document.getElementById('findings').innerHTML = findings.length ? findings.map(x => `<div class="finding ${safe(x.severity)}"><b>${safe(x.severity).toUpperCase()}</b>${safe(x.detail)}</div>`).join('') : '<div class="finding"><b>NO FLAGS</b>No heuristic indicators were triggered. This does not establish that the message is safe.</div>';
  const s = data.summary || {};
  const pairs = [['FROM',s.from],['REPLY-TO',s.reply_to],['RETURN-PATH',s.return_path],['SUBJECT',s.subject],['DATE',s.date],['MESSAGE-ID',s.message_id],['SOURCE FILE',data.source_file],['SENDER DOMAIN',s.from_domain]];
  document.getElementById('overview').innerHTML = pairs.map(([k,v]) => `<div class="kv"><small>${k}</small><span>${safe(v || '—')}</span></div>`).join('');
  const ips = data.ips || [];
  document.getElementById('ips').innerHTML = ips.length ? ips.map(ip => `<span class="ip">${safe(ip)}</span>`).join('') : '<span class="muted">No IP addresses extracted.</span>';
  document.getElementById('caveats').innerHTML = (data.limitations || []).map(x => `<li>${safe(x)}</li>`).join('');
  togglePre('dns-section','dns-output',data.dns_checks);
  togglePre('dkim-section','dkim-output',data.dkim_verification);
}
function togglePre(sectionId, outputId, value) {
  const section = document.getElementById(sectionId);
  if (value) { section.classList.remove('hidden'); document.getElementById(outputId).textContent = JSON.stringify(value,null,2); }
  else section.classList.add('hidden');
}
function safe(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
document.getElementById('download-json').addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult,null,2)], {type:'application/json'});
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = 'email-forensic-report.json'; a.click(); URL.revokeObjectURL(url);
});
document.getElementById('print-report').addEventListener('click', () => window.print());
