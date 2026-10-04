'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Credentials are intentionally held only in memory, never browser storage or URLs.
let apiKey = '', operatorToken = '', principal = null, toolSchemas = {}, model = 'qwen3:4b', selectedTicket = null;
let connectionGeneration = 0, statusRefreshing = false, operationsRefreshing = false;
let searchRequest = 0;
let catgirlEnabled = true, catgirlTimer = null, catgirlRemaining = 0, catgirlStarted = 0;
let catgirlHovered = false, catgirlFocused = false, lastCatgirlError = null, lastCatgirlErrorAt = -Infinity;
const catgirlTitles = Object.freeze({
  ALLOW: 'Certified W, nya.',
  WARN: 'Side-eye protocol engaged.',
  REDACT: 'Privacy arc activated.',
  BLOCK: 'BONK. Forbidden lore.',
  REQUIRE_APPROVAL: 'Hold up. Ask the guild leader.',
  ERROR: 'System hiccup, nya.'
});

function dismissCatgirlAlert() {
  clearTimeout(catgirlTimer); catgirlTimer = null; catgirlRemaining = 0;
  if ($('catgirl-alert')) $('catgirl-alert').hidden = true;
  if ($('catgirl-live')) $('catgirl-live').textContent = '';
}
function clearCatgirlAlert() {
  dismissCatgirlAlert();
  catgirlHovered = false; catgirlFocused = false;
  lastCatgirlError = null; lastCatgirlErrorAt = -Infinity;
  for (const id of ['catgirl-alert-label', 'catgirl-alert-title', 'catgirl-alert-message', 'catgirl-alert-detail']) {
    if ($(id)) $(id).textContent = '';
  }
  if ($('catgirl-alert')) { $('catgirl-alert').className = 'catgirl-alert'; delete $('catgirl-alert').dataset.state; }
  if ($('mascot-state')) delete $('mascot-state').dataset.state;
  if ($('mascot-status')) $('mascot-status').textContent = catgirlEnabled ? 'Awaiting your next move, nya.' : 'Alerts muted. Gateway protections remain active.';
}
function pauseCatgirlTimer() {
  if (catgirlTimer === null) return;
  clearTimeout(catgirlTimer); catgirlTimer = null;
  catgirlRemaining = Math.max(1, catgirlRemaining - (Date.now() - catgirlStarted));
}
function resumeCatgirlTimer() {
  if (catgirlHovered || catgirlFocused || catgirlTimer !== null || catgirlRemaining <= 0) return;
  catgirlStarted = Date.now();
  catgirlTimer = setTimeout(dismissCatgirlAlert, catgirlRemaining);
}
function showCatgirlAlert(decision, message, detail = 'Open the gateway result for details.') {
  const alert = $('catgirl-alert');
  if (!catgirlEnabled || !alert || !catgirlTitles[decision]) return;
  dismissCatgirlAlert();
  alert.className = 'catgirl-alert ' + decision;
  alert.dataset.state = decision;
  $('catgirl-alert-label').textContent = decision === 'ERROR' ? 'System alert' : 'Gateway / ' + decision;
  $('catgirl-alert-title').textContent = catgirlTitles[decision];
  $('catgirl-alert-message').textContent = message;
  $('catgirl-alert-detail').textContent = detail;
  alert.hidden = false;
  if ($('mascot-status')) $('mascot-status').textContent = catgirlTitles[decision];
  if ($('mascot-state')) $('mascot-state').dataset.state = decision;
  if ($('catgirl-live')) $('catgirl-live').textContent = `${decision}. ${catgirlTitles[decision]} ${message} ${detail}`;
  catgirlFocused = alert.contains(document.activeElement);
  catgirlRemaining = ['BLOCK', 'REQUIRE_APPROVAL'].includes(decision) ? 0 : 8000;
  resumeCatgirlTimer();
}
function notifyCatgirlDecision(result) {
  const messages = {
    ALLOW: 'The gateway allowed the request.',
    WARN: 'The gateway returned a warning. Inspect the controls before your next move.',
    REDACT: 'The gateway applied privacy redactions. Inspect the released result below.',
    BLOCK: 'The gateway blocked this request.',
    REQUIRE_APPROVAL: 'The gateway held this request for approval.'
  };
  if (!Object.hasOwn(messages, result.decision)) return;
  let message = messages[result.decision];
  if (result.executed && ['BLOCK', 'REQUIRE_APPROVAL'].includes(result.decision)) {
    message = result.decision === 'BLOCK'
      ? 'The tool executed before the gateway blocked its release. Its side effects may already have happened.'
      : 'The tool executed before its release was held for approval. Its side effects may already have happened.';
  } else {
    message += result.executed ? ' The tool executed.' : ' No tool execution was reported.';
  }
  // Alerts carry only fixed copy and bounded rule identifiers, never request/output data.
  const rules = [...new Set((result.controls || []).map(control => control.rule_id)
    .filter(id => typeof id === 'string' && /^[a-zA-Z0-9_.:-]{1,80}$/.test(id)))];
  const detail = rules.length ? `Rule IDs: ${rules.slice(0, 3).join(' / ')}${rules.length > 3 ? ` (+${rules.length - 3} more)` : ''}` : 'Open the gateway result for details.';
  showCatgirlAlert(result.decision, message, detail);
}
function notifyCatgirlError(error) {
  // Compare a fingerprint so repeating polling errors do not repeatedly announce.
  let fingerprint = 0;
  for (const character of String(error.message || '')) fingerprint = ((fingerprint << 5) - fingerprint + character.charCodeAt(0)) | 0;
  const now = Date.now();
  if (fingerprint === lastCatgirlError && now - lastCatgirlErrorAt < 30000) return;
  lastCatgirlError = fingerprint; lastCatgirlErrorAt = now;
  showCatgirlAlert('ERROR', 'A request or connection check failed. Review the error shown in the dashboard.', 'Check your connection, credentials, and local service.');
}

if ($('catgirl-alert-dismiss')) $('catgirl-alert-dismiss').addEventListener('click', dismissCatgirlAlert);
if ($('catgirl-mood')) $('catgirl-mood').addEventListener('click', () => {
  catgirlEnabled = !catgirlEnabled;
  $('catgirl-mood').textContent = 'Catgirl alerts: ' + (catgirlEnabled ? 'ON' : 'OFF');
  $('catgirl-mood').setAttribute('aria-pressed', String(catgirlEnabled));
  clearCatgirlAlert();
});
if ($('catgirl-alert')) {
  $('catgirl-alert').addEventListener('mouseenter', () => { catgirlHovered = true; pauseCatgirlTimer(); });
  $('catgirl-alert').addEventListener('mouseleave', () => { catgirlHovered = false; resumeCatgirlTimer(); });
  $('catgirl-alert').addEventListener('focusin', () => { catgirlFocused = true; pauseCatgirlTimer(); });
  $('catgirl-alert').addEventListener('focusout', event => {
    catgirlFocused = $('catgirl-alert').contains(event.relatedTarget);
    if (!catgirlFocused) resumeCatgirlTimer();
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !$('catgirl-alert').hidden) dismissCatgirlAlert();
  });
}

async function api(path, method = 'GET', body) {
  const generation = connectionGeneration;
  const headers = {};
  if (apiKey) headers.Authorization = 'Bearer ' + apiKey;
  if (operatorToken) headers['X-Admin-Token'] = operatorToken;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let response;
  try {
    response = await fetch(path, {method, headers, ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
  } catch (error) {
    if (generation !== connectionGeneration) throw Object.assign(new Error('Connection changed.'), {cancelled: true});
    throw error;
  }
  let data;
  try { data = await response.json(); } catch {
    if (generation !== connectionGeneration) throw Object.assign(new Error('Connection changed.'), {cancelled: true});
    throw new Error('The server returned an unreadable response.');
  }
  if (generation !== connectionGeneration) throw Object.assign(new Error('Connection changed.'), {cancelled: true});
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (HTTP ${response.status}). Check the request and your credentials.`);
  return data;
}
function showError(error) { if (error.cancelled) return; $('error').hidden = false; $('error').textContent = error.message; notifyCatgirlError(error); }
function clearError() { $('error').hidden = true; }
function row(a, b) { return `<div class="row"><span>${esc(a)}</span><strong>${esc(b)}</strong></div>`; }
function date(value) { return value ? new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString() : ''; }
function envelope(text, tool) {
  if (!apiKey || !principal) throw new Error('Connect with a valid user API key first.');
  return {agent: {id: $('agent').value, version: '1.0'}, model, input: {text}, ...(tool ? {tool} : {})};
}
function outputText(output) { return typeof output === 'string' ? output : JSON.stringify(output, null, 2); }
function renderResult(r) {
  $('result').className = 'result ' + r.decision;
  $('result').innerHTML = `<div class="result-top"><h3>${esc(r.decision)}</h3><span class="badge ${esc(r.decision)}">${esc(r.risk).toUpperCase()}</span><span>${esc(r.latency_ms)} ms &middot; Policy v${esc(r.policy_version)}</span><strong>${r.executed ? 'TOOL EXECUTED' : 'NO TOOL EXECUTION'}</strong></div>${r.sanitized_input ? `<div class="input">${esc(r.sanitized_input)}</div>` : ''}<ul>${(r.controls || []).map(c => `<li><span class="rule">${esc(c.rule_id)}</span> &middot; ${esc(c.decision)} &middot; ${esc(c.reason)}</li>`).join('')}</ul>${r.output !== null && r.output !== undefined ? `<pre>${esc(outputText(r.output))}</pre>` : '<p>No output released.</p>'}`;
  notifyCatgirlDecision(r);
}
async function guardedTool(name, arguments_, evaluate = false) {
  const generation = connectionGeneration;
  const r = await api('/api/tool/' + (evaluate ? 'evaluate' : 'execute'), 'POST', envelope('Submit a registered tool proposal.', {name, arguments: arguments_}));
  if (generation !== connectionGeneration) throw Object.assign(new Error('Connection changed.'), {cancelled: true});
  renderResult(r);
  void refreshOperations();
  return r;
}
async function withBusy(form, task) {
  const buttons = [...form.querySelectorAll('button')];
  buttons.forEach(b => b.disabled = true);
  clearError();
  try { await task(); } catch (error) { showError(error); }
  finally { buttons.forEach(b => b.disabled = false); }
}

function safeSearchURL(value, provider) {
  if (typeof value !== 'string') return '';
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash) return '';
    if (provider === 'Google' && url.hostname === 'www.google.com' && url.pathname === '/search'
      && [...url.searchParams.keys()].length === 1 && url.searchParams.has('q')
      && url.searchParams.get('q').trim().length > 0) return url.href;
    if (provider === 'Wikipedia' && url.hostname === 'en.wikipedia.org') {
      if (url.pathname.startsWith('/wiki/') && url.pathname.length > 6 && !url.search) return url.href;
      if (url.pathname === '/' && [...url.searchParams.keys()].length === 1
        && /^[1-9][0-9]*$/.test(url.searchParams.get('curid') || '')) return url.href;
    }
  } catch { /* Invalid external links stay out of the dashboard. */ }
  return '';
}
function clearSearchResults() {
  for (const id of ['search-meta', 'search-title', 'search-answer']) $(id).textContent = '';
  $('search-answer-card').hidden = true;
  $('search-sources').innerHTML = ''; $('search-sources').hidden = true;
  $('search-google-link').hidden = true; $('search-google-link').setAttribute('href', '');
}
function searchButtonsBusy(busy) {
  $('search-quick').disabled = busy; $('search-google').disabled = busy;
  $('search-results').setAttribute('aria-busy', String(busy));
}
function clearSearchView() {
  searchRequest++;
  $('search-query').value = '';
  clearSearchResults(); searchButtonsBusy(false);
  $('search-status').textContent = 'Connect with a user API key to search. No paid API key needed.';
}
function renderSearchResult(result, mode) {
  clearSearchResults();
  renderResult(result);
  if (['BLOCK', 'REQUIRE_APPROVAL'].includes(result.decision)) {
    const providerUnavailable = mode === 'quick' && (result.controls || [])
      .some(control => ['SEARCH_UNAVAILABLE', 'TOOL_EXECUTION_FAILURE'].includes(control.rule_id));
    $('search-status').textContent = providerUnavailable
      ? 'Wikipedia is unavailable right now. Try Search Google to check the query and get full web results.'
      : result.decision === 'BLOCK'
        ? 'The gateway blocked this search. No Google link was released.'
        : 'This search needs approval. No Google link was released.';
    return;
  }
  const output = result.output;
  if (!output || typeof output !== 'object' || !['ALLOW', 'WARN', 'REDACT'].includes(result.decision)) {
    $('search-status').textContent = 'No answer was released. Check the gateway decision below.';
    return;
  }
  if (typeof output.query === 'string') $('search-query').value = output.query;
  const googleURL = safeSearchURL(output.google_url, 'Google');
  if (googleURL) {
    $('search-google-link').setAttribute('href', googleURL);
    $('search-google-link').hidden = false;
  }
  if (mode === 'google') {
    $('search-status').textContent = googleURL
      ? 'Query checked. Open Google results below in a new tab.'
      : 'No Google link was released. Check the gateway decision below.';
    return;
  }
  const latency = Number.isFinite(result.latency_ms) ? `${result.latency_ms} ms` : 'Latency unavailable';
  $('search-meta').textContent = `${output.provider === 'Wikipedia' ? 'WIKIPEDIA' : 'SEARCH'} / ${latency}${output.cached ? ' / CACHED' : ''}`;
  if (typeof output.answer === 'string' && output.answer.trim()) {
    $('search-title').textContent = typeof output.title === 'string' ? output.title : 'Quick answer';
    $('search-answer').textContent = output.answer;
    $('search-answer-card').hidden = false;
    $('search-status').textContent = 'Quick answer ready. Check the source, then keep the brain cell moving.';
  } else {
    $('search-status').textContent = googleURL
      ? 'No Wikipedia answer found. Try the full Google results below.'
      : 'No Wikipedia answer found. Try another query or Search Google.';
  }
  const sources = (Array.isArray(output.sources) ? output.sources : []).slice(0, 5)
    .map(source => ({...source, url: safeSearchURL(source?.url, 'Wikipedia')})).filter(source => source.url);
  $('search-sources').innerHTML = sources.map(source => `<li><a href="${esc(source.url)}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">${esc(source.title || 'Wikipedia source')} ↗</a>${source.snippet ? `<p>${esc(source.snippet)}</p>` : ''}</li>`).join('');
  $('search-sources').hidden = !sources.length;
}
async function searchWeb(mode = 'quick') {
  const request = ++searchRequest, generation = connectionGeneration;
  clearSearchResults(); clearError();
  const query = $('search-query').value.trim();
  try {
    if (!apiKey || !principal) throw new Error('Connect with a valid user API key first.');
    if (!query || query.length > 300) throw new Error('Enter a search query of 1 to 300 characters.');
    searchButtonsBusy(true);
    $('search-status').textContent = mode === 'google'
      ? 'Checking the query before opening Google...'
      : 'Checking the query and fetching a quick Wikipedia answer...';
    const result = await api('/api/search', 'POST', {query, mode});
    if (request !== searchRequest || generation !== connectionGeneration) return;
    renderSearchResult(result, mode);
    void refreshOperations();
  } catch (error) {
    if (request !== searchRequest || generation !== connectionGeneration || error.cancelled) return;
    $('search-status').textContent = mode === 'google'
      ? 'The Google query check failed. Review the error and try again.'
      : 'Quick answers are unavailable. Search Google can check your query and release a link.';
    showError(error);
  } finally {
    if (request === searchRequest && generation === connectionGeneration) searchButtonsBusy(false);
  }
}
$('search-form').addEventListener('submit', event => {
  event.preventDefault();
  void searchWeb(event.submitter?.value === 'google' ? 'google' : 'quick');
});
$('search-query').addEventListener('input', () => {
  searchRequest++;
  clearSearchResults(); searchButtonsBusy(false);
  $('search-status').textContent = 'Query changed. Search again for a fresh answer or Google link.';
});

async function refreshStatus() {
  if (!apiKey || !principal || statusRefreshing) return;
  statusRefreshing = true;
  const generation = connectionGeneration;
  try {
    const s = await api('/api/status');
    if (generation !== connectionGeneration) return;
    model = s.model_name;
    $('posture').textContent = s.posture;
    $('posture').style.color = s.posture === 'PROTECTED' ? 'var(--green)' : 'var(--amber)';
    $('provider').textContent = `Ollama ${s.ollama} / ${s.model_name} ${s.model} / Semantic ${s.semantic_guard}`;
    $('versions').textContent = `Policy v${s.policy_version} / Signatures v${s.signature_version}`;
    if (s.policy_error || s.signature_error || s.reload_error) showError(new Error(s.policy_error || s.signature_error || s.reload_error));
  } catch (error) { if (generation === connectionGeneration) showError(error); }
  finally { statusRefreshing = false; }
}
async function refreshOperations() {
  if (!operatorToken || operationsRefreshing) return;
  operationsRefreshing = true;
  const generation = connectionGeneration;
  try {
    const results = await Promise.allSettled([api('/api/metrics'), api('/api/events?limit=60&decision=' + encodeURIComponent($('filter').value)), api('/api/budgets'), api('/api/policy')]);
    if (generation !== connectionGeneration) return;
    const failure = results.find(r => r.status === 'rejected');
    if (failure) throw failure.reason;
    const [m, events, b, p] = results.map(r => r.value);
    const cards = [['Requests', m.total_requests], ['Blocked', m.blocked_requests, 'danger'], ['PII redactions', m.pii_redactions], ['Secret blocks', m.secret_blocks, 'danger'], ['Tool blocks', m.tool_calls_blocked, 'danger'], ['Hourly requests', `${b.requests}/${b.limits.global.max_requests_per_hour}`], ['Avg. latency', `${m.average_gateway_latency_ms.toFixed(1)} ms`]];
    $('cards').innerHTML = cards.map(([label, value, cls = '']) => `<div class="card ${cls}"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('');
    const max = Math.max(1, ...Object.values(m.blocked_by_control));
    $('threats').innerHTML = Object.entries(m.blocked_by_control).map(([name, n]) => row(name, n) + `<div class="bar"><i style="width:${100 * n / max}%"></i></div>`).join('') || '<p>No blocks recorded.</p>';
    $('events').innerHTML = events.map(e => `<tr><td>${esc(date(e.timestamp))}</td><td><span class="badge ${esc(e.decision)}">${esc(e.decision)}</span></td><td>${esc(e.control)}<small>${esc(e.rule_id)}</small></td><td>${esc(e.reason)}</td><td>${esc(e.user_id || 'operator')}</td><td>v${esc(e.policy_version)}</td></tr>`).join('') || '<tr><td colspan="6" class="muted">No matching events.</td></tr>';
    $('budget').innerHTML = row('Rolling hourly requests', b.requests) + row('Per-request token limit', b.limits.per_request.max_tokens) + row('Tool calls / steps per run', `${b.limits.per_request.max_tool_calls} / ${b.limits.per_request.max_steps}`) + b.users.slice(0, 6).map(u => row(u.user_id, `${u.requests} requests / ${u.tokens} token units`)).join('');
    $('policy-summary').innerHTML = row('Active version', `v${p.active_version}`) + row('Profile', p.policy.profile) + row('Allowed models', p.policy.models.allow.join(', ')) + row('Allowed egress', p.policy.egress.allow_domains.join(', ') || 'None');
    $('policy').textContent = JSON.stringify(p.policy, null, 2);
    $('permissions').innerHTML = Object.entries(p.policy.tools.allow).map(([name, rule]) => row(name, `${(rule.action || 'allow').toUpperCase()} / ${(rule.roles || []).join(', ')}`)).join('');
    $('versions').textContent = `Policy v${m.policy_version} / Signatures v${m.signature_version}`;
    $('operator-status').textContent = 'Operator connected. Data refreshes every 8 seconds.';
    for (const id of ['reset', 'reload', 'feed-reload']) $(id).disabled = false;
    if (p.error) showError(new Error(p.error));
  } catch (error) {
    if (generation === connectionGeneration) {
      $('operator-status').textContent = 'Operator access unavailable.';
      for (const id of ['reset', 'reload', 'feed-reload']) $(id).disabled = true;
      showError(error);
    }
  } finally { operationsRefreshing = false; }
}

function schemaExample(name) {
  const examples = {
    'internal.ticket.create': {summary: 'Notification settings issue', description: ''},
    'internal.ticket.list': {limit: 50},
    'internal.ticket.read': {ticket_id: selectedTicket?.id || '1'},
    'internal.ticket.update': {ticket_id: selectedTicket?.id || '1', status: 'in_progress'},
    'internal.employee.create': {name: 'New team member', email: 'member@example.com'},
    'internal.employee.list': {limit: 100},
    'calculator': {a: 12, b: 4, operation: 'divide'},
    'http.get': {url: 'https://your-approved-host.example/path'},
    'http.post': {url: 'https://your-approved-host.example/path', data: {message: 'Public information'}}
  };
  return examples[name] || {};
}
function selectTool() {
  const name = $('tool-name').value;
  $('tool-schema').textContent = JSON.stringify(toolSchemas[name], null, 2);
  $('tool-arguments').value = JSON.stringify(schemaExample(name), null, 2);
}
function clearUserView() {
  principal = null; selectedTicket = null; toolSchemas = {}; model = 'qwen3:4b';
  $('identity').textContent = 'No authenticated user';
  $('provider').textContent = 'Connect to check the local model';
  $('posture').textContent = 'NOT CONNECTED';
  $('agent').innerHTML = '<option value="support-agent">support-agent</option>';
  $('tool-name').innerHTML = '<option value="">Connect with an API key</option>';
  $('tool-schema').textContent = 'Connect to load schemas.';
  $('tool-arguments').value = '{}';
  $('tickets').innerHTML = '<tr><td colspan="5" class="muted">Connect with an API key and refresh to load your tenant\'s tickets.</td></tr>';
  $('ticket-detail').innerHTML = '<p>Select a saved ticket to see its details.</p>';
  $('ticket-update').hidden = true;
  $('chat-history').innerHTML = '<p>Connect with an API key to chat with your agent.</p>';
  $('chat-input').value = ''; $('ticket-summary').value = ''; $('ticket-description').value = ''; $('ticket-id').value = '';
  $('result').className = 'result'; $('result').innerHTML = '<p>Send a message or submit a tool proposal to inspect its decision.</p>';
  clearSearchView();
}
function clearOperatorView() {
  $('operator-status').textContent = 'Connect with an operator token to load audit, quotas and policy.';
  $('cards').innerHTML = '';
  for (const id of ['threats', 'budget', 'permissions']) $(id).innerHTML = '<p>No operator data loaded.</p>';
  $('policy-summary').innerHTML = ''; $('policy').textContent = 'No operator data loaded.';
  $('events').innerHTML = '<tr><td colspan="6" class="muted">Connect with an operator token to load events.</td></tr>';
  for (const id of ['reset', 'reload', 'feed-reload']) $(id).disabled = true;
}

$('credentials').addEventListener('submit', event => {
  event.preventDefault();
  const key = $('api-key').value.trim(), token = $('admin-token').value.trim();
  $('api-key').value = ''; $('admin-token').value = '';
  void withBusy(event.currentTarget, async () => {
    connectionGeneration++;
    clearCatgirlAlert();
    clearSearchView();
    const generation = connectionGeneration;
    if (key) { clearUserView(); apiKey = key; }
    if (token) { clearOperatorView(); operatorToken = token; }
    if (!apiKey && !operatorToken) throw new Error('Enter a user API key or operator token.');
    if (apiKey) {
      try {
        const me = await api('/api/me');
        if (generation !== connectionGeneration) return;
        principal = me.user;
        $('identity').textContent = `${principal.id} / ${principal.role} / ${principal.tenant}`;
        $('agent').innerHTML = me.agents.map(id => `<option value="${esc(id)}">${esc(id)}</option>`).join('');
        const schemas = await api('/api/tools');
        if (generation !== connectionGeneration) return;
        toolSchemas = schemas;
        $('tool-name').innerHTML = Object.keys(toolSchemas).map(name => `<option value="${esc(name)}">${esc(name)}</option>`).join('');
        selectTool();
        $('connection').textContent = 'User connected. Create a ticket, execute a tool, or chat with Ollama.';
        await refreshStatus();
      } catch (error) {
        if (generation !== connectionGeneration) return;
        apiKey = ''; principal = null;
        $('identity').textContent = 'No authenticated user';
        $('connection').textContent = 'User connection failed. Check the API key.';
        showError(error);
      }
    }
    if (generation !== connectionGeneration) return;
    await refreshOperations();
  });
});
$('disconnect').addEventListener('click', () => {
  connectionGeneration++;
  clearCatgirlAlert();
  apiKey = ''; operatorToken = '';
  $('api-key').value = ''; $('admin-token').value = '';
  clearUserView();
  clearOperatorView();
  $('versions').textContent = 'Policy and signatures';
  $('connection').textContent = 'Disconnected. Credentials cleared.';
  clearError();
});
$('tool-name').addEventListener('change', selectTool);
$('tool-form').addEventListener('submit', event => {
  event.preventDefault();
  const evaluate = event.submitter?.value === 'evaluate';
  void withBusy(event.currentTarget, async () => {
    let args;
    try { args = JSON.parse($('tool-arguments').value); } catch { throw new Error('Arguments must be valid JSON.'); }
    if (!args || Array.isArray(args) || typeof args !== 'object') throw new Error('Arguments must be a JSON object.');
    await guardedTool($('tool-name').value, args, evaluate);
  });
});
$('chat-form').addEventListener('submit', event => {
  event.preventDefault();
  const text = $('chat-input').value;
  void withBusy(event.currentTarget, async () => {
    const body = envelope(text);
    $('chat-input').value = '';
    const generation = connectionGeneration;
    $('chat-history').innerHTML = '<p>Waiting for the local model and gateway checks...</p>';
    const r = await api('/api/chat', 'POST', body);
    if (generation !== connectionGeneration) return;
    renderResult(r);
    $('chat-history').innerHTML = `<div class="chat-message"><small>Your request after controls</small><p>${esc(r.sanitized_input)}</p></div><div class="chat-message"><small>Agent / ${esc(r.decision)}</small><pre>${esc(r.output !== null && r.output !== undefined ? outputText(r.output) : 'No output released. See the gateway decision below.')}</pre></div>`;
    void refreshOperations();
  });
});

async function loadTickets() {
  const r = await guardedTool('internal.ticket.list', {limit: 100});
  if (!r.executed || !Array.isArray(r.output)) return;
  $('tickets').innerHTML = r.output.map(t => `<tr><td>${esc(t.id)}</td><td>${esc(t.summary)}</td><td>${esc(t.status)}</td><td>${esc(date(t.updated_at))}</td><td><button class="subtle" type="button" data-ticket-id="${esc(t.id)}">Open</button></td></tr>`).join('') || '<tr><td colspan="5" class="muted">No tickets saved for this tenant. Create your first ticket above.</td></tr>';
}
function showTicket(ticket) {
  selectedTicket = ticket;
  $('ticket-id').value = ticket.id;
  $('ticket-detail').innerHTML = `<h3>#${esc(ticket.id)} ${esc(ticket.summary)}</h3><p class="ticket-description">${esc(ticket.description || 'No description.')}</p>${row('Status', ticket.status)}${row('Tenant', ticket.tenant)}${row('Created by', ticket.created_by)}${row('Updated', date(ticket.updated_at))}`;
  $('ticket-status').value = ticket.status;
  $('ticket-update').hidden = false;
}
async function readTicket(id) {
  const r = await guardedTool('internal.ticket.read', {ticket_id: id});
  if (r.executed && r.output && typeof r.output === 'object' && r.output.id) showTicket(r.output);
  else { selectedTicket = null; $('ticket-update').hidden = true; $('ticket-detail').innerHTML = '<p>No ticket was released. Check the latest gateway decision.</p>'; }
}
$('ticket-create').addEventListener('submit', event => {
  event.preventDefault();
  void withBusy(event.currentTarget, async () => {
    const r = await guardedTool('internal.ticket.create', {summary: $('ticket-summary').value, description: $('ticket-description').value});
    if (r.executed && r.output?.id) { showTicket(r.output); $('ticket-summary').value = ''; $('ticket-description').value = ''; await loadTickets(); renderResult(r); }
  });
});
$('ticket-open').addEventListener('submit', event => { event.preventDefault(); void withBusy(event.currentTarget, () => readTicket($('ticket-id').value)); });
$('ticket-update').addEventListener('submit', event => {
  event.preventDefault();
  void withBusy(event.currentTarget, async () => {
    if (!selectedTicket) throw new Error('Read a saved ticket first.');
    const r = await guardedTool('internal.ticket.update', {ticket_id: selectedTicket.id, status: $('ticket-status').value});
    if (r.executed && r.output?.id) { showTicket(r.output); await loadTickets(); renderResult(r); }
  });
});
$('ticket-refresh').addEventListener('click', async event => {
  const button = event.currentTarget; button.disabled = true; clearError();
  try { await loadTickets(); } catch (error) { showError(error); } finally { button.disabled = false; }
});
$('tickets').addEventListener('click', async event => {
  const button = event.target.closest('button[data-ticket-id]'); if (!button) return;
  button.disabled = true; clearError();
  try { await readTicket(button.dataset.ticketId); } catch (error) { showError(error); } finally { button.disabled = false; }
});
for (const [id, path] of [['reload', '/api/policy/reload'], ['feed-reload', '/api/signatures/reload'], ['reset', '/api/budgets/reset']]) {
  $(id).addEventListener('click', async () => {
    if (id === 'reset' && !window.confirm('Reset all rolling quota counters? Stored tickets and audit events remain.')) return;
    $(id).disabled = true; clearError();
    try { const r = await api(path, 'POST'); if (r.error) throw new Error(r.error); await refreshOperations(); await refreshStatus(); }
    catch (error) { showError(error); }
    finally { $(id).disabled = !operatorToken; }
  });
}
$('filter').addEventListener('change', () => void refreshOperations());
setInterval(() => { void refreshOperations(); void refreshStatus(); }, 8000);
