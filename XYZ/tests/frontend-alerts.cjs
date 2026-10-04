'use strict';
// Dependency-free checks of privacy, execution reporting, and alert lifecycle.
// Run from the project root: node tests/frontend-alerts.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('app/dashboard/static/app.js', 'utf8');
const template = fs.readFileSync('app/dashboard/templates/index.html', 'utf8');
const alertIds = ['catgirl-alert', 'catgirl-alert-label', 'catgirl-alert-title', 'catgirl-alert-message',
  'catgirl-alert-detail', 'catgirl-alert-dismiss', 'catgirl-live', 'catgirl-mood', 'mascot-status', 'mascot-state'];

function setup(fetcher = async () => new Response('{}', {headers: {'Content-Type': 'application/json'}})) {
  let now = 1000, nextTimer = 1;
  const timers = new Map(), elements = new Map(), listeners = new Map(), requests = [];
  class Element {
    constructor(id) {
      this.id = id; this.hidden = id === 'catgirl-alert'; this.dataset = {}; this.style = {};
      this.textContent = ''; this.innerHTML = ''; this.value = ''; this.className = '';
      this.listeners = new Map(); this.attributes = new Map();
    }
    addEventListener(type, fn) {
      const handlers = this.listeners.get(type) || []; handlers.push(fn); this.listeners.set(type, handlers);
    }
    dispatch(type, event = {}) {
      for (const fn of this.listeners.get(type) || []) fn({currentTarget: this, target: this, preventDefault() {}, ...event});
    }
    setAttribute(name, value) { this.attributes.set(name, value); }
    querySelectorAll() { return []; }
    contains(element) { return Boolean(element && (element === this || element.parent === this)); }
  }
  const ids = [...template.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  for (const id of new Set([...ids, ...alertIds])) elements.set(id, new Element(id));
  elements.get('catgirl-alert-dismiss').parent = elements.get('catgirl-alert');
  elements.get('agent').value = 'support-agent';
  const document = {
    activeElement: null,
    getElementById: id => elements.get(id) || null,
    addEventListener(type, fn) { listeners.set(type, fn); }
  };
  class ClockDate extends Date { static now() { return now; } }
  const context = vm.createContext({document, window: {confirm: () => true}, Date: ClockDate,
    setTimeout(fn, delay) { const id = nextTimer++; timers.set(id, {fn, due: now + delay}); return id; },
    clearTimeout(id) { timers.delete(id); }, setInterval() {},
    fetch(...args) { requests.push(args); return fetcher(...args); }, console});
  vm.runInContext(source, context, {filename: 'app.js'});
  function advance(milliseconds) {
    now += milliseconds;
    for (const [id, timer] of [...timers]) if (timer.due <= now) { timers.delete(id); timer.fn(); }
  }
  return {context, document, elements, requests, advance, timers, listeners,
    element: id => elements.get(id),
    alertText: () => alertIds.filter(id => id !== 'mascot-state').map(id => elements.get(id).textContent).join(' ')};
}

function result(decision, executed = false) {
  return {decision, executed, risk: 'low', latency_ms: 1, policy_version: 1,
    controls: [{rule_id: 'SEC-TEST-001', decision, reason: 'PRIVATE REASON'}],
    sanitized_input: 'PRIVATE INPUT', output: 'PRIVATE OUTPUT'};
}

async function main() {
  {
    const env = setup();
    for (const decision of ['ALLOW', 'WARN', 'REDACT', 'BLOCK', 'REQUIRE_APPROVAL']) {
      env.context.renderResult(result(decision));
      assert.equal(env.element('catgirl-alert').hidden, false);
      assert.equal(env.element('catgirl-alert').dataset.state, decision);
      assert.match(env.element('catgirl-alert-detail').textContent, /SEC-TEST-001/);
      assert.doesNotMatch(env.alertText(), /PRIVATE/);
      assert.match(env.element('catgirl-alert-message').textContent, /No tool execution was reported/);
      assert.match(env.element('result').innerHTML, /PRIVATE OUTPUT/);
    }
    const unsafe = result('REDACT');
    unsafe.controls.push({rule_id: '<script>SECRET</script>', reason: 'PRIVATE', decision: 'REDACT'});
    env.context.renderResult(unsafe);
    assert.doesNotMatch(env.alertText(), /script|SECRET/);
    for (const decision of ['BLOCK', 'REQUIRE_APPROVAL']) {
      env.context.renderResult(result(decision, true));
      assert.match(env.element('catgirl-alert-message').textContent, /executed before/);
      assert.match(env.element('catgirl-alert-message').textContent, /side effects may already have happened/);
      env.advance(60000);
      assert.equal(env.element('catgirl-alert').hidden, false);
    }
  }
  {
    const env = setup();
    env.context.renderResult(result('ALLOW', true));
    env.advance(3000);
    env.element('catgirl-alert').dispatch('mouseenter');
    env.advance(12000);
    assert.equal(env.element('catgirl-alert').hidden, false);
    env.element('catgirl-alert').dispatch('mouseleave');
    env.advance(4999);
    assert.equal(env.element('catgirl-alert').hidden, false);
    env.advance(1);
    assert.equal(env.element('catgirl-alert').hidden, true);
    env.context.renderResult(result('WARN'));
    env.element('catgirl-alert').dispatch('focusin');
    env.advance(12000);
    assert.equal(env.element('catgirl-alert').hidden, false);
    env.element('catgirl-alert').dispatch('focusout', {relatedTarget: env.element('catgirl-alert-dismiss')});
    assert.equal(env.timers.size, 0);
    env.element('catgirl-alert').dispatch('focusout', {relatedTarget: null});
    env.advance(8000);
    assert.equal(env.element('catgirl-alert').hidden, true);
  }
  {
    const env = setup();
    env.context.showError(new Error('PRIVATE CREDENTIAL ERROR'));
    assert.equal(env.element('catgirl-alert').dataset.state, 'ERROR');
    assert.doesNotMatch(env.alertText(), /PRIVATE CREDENTIAL/);
    assert.equal(env.element('error').textContent, 'PRIVATE CREDENTIAL ERROR');
    env.element('catgirl-alert-dismiss').dispatch('click');
    env.context.showError(new Error('PRIVATE CREDENTIAL ERROR'));
    assert.equal(env.element('catgirl-alert').hidden, true);
    env.advance(30001);
    env.context.showError(new Error('PRIVATE CREDENTIAL ERROR'));
    assert.equal(env.element('catgirl-alert').hidden, false);
    env.context.clearCatgirlAlert();
    env.context.showError(Object.assign(new Error('CANCELLED'), {cancelled: true}));
    assert.equal(env.element('catgirl-alert').hidden, true);
  }
  {
    const env = setup();
    env.context.renderResult(result('BLOCK'));
    env.listeners.get('keydown')({key: 'Escape'});
    assert.equal(env.element('catgirl-alert').hidden, true);
    env.element('catgirl-mood').dispatch('click');
    assert.equal(env.element('catgirl-mood').attributes.get('aria-pressed'), 'false');
    env.context.renderResult(result('BLOCK'));
    assert.equal(env.element('catgirl-alert').hidden, true);
    assert.match(env.element('result').innerHTML, /BLOCK/);
    env.element('catgirl-mood').dispatch('click');
    assert.equal(env.element('catgirl-mood').attributes.get('aria-pressed'), 'true');
    env.context.renderResult(result('ALLOW'));
    env.element('disconnect').dispatch('click');
    assert.equal(env.element('catgirl-alert').hidden, true);
    assert.equal(env.element('catgirl-alert-detail').textContent, '');
    assert.equal(env.element('catgirl-live').textContent, '');
    assert.equal(env.element('catgirl-alert').dataset.state, undefined);
  }
  {
    const env = setup(async () => new Response(JSON.stringify(result('ALLOW', true)), {
      headers: {'Content-Type': 'application/json'}}));
    vm.runInContext("apiKey = 'test-only-key'; principal = {id: 'test-user'};", env.context);
    await env.context.guardedTool('calculator', {a: 12, b: 4, operation: 'divide'});
    assert.equal(env.requests.length, 1);
    assert.equal(env.requests[0][0], '/api/tool/execute');
    assert.equal(env.element('catgirl-alert').dataset.state, 'ALLOW');
    assert.match(env.element('catgirl-alert-message').textContent, /The tool executed/);
    assert.equal(JSON.parse(env.requests[0][1].body).tool.arguments.operation, 'divide');
  }
  {
    let rejectRequest;
    const env = setup(() => new Promise((resolve, reject) => { rejectRequest = reject; }));
    const pending = env.context.api('/api/status').catch(error => error);
    env.element('disconnect').dispatch('click');
    rejectRequest(new Error('Old connection failed with private data'));
    const error = await pending;
    assert.equal(error.cancelled, true);
    env.context.showError(error);
    assert.equal(env.element('catgirl-alert').hidden, true);
  }
  console.log('6 frontend behavior groups passed: privacy, execution reporting, timers, error dedupe, controls, and stale requests.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
