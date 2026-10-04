'use strict';
// Privacy and browser-safety checks for the real search workflow.
// Run from the project root: node --preserve-symlinks-main tests/frontend-search.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('app/dashboard/static/app.js', 'utf8');
const template = fs.readFileSync('app/dashboard/templates/index.html', 'utf8');
const ids = [...template.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {status, headers: {'Content-Type': 'application/json'}});
}
function result(overrides = {}) {
  return {decision: 'ALLOW', executed: true, risk: 'low', latency_ms: 14, policy_version: 1,
    controls: [], sanitized_input: 'Public query', output: {
      provider: 'Wikipedia', query: 'Ada Lovelace', title: 'Ada Lovelace', answer: 'A mathematician.',
      sources: [{title: 'Ada Lovelace', url: 'https://en.wikipedia.org/?curid=123', snippet: 'Read the source.'}],
      google_url: 'https://www.google.com/search?q=Ada+Lovelace', cached: false
    }, ...overrides};
}
function setup(fetcher = async () => response(result())) {
  const elements = new Map(), requests = [];
  class Element {
    constructor(id) {
      this.id = id; this.value = ''; this.textContent = ''; this.innerHTML = ''; this.className = '';
      this.hidden = false; this.disabled = false; this.dataset = {}; this.style = {};
      this.listeners = new Map(); this.attributes = new Map();
    }
    addEventListener(type, fn) { this.listeners.set(type, fn); }
    dispatch(type, event = {}) {
      return this.listeners.get(type)?.({currentTarget: this, target: this, preventDefault() {}, ...event});
    }
    setAttribute(name, value) { this.attributes.set(name, value); }
    querySelectorAll() { return []; }
    contains() { return false; }
  }
  for (const id of ids) elements.set(id, new Element(id));
  elements.get('agent').value = 'support-agent';
  const document = {activeElement: null, getElementById: id => elements.get(id), addEventListener() {}};
  const context = vm.createContext({document, URL, Date, console, window: {confirm: () => true},
    setInterval() {}, setTimeout() { return 1; }, clearTimeout() {},
    fetch(...args) { requests.push(args); return fetcher(...args); }});
  vm.runInContext(source, context, {filename: 'app.js'});
  vm.runInContext("apiKey = 'private-user-key'; principal = {id:'reader'};", context);
  return {context, requests, elements, element: id => elements.get(id)};
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

async function main() {
  assert.equal(new Set(ids).size, ids.length, 'Dashboard IDs remain unique.');
  assert.match(template, /Quick answers from Wikipedia\. Full web results open in Google\./);
  assert.match(template, /id="search-query"[^>]*maxlength="300"/);

  {
    const env = setup();
    env.element('search-query').value = 'Ada Lovelace';
    await env.context.searchWeb();
    const [path, options] = env.requests[0];
    assert.equal(path, '/api/search');
    assert.equal(options.method, 'POST');
    assert.equal(options.headers.Authorization, 'Bearer private-user-key');
    assert.deepEqual(JSON.parse(options.body), {query: 'Ada Lovelace', mode: 'quick'});
    assert.equal(env.element('search-answer').textContent, 'A mathematician.');
    assert.match(env.element('search-meta').textContent, /WIKIPEDIA \/ 14 ms/);
    assert.equal(env.element('search-google-link').attributes.get('href'), 'https://www.google.com/search?q=Ada+Lovelace');
    assert.match(env.element('search-sources').innerHTML, /noopener noreferrer/);
    assert.equal(env.element('catgirl-alert').dataset.state, 'ALLOW');
    assert.doesNotMatch(env.element('catgirl-alert-message').textContent, /Ada|private-user-key/);
  }
  {
    const env = setup();
    const unsafe = result();
    unsafe.output.title = '<img src=x onerror=alert(1)>';
    unsafe.output.answer = '<script>alert(1)</script>';
    unsafe.output.sources = [
      {title: '<img onerror=alert(1)>', snippet: '<script>bad</script>', url: 'https://en.wikipedia.org/?curid=42'},
      {title: 'bad', url: 'javascript:alert(1)'}, {title: 'bad', url: 'https://evil.example/wiki/Ada'},
      {title: 'bad', url: 'https://en.wikipedia.org@evil.example/wiki/Ada'},
      {title: 'Wiki', url: 'https://en.wikipedia.org/wiki/Ada_Lovelace'}
    ];
    env.context.renderSearchResult(unsafe, 'quick');
    assert.equal(env.element('search-answer').textContent, '<script>alert(1)</script>');
    assert.equal(env.element('search-title').textContent, '<img src=x onerror=alert(1)>');
    assert.doesNotMatch(env.element('search-sources').innerHTML, /<script>|<img|javascript:|evil\.example/);
    assert.match(env.element('search-sources').innerHTML, /&lt;img/);
    for (const url of ['http://www.google.com/search?q=x', 'javascript:alert(1)',
      'https://www.google.com.evil.example/search?q=x', 'https://user@www.google.com/search?q=x',
      'https://www.google.com:444/search?q=x', 'https://www.google.com/search?q=x#fragment',
      'https://www.google.com/search?q=x&q=y', 'https://www.google.com/search?q=']) {
      assert.equal(env.context.safeSearchURL(url, 'Google'), '', url);
    }
    assert.equal(env.context.safeSearchURL('https://en.wikipedia.org/?curid=0', 'Wikipedia'), '');
    assert.equal(env.context.safeSearchURL('https://en.wikipedia.org/?curid=4&other=1', 'Wikipedia'), '');
  }
  {
    const env = setup(async () => response(result({executed: false, decision: 'REDACT',
      output: {provider: 'Google', query: '[EMAIL]', google_url: 'https://www.google.com/search?q=%5BEMAIL%5D'}})));
    env.element('search-query').value = 'secret.person@example.com';
    await env.context.searchWeb('google');
    assert.equal(JSON.parse(env.requests[0][1].body).mode, 'google');
    assert.equal(env.element('search-query').value, '[EMAIL]');
    assert.equal(env.element('search-google-link').hidden, false);
    assert.doesNotMatch(env.element('search-google-link').attributes.get('href'), /secret\.person/);
    assert.equal(env.element('search-answer-card').hidden, true);
    assert.match(env.element('search-status').textContent, /Open Google results below/);
    assert.match(env.element('catgirl-alert-message').textContent, /No tool execution was reported/);
    for (const decision of ['BLOCK', 'REQUIRE_APPROVAL']) {
      env.context.renderSearchResult(result({decision}), 'quick');
      assert.equal(env.element('search-google-link').hidden, true);
      assert.equal(env.element('search-google-link').attributes.get('href'), '');
      assert.equal(env.element('search-answer-card').hidden, true);
      assert.equal(env.element('search-sources').innerHTML, '');
    }
  }
  {
    const env = setup();
    const noResult = result(); noResult.output.answer = ''; noResult.output.sources = [];
    env.context.renderSearchResult(noResult, 'quick');
    assert.match(env.element('search-status').textContent, /No Wikipedia answer found/);
    assert.equal(env.element('search-google-link').hidden, false);
    const unavailable = setup(async () => response({detail: 'Wikipedia is unavailable.'}, 503));
    unavailable.element('search-query').value = 'Ada Lovelace';
    await unavailable.context.searchWeb();
    assert.match(unavailable.element('search-status').textContent, /Quick answers are unavailable/);
    assert.equal(unavailable.element('search-google-link').hidden, true);
    assert.equal(unavailable.element('search-google').disabled, false);
    assert.equal(unavailable.element('catgirl-alert').dataset.state, 'ERROR');
    env.context.renderSearchResult(result({decision: 'BLOCK', output: null,
      controls: [{rule_id: 'SEARCH_UNAVAILABLE', decision: 'BLOCK', reason: 'Provider unavailable.'}]}), 'quick');
    assert.match(env.element('search-status').textContent, /Wikipedia is unavailable right now/);
    assert.equal(env.element('search-google-link').hidden, true);
  }
  {
    const env = setup();
    env.element('search-query').value = 'Ada Lovelace';
    vm.runInContext("apiKey = ''; principal = null;", env.context);
    await env.context.searchWeb();
    assert.equal(env.requests.length, 0);
    assert.match(env.element('error').textContent, /valid user API key/);
    vm.runInContext("apiKey = 'private-user-key'; principal = {id:'reader'};", env.context);
    for (const query of ['  ', 'x'.repeat(301)]) {
      env.element('search-query').value = query;
      await env.context.searchWeb();
    }
    assert.equal(env.requests.length, 0);
  }
  {
    const first = deferred(), second = deferred();
    let call = 0;
    const env = setup(() => (++call === 1 ? first.promise : second.promise));
    env.element('search-query').value = 'First query';
    const old = env.context.searchWeb();
    env.element('search-query').value = 'Second query';
    const current = env.context.searchWeb();
    const newest = result(); newest.output.query = 'Second query'; newest.output.answer = 'Newest answer';
    second.resolve(response(newest)); await current;
    first.resolve(response(result())); await old;
    assert.equal(env.element('search-answer').textContent, 'Newest answer');
    assert.equal(env.element('search-query').value, 'Second query');
    assert.equal(env.element('search-quick').disabled, false);
  }
  {
    const pending = deferred();
    const env = setup(() => pending.promise);
    env.element('search-query').value = 'Old query';
    const old = env.context.searchWeb();
    env.element('disconnect').dispatch('click');
    pending.resolve(response(result())); await old;
    assert.equal(env.element('search-query').value, '');
    assert.equal(env.element('search-answer-card').hidden, true);
    assert.equal(env.element('search-google-link').hidden, true);
    assert.match(env.element('search-status').textContent, /Connect with a user API key/);
    assert.equal(env.element('catgirl-alert').hidden, true);
  }
  {
    const pending = deferred();
    const env = setup(() => pending.promise);
    env.element('search-query').value = 'Old query';
    const old = env.context.searchWeb();
    env.element('search-query').value = 'New draft';
    env.element('search-query').dispatch('input');
    pending.reject(new Error('Stale private error')); await old;
    assert.equal(env.element('search-query').value, 'New draft');
    assert.equal(env.element('search-answer-card').hidden, true);
    assert.equal(env.element('search-google-link').hidden, true);
    assert.equal(env.element('search-quick').disabled, false);
    assert.match(env.element('search-status').textContent, /Query changed/);
    assert.doesNotMatch(env.element('error').textContent, /Stale private/);
  }
  {
    const pending = deferred();
    const env = setup(path => path === '/api/search' ? pending.promise
      : Promise.resolve(response({detail: 'New credentials rejected.'}, 401)));
    env.element('search-query').value = 'Previous user query';
    const old = env.context.searchWeb();
    env.element('api-key').value = 'new-private-user-key';
    env.element('credentials').dispatch('submit');
    pending.resolve(response(result())); await old;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(env.element('search-query').value, '');
    assert.equal(env.element('search-answer-card').hidden, true);
    assert.equal(env.element('search-google-link').hidden, true);
    assert.equal(env.element('search-google-link').attributes.get('href'), '');
    assert.equal(env.element('api-key').value, '');
  }
  console.log('9 search behavior groups passed: request authentication, source safety, redaction, blocked release, honest fallback, validation, races, disconnect privacy, and credential changes.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
