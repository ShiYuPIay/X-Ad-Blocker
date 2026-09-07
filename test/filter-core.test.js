'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const core = require('../lib/filter-core');

const defaults = { users: [], words: ['default-risk'], regex: [/default-regex/i] };

test('fallback cache keys include author while stable IDs reuse their key', () => {
    assert.notEqual(core.tweetCacheKey({ text: 'same text', userId: 'alice' }), core.tweetCacheKey({ text: 'same text', userId: 'bob' }));
    assert.equal(core.tweetCacheKey({ id: '123', text: 'first', userId: 'alice' }), core.tweetCacheKey({ id: '123', text: 'changed', userId: 'bob' }));
    assert.equal(core.hashText('same text'), core.hashText('same text'));
});

test('compiles handles case-insensitively but preserves regex case semantics', () => {
    assert.equal(core.userMatchesRule('ALIce', core.compileUserRule('@alice')), true);
    const rule = core.compileUserRule('/Alice/');
    assert.equal(core.userMatchesRule('Alice', rule), true);
    assert.equal(core.userMatchesRule('alice', rule), false);
});

test('rejects unsupported regex flags, long patterns, and nested quantifiers', () => {
    assert.throws(() => core.compileUserRule('/alice/g'));
    assert.throws(() => core.compileUserRule(`/${'a'.repeat(121)}/`));
    assert.throws(() => core.compileUserRule('/(a+)+/'));
});

test('filters explicit custom content rules, exempts trusted users, and scores default risks', () => {
    const config = { users: [], trustedUsers: ['trusted'], words: ['custom-block'], regex: ['/custom\\d+/'] };
    const engine = core.createFilterEngine(config, defaults);
    assert.equal(engine.shouldFilter({ id: '1', text: 'custom-block', userId: 'any' }).reason.source, 'user-keyword');
    assert.equal(engine.shouldFilter({ id: '2', text: 'custom123', userId: 'any' }).reason.source, 'user-regex');
    assert.equal(engine.shouldFilter({ id: '3', text: 'custom-block default-risk', userId: 'trusted' }).shouldHide, false);
    assert.equal(engine.shouldFilter({ id: '4', text: 'default-risk default-regex', userId: 'any' }).reason.source, 'risk-score');
    assert.equal(engine.shouldFilter({ id: '5', text: 'default-risk only', userId: 'any' }).shouldHide, false);
});

test('accepts only official X API hosts', () => {
    assert.equal(core.isXApiUrl('https://api.x.com/i/api'), true);
    assert.equal(core.isXApiUrl('https://api.twitter.com/1.1'), true);
    assert.equal(core.isXApiUrl('https://api.x.com.attacker.example/i/api'), false);
});

class NodeFixture {
    constructor(testid, text = '') { this.testid = testid; this.innerText = text; this.dataset = {}; this.style = {}; this.parent = null; }
    closest(selector) { return selector === '[data-testid="cellInnerDiv"]' ? this.parent : null; }
}
function integrationFixture(config) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'X-Twitter-intercept-Malicious-advertising.user.js'), 'utf8');
    const start = source.indexOf('    let ProcessedTweets = new WeakSet();');
    const end = source.indexOf('    // ─────────────────────────────────────────────\n    //  Batch queue', start);
    const engine = core.createFilterEngine(config, { users: [], words: [], regex: [] });
    const cell = new NodeFixture('cellInnerDiv');
    const tweet = new NodeFixture('tweet'); tweet.parent = cell;
    const text = new NodeFixture('tweetText', 'block me');
    const user = new NodeFixture('User-Name', 'Alice\n@alice');
    const status = { pathname: '/alice/status/42' };
    tweet.querySelector = selector => ({ '[data-testid="tweetText"]': text, '[data-testid="User-Name"]': user, 'a[href*="/status/"]': status, 'a[href^="/"][role="link"]': null }[selector] || null);
    const document = { querySelectorAll: selector => selector === 'article[data-testid="tweet"]' ? [tweet] : [] };
    const create = new Function('FilterEngine', 'document', 'cleanText', `function shouldFilter(data) { return FilterEngine.shouldFilter(data); }\n${source.slice(start, end)}; return { parseTweet, reevaluateTweets };`);
    return { tweet, cell, api: create(engine, document, value => String(value || '').trim()), engine };
}

test('DOM fixture parses a tweet and reevaluates it through hide and restore paths', () => {
    const config = { users: [], trustedUsers: [], words: ['block me'], regex: [] };
    const fixture = integrationFixture(config);
    assert.deepEqual(fixture.api.parseTweet(fixture.tweet), { id: '42', text: 'block me', userName: 'Alice', userId: 'alice' });
    fixture.api.reevaluateTweets();
    assert.equal(fixture.cell.style.display, 'none');
    config.words = [];
    fixture.engine.reload();
    fixture.api.reevaluateTweets();
    assert.equal(fixture.cell.style.display, '');
    assert.equal(fixture.cell.dataset.xFiltered, undefined);
});
