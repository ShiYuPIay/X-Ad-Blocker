'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

class FixtureNode {
    constructor({ testid, ariaLabel = '', text = '', children = [], throwSelectors = [] } = {}) {
        this.testid = testid;
        this.throwSelectors = new Set(throwSelectors);
        this.ariaLabel = ariaLabel;
        this.textContent = text;
        this.children = children;
        this.parent = null;
        this.dataset = {};
        this.style = {};
        for (const child of children) child.parent = this;
    }

    getAttribute(name) {
        return name === 'aria-label' ? this.ariaLabel : null;
    }

    matches(selector) {
        return selector === `[data-testid="${this.testid}"]`;
    }

    closest(selector) {
        for (let node = this; node; node = node.parent) {
            if (node.matches(selector)) return node;
        }
        return null;
    }

    querySelectorAll(selector) {
        if (this.throwSelectors.has(selector)) throw new Error(`Invalid selector: ${selector}`);
        return this.children.flatMap(child => [
            ...(child.matches(selector) ? [child] : []),
            ...child.querySelectorAll(selector)
        ]);
    }
}

function adDetectionFixture(debug = false) {
    const source = fs.readFileSync(
        path.join(__dirname, '..', 'X-Twitter-intercept-Malicious-advertising.user.js'),
        'utf8'
    );
    const start = source.indexOf('    const AD_SELECTORS =');
    const end = source.indexOf('    // ─────────────────────────────────────────────\n    //  MutationObserver', start);
    assert.notEqual(start, -1, 'ad detection section should exist');
    assert.notEqual(end, -1, 'ad detection section should have a clear boundary');

    const logs = [];
    const createDetection = new Function('cleanText', 'debugWarn', `
        const CONFIG = { debug: ${debug} };
        ${source.slice(start, end)}
        return { cleanAds };
    `);
    return {
        detection: createDetection(
            value => String(value || '').replace(/[\u200B-\u200F\uFEFF\u2060]/g, '').trim(),
            (...args) => {
                if (debug) logs.push(args);
            }
        ),
        logs
    };
}

function cell(child) {
    return new FixtureNode({ testid: 'cellInnerDiv', children: [child] });
}

test('hides the stable placementTracking ad fixture', () => {
    const placement = new FixtureNode({ testid: 'placementTracking' });
    const root = new FixtureNode({ children: [cell(placement)] });

    adDetectionFixture().detection.cleanAds(root);

    assert.equal(placement.parent.style.display, 'none');
});

test('hides an English promoted social-context fixture using aria-label', () => {
    const context = new FixtureNode({ testid: 'socialContext', ariaLabel: ' Promoted ' });
    const root = new FixtureNode({ children: [cell(context)] });

    adDetectionFixture().detection.cleanAds(root);

    assert.equal(context.parent.style.display, 'none');
});

test('hides a Chinese promoted social-context fixture using normalized text', () => {
    const context = new FixtureNode({ testid: 'socialContext', text: '\u200b 广告\n' });
    const root = new FixtureNode({ children: [cell(context)] });

    adDetectionFixture().detection.cleanAds(root);

    assert.equal(context.parent.style.display, 'none');
});

test('keeps an unknown social-context label visible and only logs it in debug mode', () => {
    const context = new FixtureNode({ testid: 'socialContext', ariaLabel: 'Annonce inconnue' });
    const root = new FixtureNode({ children: [cell(context)] });
    const normal = adDetectionFixture();
    const debug = adDetectionFixture(true);

    normal.detection.cleanAds(root);
    assert.equal(context.parent.style.display, undefined);
    assert.deepEqual(normal.logs, []);

    debug.detection.cleanAds(root);
    assert.equal(debug.logs.length, 1);
    assert.match(debug.logs[0][0], /Unrecognized social context label/);
});

test('does not hide an ordinary tweet merely because its text says Promoted', () => {
    const tweet = new FixtureNode({ testid: 'tweet', text: 'Promoted thoughts are welcome.' });
    const root = new FixtureNode({ children: [cell(tweet)] });

    adDetectionFixture().detection.cleanAds(root);

    assert.equal(tweet.parent.style.display, undefined);
});


test('continues social-context detection after an ad selector fails and only logs in debug mode', () => {
    const selector = '[data-testid="placementTracking"]';
    const createRoot = () => {
        const context = new FixtureNode({ testid: 'socialContext', ariaLabel: 'Promoted' });
        return { context, root: new FixtureNode({ children: [cell(context)], throwSelectors: [selector] }) };
    };

    const normalFixture = createRoot();
    const normal = adDetectionFixture();
    normal.detection.cleanAds(normalFixture.root);
    assert.equal(normalFixture.context.parent.style.display, 'none');
    assert.deepEqual(normal.logs, []);

    const debugFixture = createRoot();
    const debug = adDetectionFixture(true);
    debug.detection.cleanAds(debugFixture.root);
    assert.equal(debugFixture.context.parent.style.display, 'none');
    assert.equal(debug.logs.length, 1);
    assert.match(debug.logs[0][0], /Could not apply ad selector/);
    assert.equal(debug.logs[0][1] instanceof Error, true);
});

test('storage write failures return false and include the operation, key, and error in debug logs', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', 'X-Twitter-intercept-Malicious-advertising.user.js'),
        'utf8'
    );
    const storageStart = source.indexOf('    const Storage =');
    const storageEnd = source.indexOf('    // ─────────────────────────────────────────────\n    //  Default filter rules', storageStart);
    const warnings = [];
    const createStorage = new Function('GM_getValue', 'GM_setValue', 'GM_setClipboard', 'localStorage', 'navigator', 'console', `
        let CONFIG = { debug: true };
        function debugWarn(message, error) {
            if (CONFIG.debug) console.warn(message, error);
        }
        ${source.slice(storageStart, storageEnd)}
        return Storage;
    `);
    const writeError = new Error('Storage quota exceeded');
    const storage = createStorage(
        undefined,
        undefined,
        undefined,
        { getItem: () => null, setItem: () => { throw writeError; } },
        {},
        { warn: (...args) => warnings.push(args) }
    );

    assert.equal(storage.set('XFilterConfig', { users: [] }), false);
    assert.match(warnings[0][0], /Storage\.set failed for key: XFilterConfig/);
    assert.equal(warnings[0][1], writeError);
});

function sensitiveContentFixture(debug = false) {
    const source = fs.readFileSync(
        path.join(__dirname, '..', 'X-Twitter-intercept-Malicious-advertising.user.js'),
        'utf8'
    );
    const start = source.indexOf('    function isXApiUrl(url, base) {');
    const end = source.indexOf('    // ─────────────────────────────────────────────\n    //  Settings panel UI', start);
    assert.notEqual(start, -1, 'sensitive-content section should exist');
    assert.notEqual(end, -1, 'sensitive-content section should have a clear boundary');

    const logs = [];
    const pageWindow = {
        location: { href: 'https://x.com/home' },
        Response,
        fetch: async () => { throw new Error('Test fetch implementation was not provided'); }
    };
    const createUnlocker = new Function('CONFIG', 'unsafeWindow', 'window', 'XFilterCore', 'debugWarn', `
        ${source.slice(start, end)}
        return unlockSensitive;
    `);
    return {
        logs,
        pageWindow,
        unlock: createUnlocker(
            { unlockSensitive: true, debug },
            pageWindow,
            pageWindow,
            require('../lib/filter-core'),
            (...args) => { if (debug) logs.push(args); }
        )
    };
}

test('sensitive-content fetch hook only patches successful JSON responses from X APIs and logs installation in debug mode', async () => {
    const { logs, pageWindow, unlock } = sensitiveContentFixture(true);
    const responseFor = (body, { url = 'https://api.x.com/2/timeline', contentType = 'application/json', status = 200 } = {}) =>
        new Response(body, { status, headers: { 'content-type': contentType } });

    pageWindow.fetch = async request => responseFor('{"possibly_sensitive":true}', request);
    unlock();

    assert.equal(pageWindow.__X_FILTER_FETCH_PATCHED__, true);
    assert.equal(logs.length, 1);
    assert.match(logs[0][0], /Sensitive-content fetch hook installed/);

    const patched = await pageWindow.fetch({ url: 'https://api.x.com/2/timeline' });
    assert.equal(await patched.text(), '{"possibly_sensitive":false}');

    const external = await pageWindow.fetch({ url: 'https://example.com/data' });
    assert.equal(await external.text(), '{"possibly_sensitive":true}');

    const nonJson = await pageWindow.fetch({ url: 'https://api.x.com/2/timeline', contentType: 'text/plain' });
    assert.equal(await nonJson.text(), '{"possibly_sensitive":true}');

    const failed = await pageWindow.fetch({ url: 'https://api.x.com/2/timeline', status: 403 });
    assert.equal(await failed.text(), '{"possibly_sensitive":true}');
});

test('settings describe sensitive-content modification as best effort', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', 'X-Twitter-intercept-Malicious-advertising.user.js'),
        'utf8'
    );

    assert.match(source, /尝试修改部分 X API fetch 响应；X 的请求实现变化时可能无效/);
    assert.doesNotMatch(source, /XMLHttpRequest/);
});

test('userscript branding selects concise Chinese or English copy from browser language', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', 'X-Twitter-intercept-Malicious-advertising.user.js'),
        'utf8'
    );

    const start = source.indexOf('    const UI_COPY =');
    const end = source.indexOf('    const Storage =', start);
    assert.notEqual(start, -1, 'UI copy should be declared');
    assert.notEqual(end, -1, 'UI copy should precede storage setup');
    const getUiText = new Function('navigator', `${source.slice(start, end)} return getUiText;`)({ languages: ['en-US'] });

    assert.equal(getUiText(['zh-CN']).name, 'X 广告拦截');
    assert.equal(getUiText(['zh-TW']).description, '屏蔽推广、垃圾内容和诈骗帖');
    assert.equal(getUiText(['en-US']).name, 'X Ad Blocker');
    assert.match(getUiText(['en-GB']).openSettings, /Open X Ad Blocker settings/);
    assert.match(source, /@name:zh-CN\s+X 广告拦截/);
    assert.match(source, /@name\s+X Ad Blocker/);
    assert.match(source, /<svg class="brand-icon"/);
});
