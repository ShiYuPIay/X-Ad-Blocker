'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

class FixtureNode {
    constructor({ testid, ariaLabel = '', text = '', children = [] } = {}) {
        this.testid = testid;
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
            (...args) => logs.push(args)
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
