// ==UserScript==
// @name         X-Twitter-intercept-Malicious-advertising.user.js
// @namespace    https://github.com/ShiYuPIay/X-Twitter-intercept-Malicious-advertising/tree/main 
// @version      1.1.0
// @description  X/Twitter spam filter, bot detection, ad blocking and scam detection — fixed edition
// @compatible    Chrome 80+, Firefox 74+, Safari 13.1+ (optional chaining support required)
// @author       Via && ShiYuPIay
// @license      MIT
// @match        https://x.com/*
// @match        https://twitter.com/*
// @run-at       document-end
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_setClipboard
// ==/UserScript==

/*
  Fixes vs 4.1:
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ 1. IIFE was split in two — everything after "Part 1 END" ran in global      │
  │    scope and couldn't access cleanText, Keyword, CONFIG, etc.               │
  │    → Merged into one IIFE.                                                  │
  │                                                                             │
  │ 2. Orphaned })(); at end-of-file caused a SyntaxError.                      │
  │    → Removed (single IIFE close is now at the very bottom).                 │
  │                                                                             │
  │ 3. detectBot regex missing delimiters: (.)\1{6,}  → /(.)\1{6,}/            │
  │                                                                             │
  │ 4. spamScore was dead code — shouldFilter never called it.                  │
  │    → shouldFilter now uses spamScore() with a SPAM_THRESHOLD of 40.         │
  │                                                                             │
  │ 5. Ad selector "article:has(span)" matched virtually every tweet.           │
  │    → Replaced with targeted aria-label / data-testid selectors.             │
  │                                                                             │
  │ 6. cleanAds() was driven by setInterval(3000) while tweets used             │
  │    MutationObserver. → Moved ad cleaning into the same observer.            │
  │                                                                             │
  │ 7. unlockSensitive patched window.fetch globally, corrupting any            │
  │    response containing "possibly_sensitive".                                │
  │    → Now scoped to api.twitter.com / api.x.com responses only.             │
  └─────────────────────────────────────────────────────────────────────────────┘
*/

(function () {
    "use strict";

    if (window.__X_FILTER_ENHANCED_LOADED__) return;
    window.__X_FILTER_ENHANCED_LOADED__ = true;

    // ─────────────────────────────────────────────
    //  Storage API
    // ─────────────────────────────────────────────

    const Storage = {
        get(key, def) {
            try {
                if (typeof GM_getValue === "function") return GM_getValue(key, def);
                const v = localStorage.getItem(key);
                return v ? JSON.parse(v) : def;
            } catch (e) { return def; }
        },
        set(key, value) {
            try {
                if (typeof GM_setValue === "function") GM_setValue(key, value);
                else localStorage.setItem(key, JSON.stringify(value));
            } catch (e) {}
        },
        copy(text) {
            try {
                if (typeof GM_setClipboard === "function") GM_setClipboard(text);
                else navigator.clipboard.writeText(text);
            } catch (e) {}
        }
    };

    // ─────────────────────────────────────────────
    //  Default filter rules
    // ─────────────────────────────────────────────

    const DEFAULT_RULES = {
        users: [
            "@telegram", "@onlyfans", "@fansly", "@casino",
            "@giveaway", "@airdrop", "@crypto", "@betting", "@escort",
            "ruantang992", "xiaonm88"
        ],
        words: [
            // 色情诱导
            "约炮", "免费约", "上门服务", "同城服务", "裸聊",
            "视频私聊", "成人资源", "福利姬", "色播", "直播福利",
            // 广告
            "扫码领取", "点击领取", "免费领取", "加微信",
            "联系方式", "私聊我", "主页有资源", "置顶获取",
            // 诈骗
            "日赚", "兼职赚钱", "稳赚", "投资返利",
            "高收益", "刷流水", "博彩", "下注", "代理招商", "内部渠道",
            // 虚拟币诈骗
            "USDT兼职", "空投", "合约带单", "稳赚币", "矿机",
            // 机器人
            "🔥🔥🔥🔥", "💎💎💎💎", "福利群", "资源群", "加入群聊"
        ],
        regex: [
            /(?:加|联系|私).{0,3}(?:微信|QQ|telegram|tg)/i,
            /(?:免费|低价).{0,5}(?:资源|福利|视频|图片)/i,
            /(?:日赚|月入).{0,10}(?:万|千|元)/i,
            /(?:投资|充值).{0,10}(?:返利|收益|赚钱)/i,
            /(?:USDT|BTC|ETH).{0,20}(?:赚钱|带单|收益)/i,
            /^[🔥💎⭐✨🚀]{5,}$/
        ]
    };

    // ─────────────────────────────────────────────
    //  User config
    // ─────────────────────────────────────────────

    let CONFIG = Object.assign(
        { users: [], words: [], trustedUsers: [], disabledUsers: [], disabledWords: [], unlockSensitive: true },
        Storage.get("XFilterConfig", {})
    );

    // ─────────────────────────────────────────────
    //  Cache helpers
    // ─────────────────────────────────────────────

    const TextCache = new Map();
    const CACHE_LIMIT = 5000;

    function cacheSet(map, key, value) {
        // Map insertion order makes this a compact LRU cache: refreshing a key
        // moves it to the end and eviction always removes the least-recent entry.
        if (map.has(key)) map.delete(key);
        map.set(key, value);
        if (map.size > CACHE_LIMIT) map.delete(map.keys().next().value);
    }

    function cleanText(text) {
        if (!text) return "";
        if (TextCache.has(text)) {
            const cached = TextCache.get(text);
            cacheSet(TextCache, text, cached);
            return cached;
        }
        const result = text.replace(/[\u200B-\u200F\uFEFF\u2060]/g, "").trim();
        cacheSet(TextCache, text, result);
        return result;
    }

    // ─────────────────────────────────────────────
    //  Keyword engine
    // ─────────────────────────────────────────────

    class KeywordEngine {
        constructor() {
            this.set = new Set();
            this.reload();
        }
        reload() {
            this.set.clear();
            [...DEFAULT_RULES.words, ...CONFIG.words]
                .forEach(w => this.set.add(w.toLowerCase()));
        }
        match(text) {
            const lower = text.toLowerCase();
            for (const word of this.set) {
                if (lower.includes(word)) return true;
            }
            return false;
        }
    }

    const Keyword = new KeywordEngine();

    // ─────────────────────────────────────────────
    //  Regex engine
    // ─────────────────────────────────────────────

    const RegexRules = [...DEFAULT_RULES.regex];

    function matchRegex(text) {
        for (const reg of RegexRules) {
            if (reg.test(text)) return true;
        }
        return false;
    }

    // ─────────────────────────────────────────────
    //  Risk scoring — FIX: was defined but never called; now used by shouldFilter
    // ─────────────────────────────────────────────

    const SPAM_THRESHOLD = 60;

    function spamScore(data) {
        let score = 0;
        const text = data.text.toLowerCase();
        if (Keyword.match(text))           score += 40;
        if (matchRegex(text))              score += 40;
        if (text.length < 8)              score += 10;
        if (/(.)\1{5,}/.test(text))       score += 20;
        if (/[🔥💎⭐🚀]{5,}/.test(text)) score += 20;
        return score;
    }

    // ─────────────────────────────────────────────
    //  Tweet cache
    // ─────────────────────────────────────────────

    const ProcessedTweets = new WeakSet();
    const TweetCache = new Map();
    const MAX_TWEET_CACHE = 8000;

    function cacheTweet(id, value) {
        if (TweetCache.has(id)) TweetCache.delete(id);
        TweetCache.set(id, value);
        if (TweetCache.size > MAX_TWEET_CACHE) {
            TweetCache.delete(TweetCache.keys().next().value);
        }
    }

    // ─────────────────────────────────────────────
    //  User blocklist check
    // ─────────────────────────────────────────────

    function normalizeUserRule(value) {
        return String(value || "").trim().toLowerCase().replace(/^@/, "");
    }

    function userMatchesRule(user, rule) {
        const normalizedUser = normalizeUserRule(user);
        const normalizedRule = normalizeUserRule(rule);
        if (!normalizedUser || !normalizedRule) return false;
        if (normalizedRule.length > 2 && normalizedRule[0] === "/" && normalizedRule.lastIndexOf("/") > 0) {
            const lastSlash = normalizedRule.lastIndexOf("/");
            try {
                return new RegExp(normalizedRule.slice(1, lastSlash), normalizedRule.slice(lastSlash + 1)).test(normalizedUser);
            } catch (e) { return false; }
        }
        return normalizedUser === normalizedRule;
    }

    function checkUser(userId, userName) {
        if (!userId && !userName) return false;
        const list = [...DEFAULT_RULES.users, ...CONFIG.users];
        return list.some(rule => userMatchesRule(userId, rule) || userMatchesRule(userName, rule));
    }

    function isTrustedUser(userId, userName) {
        return (CONFIG.trustedUsers || []).some(rule =>
            userMatchesRule(userId, rule) || userMatchesRule(userName, rule)
        );
    }

    // ─────────────────────────────────────────────
    //  Bot detection
    //  FIX: regex was written as bare  (.)\1{6,}  without /…/ delimiters
    //       → SyntaxError at parse time; corrected to  /(.)\1{6,}/
    // ─────────────────────────────────────────────

    function detectBot(text, userName) {
        if (!text) return false;
        let score = 0;

        if (/(.)\1{6,}/.test(text)) score += 25;

        const emojiCount = (text.match(/[\u{1F300}-\u{1FAFF}]/gu) || []).length;
        if (emojiCount >= 8) score += 20;

        if (/👇|⬇|👉|点击|领取|加入/.test(text)) score += 20;

        if (text.length < 6) score += 10;

        if (userName && /福利|资源|兼职|客服|官方|bot|机器人/i.test(userName)) score += 30;

        return score >= 50;
    }

    // ─────────────────────────────────────────────
    //  Tweet parsing
    // ─────────────────────────────────────────────

    function parseTweet(tweet) {
        const textNode = tweet.querySelector('[data-testid="tweetText"]');
        const text     = cleanText(textNode ? textNode.innerText : "");

        const userNode = tweet.querySelector('[data-testid="User-Name"]');
        const userName = cleanText(userNode ? userNode.innerText.split("\n")[0] : "");

        const avatar = tweet.querySelector('[data-testid^="UserAvatar"]');
        const userId = avatar
            ? avatar.getAttribute("data-testid").replace("UserAvatar-Container-", "")
            : "";

        const link = tweet.querySelector('a[href*="/status/"]');
        const statusPart = link ? link.href.split("/status/")[1] : "";
        const id   = statusPart ? statusPart.split("?")[0] : "";

        return { id, text, userName, userId };
    }

    // ─────────────────────────────────────────────
    //  Filter decision
    //  FIX: now routes through spamScore() instead of calling Keyword /
    //       matchRegex / detectBot individually (spamScore was dead code before)
    // ─────────────────────────────────────────────

    function shouldFilter(data) {
        if (!data.text && !data.userName) return false;

        const key = data.id || data.text;
        if (TweetCache.has(key)) {
            const cached = TweetCache.get(key);
            cacheTweet(key, cached);
            return cached;
        }

        const trusted = isTrustedUser(data.userId, data.userName);
        const result = !trusted && (
            checkUser(data.userId, data.userName) ||
            spamScore(data) >= SPAM_THRESHOLD ||
            detectBot(data.text, data.userName)
        );

        cacheTweet(key, result);
        return result;
    }

    // ─────────────────────────────────────────────
    //  Hide tweet
    // ─────────────────────────────────────────────

    function hideTweet(tweet) {
        const container = tweet.closest('[data-testid="cellInnerDiv"]') || tweet;
        if (container.dataset.xFiltered) return;
        container.dataset.xFiltered = "true";
        container.style.display = "none";
    }

    // ─────────────────────────────────────────────
    //  Process single tweet
    // ─────────────────────────────────────────────

    function processTweet(tweet) {
        if (!tweet || ProcessedTweets.has(tweet)) return;
        ProcessedTweets.add(tweet);
        const data = parseTweet(tweet);
        if (shouldFilter(data)) hideTweet(tweet);
    }

    // ─────────────────────────────────────────────
    //  Batch queue (250 ms debounce)
    // ─────────────────────────────────────────────

    const Queue = new Set();
    let queueTimer = null;

    function addQueue(tweet) {
        Queue.add(tweet);
        if (queueTimer) return;
        queueTimer = setTimeout(() => {
            for (const item of Queue) processTweet(item);
            Queue.clear();
            queueTimer = null;
        }, 250);
    }

    // ─────────────────────────────────────────────
    //  Ad cleaning
    //  FIX 1: "article:has(span)" matched virtually every tweet — replaced with
    //          targeted aria-label / data-testid selectors.
    //  FIX 2: was driven by setInterval(3000); moved into the MutationObserver
    //          so ads are hidden as soon as they appear, with zero polling cost.
    // ─────────────────────────────────────────────

    const AD_SELECTORS = [
        '[data-testid="placementTracking"]',
        '[data-testid="socialContext"][aria-label="Promoted"]',
        '[data-testid="socialContext"][aria-label="广告"]',
        '[data-testid="socialContext"][aria-label="Sponsored"]'
    ];

    function hideAdNode(el) {
        const container = el.closest('[data-testid="cellInnerDiv"]') || el;
        if (!container.dataset.xAdFiltered) {
            container.dataset.xAdFiltered = "true";
            container.style.display = "none";
        }
    }

    function cleanAds(root) {
        const search = root || document;
        for (const selector of AD_SELECTORS) {
            try {
                if (root && root.matches && root.matches(selector)) hideAdNode(root);
                search.querySelectorAll(selector).forEach(hideAdNode);
            } catch (e) {}
        }
    }

    // ─────────────────────────────────────────────
    //  MutationObserver — handles tweets + ads together
    // ─────────────────────────────────────────────

    function startObserver() {
        const target = document.querySelector("main") || document.body;
        if (!target) return;

        new MutationObserver(mutations => {
            for (const { addedNodes } of mutations) {
                for (const node of addedNodes) {
                    if (node.nodeType !== 1) continue;

                    if (node.matches && node.matches('article[data-testid="tweet"]')) {
                        addQueue(node);
                    } else {
                        node.querySelectorAll?.('article[data-testid="tweet"]')
                            .forEach(t => addQueue(t));
                    }

                    cleanAds(node);
                }
            }
        }).observe(target, { childList: true, subtree: false });
    }

    // ─────────────────────────────────────────────
    //  Initial scan
    // ─────────────────────────────────────────────

    function initialScan() {
        document.querySelectorAll('article[data-testid="tweet"]')
            .forEach(t => addQueue(t));
        cleanAds();
    }

    // ─────────────────────────────────────────────
    //  Sensitive content unlock
    //  FIX: original patched window.fetch globally, corrupting any response
    //       that happened to contain "possibly_sensitive" (e.g. analytics,
    //       third-party requests). Now scoped to api.twitter.com / api.x.com.
    // ─────────────────────────────────────────────

    const ResponsePatchCache = new Map();
    const RESPONSE_CACHE_LIMIT = 100;

    function cachePatchedResponse(key, source, patched) {
        if (ResponsePatchCache.has(key)) ResponsePatchCache.delete(key);
        ResponsePatchCache.set(key, { source, patched });
        if (ResponsePatchCache.size > RESPONSE_CACHE_LIMIT) {
            ResponsePatchCache.delete(ResponsePatchCache.keys().next().value);
        }
    }

    function unlockSensitive() {
        if (!CONFIG.unlockSensitive) return;
        const originalFetch = window.fetch;
        window.fetch = function (...args) {
            return originalFetch.apply(this, args).then(async response => {
                const url = typeof args[0] === "string"
                    ? args[0]
                    : (args[0]?.url || "");
                if (!url.includes("api.twitter.com") && !url.includes("api.x.com")) {
                    return response;
                }
                try {
                    const text = await response.clone().text();
                    if (!text.includes('"possibly_sensitive":true')) return response;
                    const cached = ResponsePatchCache.get(url);
                    const patched = cached && cached.source === text
                        ? cached.patched
                        : text.replace(/"possibly_sensitive":true/g, '"possibly_sensitive":false');
                    if (!cached || cached.source !== text) cachePatchedResponse(url, text, patched);
                    return new Response(patched, {
                        status:     response.status,
                        statusText: response.statusText,
                        headers:    response.headers
                    });
                } catch (e) {
                    return response;
                }
            });
        };
    }

    // ─────────────────────────────────────────────
    //  Settings panel UI
    // ─────────────────────────────────────────────

    function createPanel() {
        const box = document.createElement("div");
        box.id = "x-filter-panel";
        box.attachShadow({ mode: "open" });
        const shadow = box.shadowRoot;

        const style = document.createElement("style");
        style.textContent = `
            #button {
                position: fixed; right: 20px; top: 76px;
                width: 45px; height: 45px; border-radius: 50%;
                background: #1d9bf0; color: white;
                display: flex; align-items: center; justify-content: center;
                cursor: pointer; z-index: 999999; font-size: 20px;
                box-shadow: 0 2px 8px rgba(0,0,0,.3);
                user-select: none;
            }
            #button:hover { background: #1a8cd8; }
            #panel {
                display: none; position: fixed;
                right: 20px; top: 130px; width: 350px;
                background: white; color: #111;
                border-radius: 16px; padding: 20px;
                box-shadow: 0 10px 40px rgba(0,0,0,.25);
                z-index: 999999; font-family: sans-serif;
            }
            textarea {
                width: 100%; height: 120px; margin-bottom: 10px;
                border-radius: 8px; padding: 8px;
                box-sizing: border-box; border: 1px solid #ccc; font-size: 13px;
            }
            button {
                padding: 8px 12px; border: 0; border-radius: 8px;
                cursor: pointer; background: #1d9bf0; color: white;
                margin-top: 5px; margin-right: 4px; font-size: 13px;
            }
            button:hover { background: #1a8cd8; }
            h3 { margin-top: 0; cursor: move; }
            p  { margin: 8px 0 4px; font-size: 13px; }
        `;
        shadow.appendChild(style);

        const wrap = document.createElement("div");
        wrap.innerHTML = `
            <div id="button">⚙</div>
            <div id="panel">
                <h3 id="title">X Filter 4.1</h3>
                <p>屏蔽用户（每行一个；支持精确用户名或 <code>/正则/</code>）</p>
                <textarea id="users"></textarea>
                <p>信任用户（每行一个，不会被此脚本隐藏）</p>
                <textarea id="trusted-users"></textarea>
                <p>屏蔽关键词（每行一个）</p>
                <textarea id="words"></textarea>
                <p><label><input id="unlock-sensitive" type="checkbox"> 解锁敏感内容（拦截 X API fetch）</label></p>
                <div>
                    <button id="save">保存规则</button>
                    <button id="export">导出规则</button>
                    <button id="reset">恢复默认</button>
                </div>
            </div>
        `;
        shadow.appendChild(wrap);

        const btn   = shadow.querySelector("#button");
        const panel = shadow.querySelector("#panel");
        const users = shadow.querySelector("#users");
        const trustedUsers = shadow.querySelector("#trusted-users");
        const words = shadow.querySelector("#words");
        const unlockSensitiveCheckbox = shadow.querySelector("#unlock-sensitive");

        users.value = CONFIG.users.join("\n");
        trustedUsers.value = (CONFIG.trustedUsers || []).join("\n");
        words.value = CONFIG.words.join("\n");
        unlockSensitiveCheckbox.checked = CONFIG.unlockSensitive !== false;

        const savedPosition = Storage.get("XFilterPanelPosition", null);
        if (savedPosition && Number.isFinite(savedPosition.left) && Number.isFinite(savedPosition.top)) {
            panel.style.left = savedPosition.left + "px";
            panel.style.top = savedPosition.top + "px";
            panel.style.right = "auto";
        }

        btn.onclick = () => {
            panel.style.display = panel.style.display === "block" ? "none" : "block";
        };

        shadow.querySelector("#save").onclick = () => {
            CONFIG.users = users.value.split("\n").map(x => x.trim()).filter(Boolean);
            CONFIG.trustedUsers = trustedUsers.value.split("\n").map(x => x.trim()).filter(Boolean);
            CONFIG.words = words.value.split("\n").map(x => x.trim()).filter(Boolean);
            CONFIG.unlockSensitive = unlockSensitiveCheckbox.checked;
            Storage.set("XFilterConfig", CONFIG);
            Keyword.reload();
            TweetCache.clear();
            alert("规则已保存。敏感内容拦截开关会在下次页面加载时生效。");
        };

        shadow.querySelector("#export").onclick = () => {
            Storage.copy(JSON.stringify(CONFIG, null, 2));
            alert("规则已复制到剪贴板");
        };

        shadow.querySelector("#reset").onclick = () => {
            if (confirm("恢复默认规则？自定义规则将被清除。")) {
                CONFIG = { users: [], words: [], trustedUsers: [], disabledUsers: [], disabledWords: [], unlockSensitive: true };
                Storage.set("XFilterConfig", CONFIG);
                location.reload();
            }
        };

        let dragOffset = null;
        shadow.querySelector("#title").addEventListener("pointerdown", event => {
            const bounds = panel.getBoundingClientRect();
            dragOffset = { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
            event.currentTarget.setPointerCapture(event.pointerId);
        });
        shadow.querySelector("#title").addEventListener("pointermove", event => {
            if (!dragOffset) return;
            const left = Math.max(0, Math.min(window.innerWidth - panel.offsetWidth, event.clientX - dragOffset.x));
            const top = Math.max(0, Math.min(window.innerHeight - panel.offsetHeight, event.clientY - dragOffset.y));
            panel.style.left = left + "px";
            panel.style.top = top + "px";
            panel.style.right = "auto";
        });
        shadow.querySelector("#title").addEventListener("pointerup", () => {
            if (!dragOffset) return;
            Storage.set("XFilterPanelPosition", {
                left: parseInt(panel.style.left, 10), top: parseInt(panel.style.top, 10)
            });
            dragOffset = null;
        });

        document.body.appendChild(box);
    }

    // ─────────────────────────────────────────────
    //  Boot
    // ─────────────────────────────────────────────

    function boot() {
        createPanel();
        initialScan();
        startObserver();
        unlockSensitive();
        console.log(
            "%c X Filter 4.1 Loaded ",
            "background:#1d9bf0;color:white;padding:5px;border-radius:4px"
        );
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot, { once: true });
    } else {
        boot();
    }

// ─── single IIFE close — nothing runs outside this scope ───────────────────
})();
