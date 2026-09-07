// ==UserScript==
// @name         X-Twitter-intercept-Malicious-advertising.user.js
// @namespace    https://github.com/ShiYuPIay/X-Twitter-intercept-Malicious-advertising/tree/main 
// @version      1.2.0
// @description  X/Twitter spam filter, bot detection, ad blocking and scam detection — fixed edition
// @compatible    Chrome 80+, Firefox 74+, Safari 13.1+ (optional chaining support required)
// @author       Via && ShiYuPIay
// @license      MIT
// @match        https://x.com/*
// @match        https://twitter.com/*
// @updateURL     https://raw.githubusercontent.com/ShiYuPIay/X-Twitter-intercept-Malicious-advertising/main/X-Twitter-intercept-Malicious-advertising.user.js
// @downloadURL   https://raw.githubusercontent.com/ShiYuPIay/X-Twitter-intercept-Malicious-advertising/main/X-Twitter-intercept-Malicious-advertising.user.js
// @run-at       document-start
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_setClipboard
// @grant        unsafeWindow
// ==/UserScript==

/*
 * X Filter 1.2.0: performance-oriented tweet/ad filtering with configurable
 * trusted-user rules and an opt-in, page-context sensitive-content fetch patch.
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
        async copy(text) {
            if (typeof GM_setClipboard === "function") {
                GM_setClipboard(text);
                return true;
            }
            await navigator.clipboard.writeText(text);
            return true;
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
        { users: [], words: [], regex: [], trustedUsers: [], unlockSensitive: false, debug: false },
        Storage.get("XFilterConfig", {})
    );
    // Remove fields from old releases that were never implemented.
    delete CONFIG.disabledUsers;
    delete CONFIG.disabledWords;
    // Older saved configurations do not have custom regular expressions.
    if (!Array.isArray(CONFIG.regex)) CONFIG.regex = [];

    function debugWarn(message, error) {
        if (CONFIG.debug) console.warn("[X Filter 1.2.0] " + message, error || "");
    }

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
            this.defaultWords = new Set();
            this.userWords = new Set();
            this.reload();
        }
        reload() {
            this.defaultWords = new Set(DEFAULT_RULES.words.map(word => word.toLowerCase()));
            this.userWords = new Set((CONFIG.words || []).map(word => word.toLowerCase()));
        }
        matchWords(text, words, source) {
            const lower = text.toLowerCase();
            for (const word of words) {
                if (lower.includes(word)) return createMatchReason(source, { word });
            }
            return null;
        }
        matchDefault(text) {
            return this.matchWords(text, this.defaultWords, "default-keyword");
        }
        matchUser(text) {
            return this.matchWords(text, this.userWords, "user-keyword");
        }
    }

    const Keyword = new KeywordEngine();

    // ─────────────────────────────────────────────
    //  Regex engine
    // ─────────────────────────────────────────────

    const DefaultRegexRules = [...DEFAULT_RULES.regex];
    let UserRegexRules = [];

    const MATCH_REASON_LABELS = {
        "user-keyword": "用户关键词命中",
        "user-regex": "用户正则命中",
        "default-keyword": "默认关键词命中",
        "default-regex": "默认正则命中",
        "blocked-user": "屏蔽用户命中",
        "risk-score": "风险评分命中",
        "bot-detection": "机器人检测命中"
    };

    function createMatchReason(source, details) {
        return Object.assign({ source, label: MATCH_REASON_LABELS[source] || source }, details);
    }

    function matchRegex(text, rules, source) {
        for (const rule of rules) {
            const regex = rule.regex || rule;
            // A global/sticky expression retains lastIndex between tests.
            regex.lastIndex = 0;
            if (regex.test(text)) return createMatchReason(source, { regex: rule.raw || regex.toString() });
        }
        return null;
    }

    // ─────────────────────────────────────────────
    //  Risk scoring — FIX: was defined but never called; now used by shouldFilter
    // ─────────────────────────────────────────────

    const SPAM_THRESHOLD = 60;

    function spamScore(data, defaultKeywordMatch, defaultRegexMatch) {
        let score = 0;
        const text = data.text.toLowerCase();
        if (defaultKeywordMatch)           score += 40;
        if (defaultRegexMatch)             score += 40;
        if (text.length < 8)              score += 10;
        if (/(.)\1{5,}/.test(text))       score += 20;
        if (/[🔥💎⭐🚀]{5,}/.test(text)) score += 20;
        return score;
    }

    // ─────────────────────────────────────────────
    //  Tweet cache
    // ─────────────────────────────────────────────

    let ProcessedTweets = new WeakSet();
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
    //  User-rule compilation
    // ─────────────────────────────────────────────

    const MAX_USER_REGEX_LENGTH = 120;
    let BlockedUserRules = [];
    let TrustedUserRules = [];

    function normalizeUser(value) {
        return String(value || "").trim().toLowerCase().replace(/^@/, "");
    }

    function compileUserRule(rule) {
        const raw = String(rule || "").trim();
        const lastSlash = raw.lastIndexOf("/");
        if (raw[0] === "/" && lastSlash > 0) {
            const pattern = raw.slice(1, lastSlash);
            const flags = raw.slice(lastSlash + 1);
            if (pattern.length > MAX_USER_REGEX_LENGTH || !/^[imsu]*$/.test(flags)) {
                throw new Error("Regex is too long or has unsupported flags");
            }
            // Reject common nested-quantifier forms that can cause excessive backtracking.
            if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern)) {
                throw new Error("Regex contains a nested quantifier");
            }
            return { regex: new RegExp(pattern, flags), raw };
        }
        const user = normalizeUser(raw);
        if (!user) throw new Error("Empty username rule");
        return { user, raw };
    }

    function compileUserRules(rules) {
        const compiled = [];
        const errors = [];
        rules.forEach(rule => {
            try { compiled.push(compileUserRule(rule)); }
            catch (error) { errors.push(String(rule)); debugWarn("Ignored invalid user rule: " + rule, error); }
        });
        return { compiled, errors };
    }

    function compileContentRegexRules(rules) {
        const compiled = [];
        const errors = [];
        rules.forEach(rule => {
            const raw = String(rule || "").trim();
            const lastSlash = raw.lastIndexOf("/");
            try {
                if (raw[0] !== "/" || lastSlash <= 0) throw new Error("Regex must use /pattern/flags syntax");
                const pattern = raw.slice(1, lastSlash);
                const flags = raw.slice(lastSlash + 1);
                if (pattern.length > MAX_USER_REGEX_LENGTH || !/^[imsu]*$/.test(flags)) {
                    throw new Error("Regex is too long or has unsupported flags");
                }
                if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern)) throw new Error("Regex contains a nested quantifier");
                compiled.push({ regex: new RegExp(pattern, flags), raw });
            } catch (error) {
                errors.push(raw);
                debugWarn("Ignored invalid content regex: " + raw, error);
            }
        });
        return { compiled, errors };
    }

    function reloadUserRules() {
        const blocked = compileUserRules([...DEFAULT_RULES.users, ...CONFIG.users]);
        const trusted = compileUserRules(CONFIG.trustedUsers || []);
        const contentRegex = compileContentRegexRules(CONFIG.regex || []);
        BlockedUserRules = blocked.compiled;
        TrustedUserRules = trusted.compiled;
        UserRegexRules = contentRegex.compiled;
        return blocked.errors.concat(trusted.errors, contentRegex.errors);
    }

    function userMatchesRule(user, rule) {
        const rawCandidate = String(user || "").trim().replace(/^@/, "");
        if (!rawCandidate) return false;
        // Preserve user-provided regular-expression case semantics. Plain handles
        // remain case-insensitive because X handles are case-insensitive.
        return rule.regex ? rule.regex.test(rawCandidate) : normalizeUser(rawCandidate) === rule.user;
    }

    function matchesUserRules(userId, userName, rules) {
        return rules.some(rule => userMatchesRule(userId, rule) || userMatchesRule(userName, rule));
    }

    function checkUser(userId, userName) {
        return matchesUserRules(userId, userName, BlockedUserRules);
    }

    function isTrustedUser(userId, userName) {
        return matchesUserRules(userId, userName, TrustedUserRules);
    }

    reloadUserRules();
    // Installed at document-start so X's earliest page-context fetches are covered.
    unlockSensitive();

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

        const statusLink = tweet.querySelector('a[href*="/status/"]');
        const statusMatch = statusLink && statusLink.pathname.match(/^\/([^/]+)\/status\/([^/?]+)/);
        const userId = statusMatch ? statusMatch[1] : "";
        const id = statusMatch ? statusMatch[2] : "";
        // The status URL supplies the stable account handle; only fall back to
        // visible text when X changes its link markup.
        const profileLink = tweet.querySelector('a[href^="/"][role="link"]');
        const profileHref = profileLink ? profileLink.getAttribute("href") || "" : "";
        const fallbackHandle = profileHref.split("/")[1] || "";

        return { id, text, userName, userId: userId || fallbackHandle };
    }

    function hashText(text) {
        let hash = 5381;
        for (let i = 0; i < text.length; i += 1) hash = ((hash << 5) + hash) ^ text.charCodeAt(i);
        return (hash >>> 0).toString(36);
    }

    // ─────────────────────────────────────────────
    //  Filter decision
    //  FIX: now routes through spamScore() instead of calling Keyword /
    //       matchRegex / detectBot individually (spamScore was dead code before)
    // ─────────────────────────────────────────────

    function shouldFilter(data) {
        if (!data.text && !data.userName) return { shouldHide: false, reason: null };

        // Text alone is not safe: author and trust rules affect the decision.
        // Tweets without an ID receive an author-qualified, bounded cache key.
        const key = data.id
            ? "id:" + data.id
            : "fallback:" + normalizeUser(data.userId || data.userName) + ":" + hashText(data.text);
        if (TweetCache.has(key)) {
            const cached = TweetCache.get(key);
            cacheTweet(key, cached);
            return cached;
        }

        const trusted = isTrustedUser(data.userId, data.userName);
        let result = { shouldHide: false, reason: null };
        if (!trusted) {
            const userKeywordMatch = Keyword.matchUser(data.text);
            const userRegexMatch = matchRegex(data.text, UserRegexRules, "user-regex");
            // User content rules are explicit blocks, not risk signals, so they
            // must never depend on the aggregate spam-score threshold.
            if (userKeywordMatch) {
                result = { shouldHide: true, reason: userKeywordMatch };
            } else if (userRegexMatch) {
                result = { shouldHide: true, reason: userRegexMatch };
            } else if (checkUser(data.userId, data.userName)) {
                result = { shouldHide: true, reason: createMatchReason("blocked-user") };
            } else {
                const defaultKeywordMatch = Keyword.matchDefault(data.text);
                const defaultRegexMatch = matchRegex(data.text, DefaultRegexRules, "default-regex");
                const score = spamScore(data, defaultKeywordMatch, defaultRegexMatch);
                if (score >= SPAM_THRESHOLD) {
                    result = {
                        shouldHide: true,
                        reason: createMatchReason("risk-score", { score, defaultKeywordMatch, defaultRegexMatch })
                    };
                } else if (detectBot(data.text, data.userName)) {
                    result = { shouldHide: true, reason: createMatchReason("bot-detection") };
                }
            }
        }

        cacheTweet(key, result);
        return result;
    }

    // ─────────────────────────────────────────────
    //  Hide tweet
    // ─────────────────────────────────────────────

    function hideTweet(tweet) {
        const container = tweet.closest('[data-testid="cellInnerDiv"]') || tweet;
        if (!container.dataset.xFiltered) container.dataset.xFilterDisplay = container.style.display;
        container.dataset.xFiltered = "true";
        container.style.display = "none";
    }

    function restoreTweet(tweet) {
        const container = tweet.closest('[data-testid="cellInnerDiv"]') || tweet;
        if (!container.dataset.xFiltered) return;
        container.style.display = container.dataset.xFilterDisplay || "";
        delete container.dataset.xFiltered;
        delete container.dataset.xFilterDisplay;
    }

    // ─────────────────────────────────────────────
    //  Process single tweet
    // ─────────────────────────────────────────────

    function processTweet(tweet, force) {
        if (!tweet || (!force && ProcessedTweets.has(tweet))) return;
        ProcessedTweets.add(tweet);
        const data = parseTweet(tweet);
        if (shouldFilter(data).shouldHide) hideTweet(tweet);
        else restoreTweet(tweet);
    }

    function reevaluateTweets() {
        ProcessedTweets = new WeakSet();
        TweetCache.clear();
        document.querySelectorAll('article[data-testid="tweet"]').forEach(tweet => processTweet(tweet, true));
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
    //          targeted data-testid selectors and scoped social-context labels.
    //  FIX 2: was driven by setInterval(3000); moved into the MutationObserver
    //          so ads are hidden as soon as they appear, with zero polling cost.
    // ─────────────────────────────────────────────

    // These selectors identify X's stable ad container structure. Keep text
    // matching out of this list: UI copy is localized and changes independently.
    const AD_SELECTORS = Object.freeze([
        '[data-testid="placementTracking"]'
    ]);

    const SOCIAL_CONTEXT_SELECTOR = '[data-testid="socialContext"]';
    const PROMOTED_SOCIAL_CONTEXT_LABELS = new Set([
        "promoted", "sponsored", "广告", "推廣", "推广", "広告",
        "patrocinado", "publicité", "gesponsert"
    ]);

    function normalizeSocialContextLabel(value) {
        return cleanText(value || "").replace(/\s+/g, " ").toLowerCase();
    }

    function getSocialContextLabels(context) {
        return [context.getAttribute("aria-label"), context.textContent]
            .map(normalizeSocialContextLabel)
            .filter(Boolean);
    }

    function isPromotedSocialContext(context) {
        return getSocialContextLabels(context)
            .some(label => PROMOTED_SOCIAL_CONTEXT_LABELS.has(label));
    }

    function hideAdNode(el) {
        const container = el.closest('[data-testid="cellInnerDiv"]') || el;
        if (!container.dataset.xAdFiltered) {
            container.dataset.xAdFiltered = "true";
            container.style.display = "none";
        }
    }

    function inspectSocialContext(context) {
        if (isPromotedSocialContext(context)) {
            hideAdNode(context);
        } else if (CONFIG.debug && !context.dataset.xAdSocialContextDiagnosed) {
            context.dataset.xAdSocialContextDiagnosed = "true";
            debugWarn("Unrecognized social context label", {
                ariaLabel: normalizeSocialContextLabel(context.getAttribute("aria-label")),
                text: normalizeSocialContextLabel(context.textContent)
            });
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

        // Only inspect social-context nodes. Never infer ads from arbitrary
        // tweet text, which would risk hiding ordinary posts that mention ads.
        if (root && root.matches && root.matches(SOCIAL_CONTEXT_SELECTOR)) inspectSocialContext(root);
        search.querySelectorAll(SOCIAL_CONTEXT_SELECTOR).forEach(inspectSocialContext);
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

    function isXApiUrl(url, base) {
        try {
            const hostname = new URL(url, base).hostname;
            return hostname === "api.x.com" || hostname === "api.twitter.com";
        } catch (error) {
            debugWarn("Could not parse request URL", error);
            return false;
        }
    }

    function unlockSensitive() {
        if (!CONFIG.unlockSensitive) return;
        const pageWindow = typeof unsafeWindow === "undefined" ? window : unsafeWindow;
        if (!pageWindow || pageWindow.__X_FILTER_FETCH_PATCHED__) return;
        const originalFetch = pageWindow.fetch;
        if (typeof originalFetch !== "function") return;
        pageWindow.__X_FILTER_FETCH_PATCHED__ = true;
        pageWindow.fetch = function () {
            const args = arguments;
            return originalFetch.apply(this, args).then(async response => {
                const request = args[0];
                const url = typeof request === "string" ? request : (request && request.url) || response.url;
                if (!isXApiUrl(url, pageWindow.location.href)) return response;
                const contentType = response.headers.get("content-type") || "";
                if (!contentType.toLowerCase().includes("application/json") || !response.ok) return response;
                try {
                    const text = await response.clone().text();
                    if (!text.includes('"possibly_sensitive":true')) return response;
                    const patched = text.replace(/"possibly_sensitive":true/g, '"possibly_sensitive":false');
                    return new pageWindow.Response(patched, {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers
                    });
                } catch (error) {
                    debugWarn("Sensitive-content response was not patched", error);
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
                width: 45px; height: 45px; border: 0; border-radius: 50%;
                background: #1d9bf0; color: white;
                display: flex; align-items: center; justify-content: center;
                cursor: pointer; z-index: 999999; font-size: 20px;
                box-shadow: 0 2px 8px rgba(0,0,0,.3);
                user-select: none;
            }
            #button:hover { background: #1a8cd8; }
            #panel {
                display: none; position: fixed;
                right: 20px; top: 130px; width: 350px; max-width: calc(100vw - 32px);
                max-height: calc(100vh - 150px); overflow: auto;
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
            <button id="button" type="button" aria-label="打开 X Filter 设置" aria-expanded="false">⚙</button>
            <section id="panel" role="dialog" aria-label="X Filter 设置">
                <h3 id="title">X Filter 1.2.0</h3>
                <p>屏蔽用户（每行一个；支持精确用户名或 <code>/正则/</code>）</p>
                <textarea id="users"></textarea>
                <p>信任用户（每行一个，不会被此脚本隐藏）</p>
                <textarea id="trusted-users"></textarea>
                <p>自定义关键词（每行一个；命中后立即隐藏）</p>
                <textarea id="words"></textarea>
                <p>自定义内容正则（每行一个；格式 <code>/正则/flags</code>，命中后立即隐藏）</p>
                <textarea id="regex"></textarea>
                <p><label><input id="unlock-sensitive" type="checkbox"> 解锁敏感内容（拦截 X API fetch）</label></p>
                <div>
                    <button id="save">保存规则</button>
                    <button id="export">导出规则</button>
                    <button id="reset">恢复默认</button>
                </div>
            </section>
        `;
        shadow.appendChild(wrap);

        const btn   = shadow.querySelector("#button");
        const panel = shadow.querySelector("#panel");
        const users = shadow.querySelector("#users");
        const trustedUsers = shadow.querySelector("#trusted-users");
        const words = shadow.querySelector("#words");
        const regex = shadow.querySelector("#regex");
        const unlockSensitiveCheckbox = shadow.querySelector("#unlock-sensitive");

        users.value = CONFIG.users.join("\n");
        trustedUsers.value = (CONFIG.trustedUsers || []).join("\n");
        words.value = CONFIG.words.join("\n");
        regex.value = CONFIG.regex.join("\n");
        unlockSensitiveCheckbox.checked = CONFIG.unlockSensitive !== false;

        const savedPosition = Storage.get("XFilterPanelPosition", null);
        if (savedPosition && Number.isFinite(savedPosition.left) && Number.isFinite(savedPosition.top)) {
            panel.style.left = savedPosition.left + "px";
            panel.style.top = savedPosition.top + "px";
            panel.style.right = "auto";
        }

        function setPanelOpen(open) {
            panel.style.display = open ? "block" : "none";
            btn.setAttribute("aria-expanded", String(open));
            if (open) users.focus();
        }
        btn.onclick = () => setPanelOpen(panel.style.display !== "block");
        shadow.addEventListener("keydown", event => {
            if (event.key === "Escape") setPanelOpen(false);
        });

        shadow.querySelector("#save").onclick = () => {
            CONFIG.users = users.value.split("\n").map(x => x.trim()).filter(Boolean);
            CONFIG.trustedUsers = trustedUsers.value.split("\n").map(x => x.trim()).filter(Boolean);
            CONFIG.words = words.value.split("\n").map(x => x.trim()).filter(Boolean);
            CONFIG.regex = regex.value.split("\n").map(x => x.trim()).filter(Boolean);
            CONFIG.unlockSensitive = unlockSensitiveCheckbox.checked;
            const invalidRules = reloadUserRules();
            Storage.set("XFilterConfig", CONFIG);
            Keyword.reload();
            reevaluateTweets();
            const suffix = invalidRules.length ? " 已忽略无效正则：" + invalidRules.join("、") : "";
            alert("规则已保存，当前页面已重新评估。敏感内容拦截开关会在下次页面加载时生效。" + suffix);
        };

        shadow.querySelector("#export").onclick = async () => {
            try {
                await Storage.copy(JSON.stringify(CONFIG, null, 2));
                alert("规则已复制到剪贴板");
            } catch (error) {
                debugWarn("Could not copy rules", error);
                alert("无法复制规则，请检查剪贴板权限。");
            }
        };

        shadow.querySelector("#reset").onclick = () => {
            if (confirm("恢复默认规则？自定义规则将被清除。")) {
                CONFIG = { users: [], words: [], regex: [], trustedUsers: [], unlockSensitive: false, debug: false };
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
        console.log(
            "%c X Filter 1.2.0 Loaded ",
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
