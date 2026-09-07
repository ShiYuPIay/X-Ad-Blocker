'use strict';

/** DOM-independent filtering primitives shared by the userscript and tests. */
const MAX_USER_REGEX_LENGTH = 120;
const SPAM_THRESHOLD = 60;
const MATCH_REASON_LABELS = {
    'user-keyword': '用户关键词命中', 'user-regex': '用户正则命中',
    'default-keyword': '默认关键词命中', 'default-regex': '默认正则命中',
    'blocked-user': '屏蔽用户命中', 'risk-score': '风险评分命中',
    'bot-detection': '机器人检测命中'
};

function normalizeUser(value) { return String(value || '').trim().toLowerCase().replace(/^@/, ''); }
function hashText(text) {
    let hash = 5381;
    for (let i = 0; i < String(text || '').length; i += 1) hash = ((hash << 5) + hash) ^ String(text || '').charCodeAt(i);
    return (hash >>> 0).toString(36);
}
function tweetCacheKey(data) {
    return data.id ? `id:${data.id}` : `fallback:${normalizeUser(data.userId || data.userName)}:${hashText(data.text)}`;
}
function compileUserRule(rule) {
    const raw = String(rule || '').trim();
    const lastSlash = raw.lastIndexOf('/');
    if (raw[0] === '/' && lastSlash > 0) {
        const pattern = raw.slice(1, lastSlash), flags = raw.slice(lastSlash + 1);
        if (pattern.length > MAX_USER_REGEX_LENGTH || !/^[imsu]*$/.test(flags)) throw new Error('Regex is too long or has unsupported flags');
        if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern)) throw new Error('Regex contains a nested quantifier');
        return { regex: new RegExp(pattern, flags), raw };
    }
    const user = normalizeUser(raw);
    if (!user) throw new Error('Empty username rule');
    return { user, raw };
}
function userMatchesRule(user, rule) {
    const candidate = String(user || '').trim().replace(/^@/, '');
    return Boolean(candidate) && (rule.regex ? (rule.regex.lastIndex = 0, rule.regex.test(candidate)) : normalizeUser(candidate) === rule.user);
}
function isXApiUrl(url, base) {
    try { const hostname = new URL(url, base).hostname; return hostname === 'api.x.com' || hostname === 'api.twitter.com'; }
    catch { return false; }
}
function createMatchReason(source, details) { return Object.assign({ source, label: MATCH_REASON_LABELS[source] || source }, details); }
function compileRules(rules, onError) {
    const compiled = [], errors = [];
    (rules || []).forEach(rule => { try { compiled.push(compileUserRule(rule)); } catch (error) { errors.push(String(rule)); if (onError) onError(rule, error); } });
    return { compiled, errors };
}
function compileContentRegexRules(rules, onError) {
    const compiled = [], errors = [];
    (rules || []).forEach(value => { const raw = String(value || '').trim(), lastSlash = raw.lastIndexOf('/'); try {
        if (raw[0] !== '/' || lastSlash <= 0) throw new Error('Regex must use /pattern/flags syntax');
        const pattern = raw.slice(1, lastSlash), flags = raw.slice(lastSlash + 1);
        if (pattern.length > MAX_USER_REGEX_LENGTH || !/^[imsu]*$/.test(flags)) throw new Error('Regex is too long or has unsupported flags');
        if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern)) throw new Error('Regex contains a nested quantifier');
        compiled.push({ regex: new RegExp(pattern, flags), raw });
    } catch (error) { errors.push(raw); if (onError) onError(raw, error); } });
    return { compiled, errors };
}
function spamScore(data, defaultKeywordMatch, defaultRegexMatch) {
    const text = String(data.text || '').toLowerCase(); let score = 0;
    if (defaultKeywordMatch) score += 40; if (defaultRegexMatch) score += 40;
    if (text.length < 8) score += 10; if (/(.)\1{5,}/.test(text)) score += 20; if (/[🔥💎⭐🚀]{5,}/.test(text)) score += 20;
    return score;
}
function detectBot(text, userName) { text = String(text || ''); let score = 0; if (!text) return false; if (/(.)\1{6,}/.test(text)) score += 25; if ((text.match(/[\u{1F300}-\u{1FAFF}]/gu) || []).length >= 8) score += 20; if (/👇|⬇|👉|点击|领取|加入/.test(text)) score += 20; if (text.length < 6) score += 10; if (userName && /福利|资源|兼职|客服|官方|bot|机器人/i.test(userName)) score += 30; return score >= 50; }
function createFilterEngine(config, defaultRules, onError) {
    const cache = new Map(); let blocked = [], trusted = [], userRegex = [];
    const matchWords = (text, words, source) => { const lower = String(text || '').toLowerCase(); for (const word of words) if (lower.includes(word)) return createMatchReason(source, { word }); return null; };
    const matchRegex = (text, rules, source) => { for (const rule of rules) { const regex = rule.regex || rule; regex.lastIndex = 0; if (regex.test(text)) return createMatchReason(source, { regex: rule.raw || regex.toString() }); } return null; };
    function reload() { const b = compileRules([...(defaultRules.users || []), ...(config.users || [])], onError), t = compileRules(config.trustedUsers || [], onError), r = compileContentRegexRules(config.regex || [], onError); blocked = b.compiled; trusted = t.compiled; userRegex = r.compiled; cache.clear(); return b.errors.concat(t.errors, r.errors); }
    function matches(userId, userName, rules) { return rules.some(rule => userMatchesRule(userId, rule) || userMatchesRule(userName, rule)); }
    function shouldFilter(data) { if (!data.text && !data.userName) return { shouldHide: false, reason: null }; const key = tweetCacheKey(data); if (cache.has(key)) return cache.get(key); let result = { shouldHide: false, reason: null };
        if (!matches(data.userId, data.userName, trusted)) { const userKeyword = matchWords(data.text, (config.words || []).map(word => String(word).toLowerCase()), 'user-keyword'), userRegexMatch = matchRegex(data.text, userRegex, 'user-regex');
            if (userKeyword) result = { shouldHide: true, reason: userKeyword }; else if (userRegexMatch) result = { shouldHide: true, reason: userRegexMatch }; else if (matches(data.userId, data.userName, blocked)) result = { shouldHide: true, reason: createMatchReason('blocked-user') }; else { const keyword = matchWords(data.text, (defaultRules.words || []).map(word => String(word).toLowerCase()), 'default-keyword'), regex = matchRegex(data.text, defaultRules.regex || [], 'default-regex'), score = spamScore(data, keyword, regex); if (score >= SPAM_THRESHOLD) result = { shouldHide: true, reason: createMatchReason('risk-score', { score, defaultKeywordMatch: keyword, defaultRegexMatch: regex }) }; else if (detectBot(data.text, data.userName)) result = { shouldHide: true, reason: createMatchReason('bot-detection') }; } }
        cache.set(key, result); return result; }
    reload(); return { reload, shouldFilter, clearCache: () => cache.clear() };
}
const exported = { MAX_USER_REGEX_LENGTH, SPAM_THRESHOLD, normalizeUser, hashText, tweetCacheKey, compileUserRule, userMatchesRule, isXApiUrl, spamScore, createFilterEngine };
if (typeof module !== 'undefined' && module.exports) module.exports = exported;
if (typeof globalThis !== 'undefined') globalThis.XFilterCore = exported;
