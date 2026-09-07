# X / Twitter Intercept Malicious Advertising

这是一个运行于 `x.com` 和 `twitter.com` 的 Tampermonkey 用户脚本，用于按用户名、关键词和正则规则隐藏帖子，并隐藏已识别的推广内容。脚本还提供一个可选的敏感内容响应处理开关。

## Tampermonkey compatibility

### Compatibility policy

兼容性声明只包含**在真实浏览器中按下方用例逐项手动验证通过**的组合；自动化单元测试或静态代码审查不能替代该验证。截至 2026-09-07，本仓库没有完成的 Tampermonkey 手动验证记录，因此没有任何浏览器/Tampermonkey 组合被声明为兼容。

因此，用户脚本元数据中没有 `@compatible` 条目。请不要将旧版本中宽泛的 Chrome、Firefox 或 Safari 版本范围视为 Tampermonkey 兼容性承诺。

### Manual validation record

| Browser channel | Browser version | Tampermonkey version | Test date | Result | Known limitations |
| --- | --- | --- | --- | --- | --- |
| Chrome Stable | Not tested | Not tested | Not run (record reviewed 2026-09-07) | Not verified | A real Chrome Stable + Tampermonkey session is required before this combination can be declared compatible. |
| Chrome Beta | Not tested | Not tested | Not run (record reviewed 2026-09-07) | Not verified | A real Chrome Beta + Tampermonkey session is required before this combination can be declared compatible. |
| Firefox | Not tested | Not tested | Not run (record reviewed 2026-09-07) | Not verified | A real Firefox + Tampermonkey session is required before this combination can be declared compatible. |

The test environment used for this documentation change does not include Chrome, Chromium, Firefox, or Tampermonkey. Version numbers and passing results must not be inferred from the script's JavaScript support or its unit tests.

### Tampermonkey 安装验收

每次发布前，使用目标浏览器中的 Tampermonkey 完成以下安装和回归验收，并将结果记录到下方的发布前检查表。

1. 在 Tampermonkey Dashboard 中打开“实用工具”（Utilities），粘贴脚本 Raw 地址并安装；也可以直接在浏览器中打开 [Raw `.user.js` 地址](https://raw.githubusercontent.com/ShiYuPIay/X-Twitter-intercept-Malicious-advertising/main/X-Twitter-intercept-Malicious-advertising.user.js)，在 Tampermonkey 安装预览页完成安装。
2. 在安装预览页确认恰好展示以下四项 grant：`GM_getValue`、`GM_setValue`、`GM_setClipboard`、`unsafeWindow`。若 grant 缺失、额外出现，或预览页未将其识别为用户脚本，则停止发布并排查元数据。
3. 分别直接访问脚本的 `@updateURL` 与 `@downloadURL`，确认两者均返回 Userscript 文件内容，而不是 HTML 页面、登录页或错误重定向。
4. 打开 `https://x.com/` 验证：设置面板只出现一次；新增或修改规则后可以保存；让剪贴板导出失败时会显示错误；刷新页面后，配置和设置面板位置均能恢复。
5. 记录本次 Tampermonkey 版本、测试日期和每项结果，作为发布前检查项；任一失败或未执行项都不得标记为通过。

| 发布前检查项 | Tampermonkey 版本 | 测试日期 | 结果 | 证据 / 备注 |
| --- | --- | --- | --- | --- |
| 安装预览、grant 与 URL 响应 |  |  | Pending |  |
| X 页面设置、规则保存、导出失败与状态恢复 |  |  | Pending |  |

### Required manual scenarios

Run every scenario below in **each** row above. Record the exact browser and Tampermonkey versions, the calendar date, evidence (for example, screenshot or issue link), and any observed limitation in the validation record. Mark a combination as **Verified** only when every applicable scenario passes; then add that exact combination to this table and, if desired, to the userscript `@compatible` metadata.

| Scenario | Manual procedure | Pass criteria / expected behavior |
| --- | --- | --- |
| First installation | Install the script from the repository's raw `X-Twitter-intercept-Malicious-advertising.user.js` URL in Tampermonkey, accept the manager prompt, then open `https://x.com/`. | Tampermonkey reports the script as enabled; X loads normally; one settings button is present; the browser console shows the `X Filter ... Loaded` message without an uncaught script error. |
| Automatic update | Install an older test build with the same script identity and a lower `@version`, then publish/install a higher-version build at the configured `@updateURL`; use Tampermonkey's update check and reload X. | Tampermonkey detects and installs the newer version, preserves saved rules, and the updated script runs after reload. Do not mark this as passed merely because the URL is reachable. |
| First page load | With the script enabled and default settings restored, open an X timeline containing a known matching rule and a promoted placement. | Matching posts and recognized promoted placements are hidden on the initial scan; ordinary posts remain visible; no repeated settings buttons appear. |
| SPA navigation | Navigate between Home, Search, a profile, and a post detail view using X's in-app links, without a full browser reload. | The existing panel remains usable and newly rendered matching posts/ads are filtered. Record routes where X replaces the observed root and filtering stops. |
| Infinite scroll | On a timeline, scroll until several additional batches of posts load. | Newly appended matching posts and recognized promoted placements are filtered after the script's short queued processing delay; scrolling remains usable. |
| iframe page | Load an X URL in a same-origin iframe test page and inspect the frame's console and DOM. | **Expected exclusion:** the script does not execute in the iframe because it declares `@noframes` and also returns when `window.top !== window.self`. This is a passing result, not a supported iframe filtering feature. |
| Clipboard permission denied | Deny clipboard permission (or otherwise cause the Clipboard API to reject), open the settings panel, and choose **Export rules**. | The page does not crash; it displays the copy-failure alert. If Tampermonkey's `GM_setClipboard` succeeds despite page permission denial, record that manager-specific behavior separately. |
| Sensitive-content switch off | Ensure **解锁敏感内容** is unchecked, save, reload the page, and observe relevant X API responses/functionality. | The script does not install its fetch patch; normal filtering still works. |
| Sensitive-content switch on | Check **解锁敏感内容**, save, reload the page, and observe eligible X API JSON responses. | On the next load, only successful JSON requests to `api.x.com` or `api.twitter.com` are eligible for the `possibly_sensitive` response change; unrelated requests remain untouched. |

### Known behavior and limitations to verify

* **No iframe support by design.** The metadata declares `@noframes`, and the runtime independently exits in a frame. Do not report iframe filtering as supported. [Userscript metadata](./X-Twitter-intercept-Malicious-advertising.user.js#L14-L15) and [frame guard](./X-Twitter-intercept-Malicious-advertising.user.js#L29-L30).
* **Sensitive-content changes require a reload.** Saving the checkbox only persists the setting; the fetch patch is installed at document start, so the UI tells the user that it takes effect on the next page load. [Patch installation](./X-Twitter-intercept-Malicious-advertising.user.js#L136-L137) and [save notice](./X-Twitter-intercept-Malicious-advertising.user.js#L496-L496).
* **The sensitive-content patch is deliberately narrow.** It considers only successful JSON responses for `api.x.com` and `api.twitter.com`; verify any X endpoint changes against that boundary. [Fetch patch](./X-Twitter-intercept-Malicious-advertising.user.js#L342-L374).
* **Clipboard export can fail gracefully.** The script prefers Tampermonkey's `GM_setClipboard`, otherwise uses the page Clipboard API, and shows an error alert when copying fails. [Clipboard implementation](./X-Twitter-intercept-Malicious-advertising.user.js#L63-L74) and [export handling](./X-Twitter-intercept-Malicious-advertising.user.js#L501-L510).
* **Ad detection depends on X DOM markers and localized labels.** It currently targets `placementTracking` plus a finite set of promoted labels. X UI/API changes or an unlisted locale can cause ads not to be recognized; record the locale and DOM evidence when that occurs. [Ad selectors and labels](./X-Twitter-intercept-Malicious-advertising.user.js#L232-L253).

### Updating this record

1. Run the full scenario table manually on one exact browser channel/version and one exact Tampermonkey version.
2. Replace its `Not tested` fields with the recorded versions and date, attach evidence, and describe any limitations observed.
3. Change the result to **Verified** only if all applicable rows pass. Keep failed or incomplete combinations out of `@compatible` and compatibility claims.
4. Re-run the automated tests after any script change, then update this document in the same commit.
