# 恶意网站监控站 — 实现计划

## 背景与需求
构建一个纯静态网站，定期采集并展示网上带有病毒的网站信息。

用户选择：
- 数据来源：Google Safe Browsing API
- 技术栈：纯静态站点

## 关键限制说明

Google Safe Browsing API 的 **Update API** (`threatListUpdates:fetch`) 返回的是 URL 的 **SHA256 hash prefixes**（通常是 4 字节哈希前缀），**而非原始 URL**。这是 Google 出于隐私保护的刻意设计，API 文档明确说明：

> "To save bandwidth, clients download the hash prefixes of URLs rather than the raw URLs."

**这意味着：**
- ❌ 无法直接从 Safe Browsing API 获取 "www.malware-site.com" 这样的可展示 URL 列表
- ✅ 可以获取威胁分类统计（MALWARE、PHISHING 等列表的条目数量、版本号、更新时间）
- ✅ 可以构建 "URL 安全查询" 工具（Lookup API）

## 推荐方案

### 方案 A：混合数据源（推荐，可展示真实 URL）
- **主要数据**：URLhaus API（abuse.ch，免费开放，无需 API Key，提供真实恶意 URL、威胁类型、首次发现时间、状态等）
- **辅助数据**：Safe Browsing API `threatListUpdates:fetch` 获取威胁分类列表的元数据，用于展示 Google 威胁情报覆盖范围
- **展示内容**：
  - 实时恶意网站列表（来自 URLhaus）
  - 威胁分类统计（来自 Safe Browsing）
  - 各类型威胁趋势图表

### 方案 B：纯 Safe Browsing API
- 仅使用 Safe Browsing API 的统计能力
- 展示内容：威胁类型分布、列表版本信息、更新历史
- **无法展示具体恶意 URL**，只能展示统计数字

## 技术架构（纯静态站点）

```
.github/workflows/
  update.yml              # GitHub Actions 定时任务（每 6 小时执行）
scripts/
  fetch-data.js           # 数据拉取脚本（Node.js）
data/
  threats.json            # 采集的恶意网站数据
  stats.json              # Safe Browsing 统计数据
index.html                # 主页面
style.css                 # 样式
app.js                    # 前端渲染逻辑
package.json
```

## 核心实现步骤

1. **创建数据拉取脚本** (`scripts/fetch-data.js`)
   - 调用 URLhaus API (`https://urlhaus-api.abuse.ch/v1/urls/recent/`) 获取最近恶意 URL
   - 调用 Safe Browsing API `threatListUpdates:fetch` 获取威胁列表统计
   - 处理、去重、格式化数据，输出到 `data/` 目录

2. **创建静态前端**
   - `index.html`：单页应用，展示恶意网站表格和统计卡片
   - `style.css`：暗色主题，红色高亮威胁项
   - `app.js`：读取 `data/threats.json` 和 `data/stats.json`，渲染表格、搜索、分页

3. **配置 GitHub Actions** (`.github/workflows/update.yml`)
   - `schedule: '0 */6 * * *'` 每 6 小时触发
   - 执行 `node scripts/fetch-data.js`
   - 提交数据变更并推送到 `gh-pages` 分支

4. **配置 GitHub Pages**
   - 从 `gh-pages` 分支部署静态站点

## 依赖与前提
- Node.js 18+
- Google Safe Browsing API Key（用户需提供）
- GitHub 仓库（用于 Actions 和 Pages）

## 验证方式
1. 本地运行 `node scripts/fetch-data.js`，检查 `data/` 目录是否生成正确 JSON
2. 本地打开 `index.html`，确认表格和统计正常渲染
3. 推送至 GitHub 后，确认 Actions 定时执行且 Pages 站点正常更新
