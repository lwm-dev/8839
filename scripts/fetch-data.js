/**
 * 恶意网站数据采集脚本
 * 数据源：
 *  1. URLhaus API (abuse.ch) — 真实恶意 URL 列表
 *  2. Google Safe Browsing API — 威胁列表统计信息
 */

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/';
const GSB_API = 'https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch';
const GSB_API_KEY = process.env.GSB_API_KEY || '';

// URLhaus 返回的 threat_type 到中文的映射
const THREAT_TYPE_MAP = {
  malware_download: '恶意软件下载',
  phishing: '钓鱼网站',
  botnet_cc: '僵尸网络 C&C',
  spam: '垃圾邮件',
  unknown: '未知威胁',
};

async function fetchUrlhaus() {
  console.log('[URLhaus] 正在拉取最近恶意 URL...');
  const res = await fetch(URLHAUS_API, {
    method: 'GET',
    headers: { 'User-Agent': 'malicious-site-monitor/1.0' },
  });

  if (!res.ok) {
    throw new Error(`URLhaus API 请求失败: ${res.status} ${res.statusText}`);
  }

  const json = await res.json();
  if (json.query_status !== 'ok') {
    throw new Error(`URLhaus API 返回异常: ${json.query_status}`);
  }

  const urls = (json.urls || []).map((item) => ({
    id: item.id,
    url: item.url,
    url_status: item.url_status,           // online / offline / unknown
    host: item.host,
    date_added: item.date_added,
    threat_type: item.threat_type,
    threat_type_cn: THREAT_TYPE_MAP[item.threat_type] || item.threat_type || '未知威胁',
    tags: item.tags || [],
    urlhaus_link: item.urlhaus_reference || '',
    reporter: item.reporter || '',
  }));

  console.log(`[URLhaus] 获取到 ${urls.length} 条恶意 URL`);
  return urls;
}

async function fetchSafeBrowsingStats() {
  if (!GSB_API_KEY) {
    console.warn('[SafeBrowsing] 未提供 GSB_API_KEY，跳过统计拉取');
    return null;
  }

  console.log('[SafeBrowsing] 正在拉取威胁列表统计...');

  const lists = [
    { threatType: 'MALWARE', platformType: 'ANY_PLATFORM', threatEntryType: 'URL' },
    { threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threatEntryType: 'URL' },
    { threatType: 'UNWANTED_SOFTWARE', platformType: 'ANY_PLATFORM', threatEntryType: 'URL' },
    { threatType: 'POTENTIALLY_HARMFUL_APPLICATION', platformType: 'ANDROID', threatEntryType: 'URL' },
  ];

  const body = {
    client: { clientId: 'malicious-site-monitor', clientVersion: '1.0.0' },
    listUpdateRequests: lists.map((l) => ({
      ...l,
      state: '',
      constraints: {
        maxUpdateEntries: 1,
        maxDatabaseEntries: 1,
        region: 'US',
        supportedCompressions: ['RAW'],
      },
    })),
  };

  const res = await fetch(`${GSB_API}?key=${GSB_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Safe Browsing API 请求失败: ${res.status} ${text}`);
  }

  const json = await res.json();

  // 解析统计信息：每个列表的响应包含版本、状态等
  const stats = (json.listUpdateResponses || []).map((r, idx) => {
    const list = lists[idx];
    return {
      threatType: list.threatType,
      threatTypeCn: {
        MALWARE: '恶意软件',
        SOCIAL_ENGINEERING: '社交工程 / 钓鱼',
        UNWANTED_SOFTWARE: '不需要的软件',
        POTENTIALLY_HARMFUL_APPLICATION: '潜在有害应用',
      }[list.threatType] || list.threatType,
      platformType: list.platformType,
      responseType: r.responseType,       // FULL_UPDATE / PARTIAL_UPDATE
      version: r.version || null,
      newClientState: r.newClientState || null,
      checksum: r.checksum?.sha256 || null,
    };
  });

  console.log(`[SafeBrowsing] 获取到 ${stats.length} 个威胁列表统计`);
  return stats;
}

function buildStatsFromUrls(urls) {
  const byType = {};
  const byStatus = { online: 0, offline: 0, unknown: 0 };
  const byTag = {};

  urls.forEach((u) => {
    byType[u.threat_type_cn] = (byType[u.threat_type_cn] || 0) + 1;
    byStatus[u.url_status] = (byStatus[u.url_status] || 0) + 1;
    (u.tags || []).forEach((t) => {
      byTag[t] = (byTag[t] || 0) + 1;
    });
  });

  return { byType, byStatus, byTag };
}

async function main() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    const [urls, gsbStats] = await Promise.all([
      fetchUrlhaus(),
      fetchSafeBrowsingStats(),
    ]);

    const statsFromUrls = buildStatsFromUrls(urls);

    const threatsOutput = {
      updated_at: new Date().toISOString(),
      source: 'URLhaus (abuse.ch)',
      total: urls.length,
      stats: statsFromUrls,
      urls,
    };

    fs.writeFileSync(
      path.join(DATA_DIR, 'threats.json'),
      JSON.stringify(threatsOutput, null, 2),
      'utf-8'
    );
    console.log(`[输出] threats.json 已写入，共 ${urls.length} 条`);

    // 同时生成 JS 内联文件（支持 file:// 协议直接打开）
    const threatsJs = `window.__DATA__ = window.__DATA__ || {};\nwindow.__DATA__.threats = ${JSON.stringify(threatsOutput, null, 2)};\n`;
    fs.writeFileSync(
      path.join(DATA_DIR, 'threats.js'),
      '/**\n * 恶意网站数据（自动生成）\n */\n' + threatsJs,
      'utf-8'
    );
    console.log('[输出] threats.js 已写入');

    if (gsbStats) {
      const statsOutput = {
        updated_at: new Date().toISOString(),
        source: 'Google Safe Browsing API',
        lists: gsbStats,
      };

      fs.writeFileSync(
        path.join(DATA_DIR, 'stats.json'),
        JSON.stringify(statsOutput, null, 2),
        'utf-8'
      );
      console.log(`[输出] stats.json 已写入`);

      // 同时生成 JS 内联文件
      const statsJs = `window.__DATA__ = window.__DATA__ || {};\nwindow.__DATA__.stats = ${JSON.stringify(statsOutput, null, 2)};\n`;
      fs.writeFileSync(
        path.join(DATA_DIR, 'stats.js'),
        '/**\n * Safe Browsing 统计数据（自动生成）\n */\n' + statsJs,
        'utf-8'
      );
      console.log('[输出] stats.js 已写入');
    } else {
      // 没有 API Key 时写一个占位文件，避免前端报错
      const placeholder = {
        updated_at: new Date().toISOString(),
        source: 'Google Safe Browsing API',
        lists: [],
        note: '未配置 GSB_API_KEY，暂无 Safe Browsing 统计数据',
      };
      fs.writeFileSync(
        path.join(DATA_DIR, 'stats.json'),
        JSON.stringify(placeholder, null, 2),
        'utf-8'
      );
      const statsJs = `window.__DATA__ = window.__DATA__ || {};\nwindow.__DATA__.stats = ${JSON.stringify(placeholder, null, 2)};\n`;
      fs.writeFileSync(
        path.join(DATA_DIR, 'stats.js'),
        '/**\n * Safe Browsing 统计数据（自动生成）\n */\n' + statsJs,
        'utf-8'
      );
      console.log('[输出] stats.json / stats.js 占位文件已写入（未配置 API Key）');
    }

    console.log('✅ 数据采集完成');
  } catch (err) {
    console.error('❌ 采集失败:', err.message);
    process.exit(1);
  }
}

main();
