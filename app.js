/**
 * 恶意网站监控站 — 前端渲染逻辑
 * 数据通过 data/threats.js 和 data/stats.js 内联注入（window.__DATA__），
 * 无需 HTTP 服务，支持 file:// 协议直接打开。
 */

const PAGE_SIZE = 20;

let allThreats = [];
let filteredThreats = [];
let currentPage = 1;

// 状态映射
const STATUS_MAP = {
  online: { text: '在线', class: 'status-online' },
  offline: { text: '离线', class: 'status-offline' },
  unknown: { text: '未知', class: 'status-unknown' },
};

// 初始化
function init() {
  try {
    const threatsData = window.__DATA__?.threats;
    const statsData = window.__DATA__?.stats;

    if (!threatsData) {
      throw new Error('数据未加载，请确保 data/threats.js 存在');
    }

    allThreats = threatsData.urls || [];

    // 更新统计卡片
    updateStats(threatsData);

    // 填充筛选器
    populateFilters(allThreats);

    // 渲染威胁类型图表
    renderTypeChart(threatsData.stats?.byType || {});

    // Safe Browsing 统计
    if (statsData?.lists?.length > 0) {
      renderGsbStats(statsData.lists);
    }

    // 初始筛选
    applyFilters();

    // 绑定事件
    bindEvents();
  } catch (err) {
    console.error('初始化失败:', err);
    document.getElementById('tableBody').innerHTML = `
      <tr class="empty-row">
        <td colspan="6">数据加载失败，请检查 data/threats.js 是否存在</td>
      </tr>`;
  }
}

// 更新统计卡片
function updateStats(data) {
  const urls = data.urls || [];
  const onlineCount = urls.filter((u) => u.url_status === 'online').length;
  const malwareCount = (data.stats?.byType?.['恶意软件下载']) || 0;

  document.getElementById('statTotal').textContent = data.total ?? urls.length;
  document.getElementById('statOnline').textContent = onlineCount;
  document.getElementById('statMalware').textContent = malwareCount;

  const updated = new Date(data.updated_at);
  document.getElementById('statUpdated').textContent =
    isNaN(updated) ? '-' : formatTime(updated);
}

// 渲染 Safe Browsing 统计
function renderGsbStats(lists) {
  const section = document.getElementById('gsbSection');
  const grid = document.getElementById('gsbGrid');

  grid.innerHTML = lists
    .map(
      (item) => `
      <div class="gsb-card">
        <div class="type">${escapeHtml(item.threatTypeCn)}</div>
        <div class="meta">
          平台: ${escapeHtml(item.platformType)}<br>
          类型: ${escapeHtml(item.responseType)}<br>
          ${item.version ? `版本: ${escapeHtml(String(item.version).slice(0, 12))}...` : ''}
        </div>
      </div>`
    )
    .join('');

  section.style.display = 'block';
}

// 渲染威胁类型分布图表
function renderTypeChart(byType) {
  const container = document.getElementById('typeChart');
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);

  if (entries.length === 0) {
    container.innerHTML = '<p style="color:var(--text-secondary)">暂无数据</p>';
    return;
  }

  const max = entries[0][1];
  const colors = [
    'var(--accent-red)',
    'var(--accent-orange)',
    'var(--accent-blue)',
    'var(--accent-green)',
    'var(--accent-purple)',
  ];

  container.innerHTML = entries
    .map(([label, count], i) => {
      const pct = max > 0 ? (count / max) * 100 : 0;
      const color = colors[i % colors.length];
      return `
        <div class="bar-row">
          <div class="bar-label">${escapeHtml(label)}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:${pct}%;background:${color}"></div>
          </div>
          <div class="bar-value">${count}</div>
        </div>`;
    })
    .join('');
}

// 填充筛选器选项
function populateFilters(threats) {
  const typeFilter = document.getElementById('typeFilter');
  const types = [...new Set(threats.map((t) => t.threat_type_cn).filter(Boolean))];

  types.forEach((type) => {
    const opt = document.createElement('option');
    opt.value = type;
    opt.textContent = type;
    typeFilter.appendChild(opt);
  });
}

// 应用筛选
function applyFilters() {
  const search = document.getElementById('searchInput').value.trim().toLowerCase();
  const type = document.getElementById('typeFilter').value;
  const status = document.getElementById('statusFilter').value;

  filteredThreats = allThreats.filter((t) => {
    const matchSearch =
      !search ||
      (t.url && t.url.toLowerCase().includes(search)) ||
      (t.host && t.host.toLowerCase().includes(search)) ||
      (t.tags && t.tags.some((tag) => tag.toLowerCase().includes(search)));

    const matchType = !type || t.threat_type_cn === type;
    const matchStatus = !status || t.url_status === status;

    return matchSearch && matchType && matchStatus;
  });

  currentPage = 1;
  renderTable();
  renderPagination();
}

// 渲染表格
function renderTable() {
  const tbody = document.getElementById('tableBody');
  const start = (currentPage - 1) * PAGE_SIZE;
  const pageData = filteredThreats.slice(start, start + PAGE_SIZE);

  document.getElementById('recordCount').textContent = `共 ${filteredThreats.length} 条`;

  if (pageData.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="6">没有匹配的数据</td>
      </tr>`;
    return;
  }

  tbody.innerHTML = pageData
    .map((t) => {
      const status = STATUS_MAP[t.url_status] || STATUS_MAP.unknown;
      const tags = (t.tags || [])
        .map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`)
        .join('');

      return `
        <tr>
          <td><span class="status-badge ${status.class}">${status.text}</span></td>
          <td class="url-cell">
            <div class="host">${escapeHtml(t.host || '-')}</div>
            <div class="full-url">${escapeHtml(t.url || '-')}</div>
          </td>
          <td><span class="type-badge">${escapeHtml(t.threat_type_cn || '-')}</span></td>
          <td>${tags || '-'}</td>
          <td>${formatTime(new Date(t.date_added))}</td>
          <td>
            <button class="btn-copy" onclick="copyUrl(this, '${escapeAttr(t.url || '')}')">
              复制
            </button>
          </td>
        </tr>`;
    })
    .join('');
}

// 渲染分页
function renderPagination() {
  const totalPages = Math.ceil(filteredThreats.length / PAGE_SIZE);
  const container = document.getElementById('pagination');

  if (totalPages <= 1) {
    container.innerHTML = '';
    return;
  }

  let html = '';

  // 上一页
  html += `<button ${currentPage === 1 ? 'disabled' : ''} onclick="goToPage(${currentPage - 1})">上一页</button>`;

  // 页码（最多显示 7 个）
  const maxVisible = 7;
  let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
  let endPage = Math.min(totalPages, startPage + maxVisible - 1);
  if (endPage - startPage < maxVisible - 1) {
    startPage = Math.max(1, endPage - maxVisible + 1);
  }

  if (startPage > 1) {
    html += `<button onclick="goToPage(1)">1</button>`;
    if (startPage > 2) html += '<button disabled>...</button>';
  }

  for (let i = startPage; i <= endPage; i++) {
    html += `<button class="${i === currentPage ? 'active' : ''}" onclick="goToPage(${i})">${i}</button>`;
  }

  if (endPage < totalPages) {
    if (endPage < totalPages - 1) html += '<button disabled>...</button>';
    html += `<button onclick="goToPage(${totalPages})">${totalPages}</button>`;
  }

  // 下一页
  html += `<button ${currentPage === totalPages ? 'disabled' : ''} onclick="goToPage(${currentPage + 1})">下一页</button>`;

  container.innerHTML = html;
}

// 跳转页面
function goToPage(page) {
  const totalPages = Math.ceil(filteredThreats.length / PAGE_SIZE);
  if (page < 1 || page > totalPages) return;
  currentPage = page;
  renderTable();
  renderPagination();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// 复制 URL
function copyUrl(btn, url) {
  navigator.clipboard.writeText(url).then(() => {
    btn.textContent = '已复制';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = '复制';
      btn.classList.remove('copied');
    }, 1500);
  });
}

// 绑定事件
function bindEvents() {
  document.getElementById('searchInput').addEventListener('input', debounce(applyFilters, 300));
  document.getElementById('typeFilter').addEventListener('change', applyFilters);
  document.getElementById('statusFilter').addEventListener('change', applyFilters);
}

// 工具函数
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  if (!str) return '';
  return str.replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

function formatTime(date) {
  if (isNaN(date)) return '-';
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

// 启动
init();
