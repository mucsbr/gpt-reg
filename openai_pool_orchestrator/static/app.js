/**
 * OpenAI Pool Orchestrator — v5.2.1
 */

// ==========================================
// 状态
// ==========================================
const state = {
  task: {
    status: 'idle',
    run_id: null,
    revision: -1,
    server_time: null,
  },
  runtime: {
    run_id: null,
    revision: -1,
    focus_worker_id: null,
    workers: [],
    completion_semantics: 'registration_only',
  },
  stats: {
    success: 0,
    fail: 0,
    total: 0,
  },
  ui: {
    autoScroll: true,
    logCount: 0,
    focusWorkerId: null,
    focusLocked: false,
    eventSource: null,
    tokens: [],
    tokenFilter: {
      status: 'all',
      keyword: '',
    },
    sub2apiAccounts: [],
    sub2apiAccountFilter: {
      status: 'all',
      keyword: '',
    },
    sub2apiAccountPager: {
      page: 1,
      pageSize: 20,
      total: 0,
      filteredTotal: 0,
      totalPages: 1,
    },
    selectedSub2ApiAccountIds: new Set(),
    sub2apiAccountsLoading: false,
    sub2apiAccountActionBusy: false,
    countdownTimer: null,
    _loadTokensTimer: null,
    latestRevisionByRun: {},
    snapshotRequested: false,
    dataPanelTab: 'dataPanelSub2Api',
  },
};

// ==========================================
// DOM 引用
// ==========================================
const $ = id => document.getElementById(id);
const DOM = {};

const STEP_DISPLAY_LABELS = {
  check_proxy: '网络检查',
  create_email: '创建邮箱',
  oauth_init: 'OAuth 初始化',
  sentinel: 'Sentinel Token',
  signup: '提交注册',
  send_otp: '发送验证码',
  wait_otp: '等待验证码',
  verify_otp: '验证 OTP',
  create_account: '创建账户',
  workspace: '选择 Workspace',
  get_token: '获取 Token',
  start: '开始新一轮',
  saved: '保存 Token',
  retry: '等待重试',
  runtime: '运行异常',
  wait: '等待下一轮',
  stopped: '已停止',
  dedupe: '重复检测',
  sync: '同步 Sub2Api',
  cpa_upload: '上传 CPA',
  mode: '上传策略',
  auto_stop: '自动停止',
  stopping: '停止中',
};

const STATUS_LABEL_MAP = {
  idle: '空闲',
  starting: '启动中',
  preparing: '准备中',
  running: '运行中',
  registering: '注册中',
  postprocessing: '后处理中',
  waiting: '等待中',
  stopping: '停止中',
  stopped: '已停止',
  finished: '已完成',
  failed: '失败',
  error: '异常',
};

const PHASE_LABEL_MAP = {
  preparing: '准备阶段',
  registration: '注册阶段',
  postprocess: '后处理阶段',
  finished: '结束阶段',
  idle: '等待任务',
};

const COMPLETION_SEMANTICS_MAP = {
  registration_only: '注册完成即结束',
  requires_postprocess: '注册完成后仍需后处理',
};

const WORKER_STATUS_PRIORITY = {
  registering: 6,
  postprocessing: 5,
  preparing: 4,
  running: 4,
  waiting: 3,
  error: 3,
  stopping: 2,
  stopped: 1,
  idle: 0,
};

const SUB2API_ABNORMAL_STATUSES = new Set(['error', 'disabled']);

function clearSub2ApiAccountKeywordInput() {
  if (!DOM.sub2apiAccountKeyword) return;
  if (state.ui.sub2apiAccountFilter.keyword) return;
  DOM.sub2apiAccountKeyword.value = '';
  requestAnimationFrame(() => {
    if (!state.ui.sub2apiAccountFilter.keyword && DOM.sub2apiAccountKeyword) DOM.sub2apiAccountKeyword.value = '';
  });
  setTimeout(() => {
    if (!state.ui.sub2apiAccountFilter.keyword && DOM.sub2apiAccountKeyword) DOM.sub2apiAccountKeyword.value = '';
  }, 120);
}

// ==========================================
// 初始化
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  Object.assign(DOM, {
    statusBadge: $('statusBadge'),
    statusText: $('statusText'),
    statusDot: $('statusDot'),
    proxyInput: $('proxyInput'),
    checkProxyBtn: $('checkProxyBtn'),
    proxyStatus: $('proxyStatus'),
    btnStart: $('btnStart'),
    btnStop: $('btnStop'),
    statSuccess: $('statSuccess'),
    statFail: $('statFail'),
    statTotal: $('statTotal'),
    logBody: $('logBody'),
    logCount: $('logCount'),
    clearLogBtn: $('clearLogBtn'),
    progressFill: $('progressFill'),
    taskOverview: $('taskOverview'),
    workerList: $('workerList'),
    workerDetail: $('workerDetail'),
    unlockFocusBtn: $('unlockFocusBtn'),
    segmentIndicator: $('segmentIndicator'),
    autoScrollCheck: $('autoScrollCheck'),
    multithreadCheck: $('multithreadCheck'),
    threadCountInput: $('threadCountInput'),
    sub2apiBaseUrl: $('sub2apiBaseUrl'),
    sub2apiEmail: $('sub2apiEmail'),
    sub2apiPassword: $('sub2apiPassword'),
    autoSyncCheck: $('autoSyncCheck'),
    uploadMode: $('uploadMode'),
    uploadModeSaveBtn: $('uploadModeSaveBtn'),
    uploadModeStatus: $('uploadModeStatus'),
    saveSyncConfigBtn: $('saveSyncConfigBtn'),
    syncStatus: $('syncStatus'),
    headerSub2apiChip: $('headerSub2apiChip'),
    headerSub2apiLabel: $('headerSub2apiLabel'),
    headerSub2apiDelta: $('headerSub2apiDelta'),
    headerSub2apiBar: $('headerSub2apiBar'),
    headerCpaChip: $('headerCpaChip'),
    headerCpaLabel: $('headerCpaLabel'),
    headerCpaDelta: $('headerCpaDelta'),
    headerCpaBar: $('headerCpaBar'),
    headerLocalTokenChip: $('headerLocalTokenChip'),
    headerLocalTokenLabel: $('headerLocalTokenLabel'),
    headerLocalTokenDelta: $('headerLocalTokenDelta'),
    headerLocalTokenBar: $('headerLocalTokenBar'),
    themeToggleBtn: $('themeToggleBtn'),
    cpaBaseUrl: $('cpaBaseUrl'),
    cpaToken: $('cpaToken'),
    cpaMinCandidates: $('cpaMinCandidates'),
    cpaUsedPercent: $('cpaUsedPercent'),
    cpaAutoMaintain: $('cpaAutoMaintain'),
    cpaInterval: $('cpaInterval'),
    cpaTestBtn: $('cpaTestBtn'),
    cpaSaveBtn: $('cpaSaveBtn'),
    cpaStatus: $('cpaStatus'),
    localMaintainEnabled: $('localMaintainEnabled'),
    localMaintainInterval: $('localMaintainInterval'),
    localRefreshThreshold: $('localRefreshThreshold'),
    localCheckIntervalHours: $('localCheckIntervalHours'),
    localMaintainThreadCount: $('localMaintainThreadCount'),
    localMaintainBtn: $('localMaintainBtn'),
    localMaintainSaveBtn: $('localMaintainSaveBtn'),
    localMaintainStatus: $('localMaintainStatus'),
    localPoolStats: $('localPoolStats'),
    mailStrategySelect: $('mailStrategySelect'),
    mailTestBtn: $('mailTestBtn'),
    mailSaveBtn: $('mailSaveBtn'),
    mailStatus: $('mailStatus'),
    registerVersionSelect: $('registerVersionSelect'),
    registerVersionSaveBtn: $('registerVersionSaveBtn'),
    registerVersionStatus: $('registerVersionStatus'),
    poolTotal: $('poolTotal'),
    poolCandidates: $('poolCandidates'),
    poolError: $('poolError'),
    poolThreshold: $('poolThreshold'),
    poolPercent: $('poolPercent'),
    poolRefreshBtn: $('poolRefreshBtn'),
    poolMaintainBtn: $('poolMaintainBtn'),
    poolMaintainStatus: $('poolMaintainStatus'),
    dataPanelSub2Api: $('dataPanelSub2Api'),
    dataPanelCpa: $('dataPanelCpa'),
    dataPanelLocalTokens: $('dataPanelLocalTokens'),
    poolTokenList: $('poolTokenList'),
    poolCopyRtBtn: $('poolCopyRtBtn'),
    poolExportBtn: $('poolExportBtn'),
    poolPwSyncBtn: $('poolPwSyncBtn'),
    tokenFilterStatus: $('tokenFilterStatus'),
    tokenFilterKeyword: $('tokenFilterKeyword'),
    tokenFilterApplyBtn: $('tokenFilterApplyBtn'),
    tokenFilterResetBtn: $('tokenFilterResetBtn'),
    sub2apiPoolTotal: $('sub2apiPoolTotal'),
    sub2apiPoolNormal: $('sub2apiPoolNormal'),
    sub2apiPoolError: $('sub2apiPoolError'),
    sub2apiPoolThreshold: $('sub2apiPoolThreshold'),
    sub2apiPoolPercent: $('sub2apiPoolPercent'),
    sub2apiPoolRefreshBtn: $('sub2apiPoolRefreshBtn'),
    sub2apiPoolMaintainBtn: $('sub2apiPoolMaintainBtn'),
    sub2apiPoolMaintainStatus: $('sub2apiPoolMaintainStatus'),
    sub2apiAccountStatusFilter: $('sub2apiAccountStatusFilter'),
    sub2apiAccountKeyword: $('sub2apiAccountKeyword'),
    sub2apiAccountApplyBtn: $('sub2apiAccountApplyBtn'),
    sub2apiAccountResetBtn: $('sub2apiAccountResetBtn'),
    sub2apiAccountSelectAll: $('sub2apiAccountSelectAll'),
    sub2apiAccountSelection: $('sub2apiAccountSelection'),
    sub2apiAccountProbeBtn: $('sub2apiAccountProbeBtn'),
    sub2apiAccountExceptionBtn: $('sub2apiAccountExceptionBtn'),
    sub2apiDuplicateScanBtn: $('sub2apiDuplicateScanBtn'),
    sub2apiDuplicateCleanBtn: $('sub2apiDuplicateCleanBtn'),
    sub2apiAccountDeleteBtn: $('sub2apiAccountDeleteBtn'),
    sub2apiAccountList: $('sub2apiAccountList'),
    sub2apiAccountActionStatus: $('sub2apiAccountActionStatus'),
    sub2apiAccountPrevBtn: $('sub2apiAccountPrevBtn'),
    sub2apiAccountNextBtn: $('sub2apiAccountNextBtn'),
    sub2apiAccountPageInfo: $('sub2apiAccountPageInfo'),
    sub2apiAccountPageSize: $('sub2apiAccountPageSize'),
    sub2apiMinCandidates: $('sub2apiMinCandidates'),
    sub2apiInterval: $('sub2apiInterval'),
    sub2apiAutoMaintain: $('sub2apiAutoMaintain'),
    sub2apiTestPoolBtn: $('sub2apiTestPoolBtn'),
    sub2apiMaintainRefreshAbnormal: $('sub2apiMaintainRefreshAbnormal'),
    sub2apiMaintainDeleteAbnormal: $('sub2apiMaintainDeleteAbnormal'),
    sub2apiMaintainDedupe: $('sub2apiMaintainDedupe'),
    proxyPoolEnabled: $('proxyPoolEnabled'),
    proxyPoolApiUrl: $('proxyPoolApiUrl'),
    proxyPoolAuthMode: $('proxyPoolAuthMode'),
    proxyPoolApiKey: $('proxyPoolApiKey'),
    proxyPoolCount: $('proxyPoolCount'),
    proxyPoolCountry: $('proxyPoolCountry'),
    proxyPoolTestBtn: $('proxyPoolTestBtn'),
    proxyPoolSaveBtn: $('proxyPoolSaveBtn'),
    proxyPoolStatus: $('proxyPoolStatus'),
    saveProxyBtn: $('saveProxyBtn'),
    autoRegisterCheck: $('autoRegisterCheck'),
  });

  clearSub2ApiAccountKeywordInput();

  renderRuntimePanels();
  connectSSE();
  loadTokens();
  requestStatusSnapshot();
  loadTaskControl();
  loadSyncConfig();
  loadProxyPoolConfig();
  loadPoolConfig();
  loadLocalPoolConfig();
  loadLocalPoolStatus();
  loadMailConfig();
  initMailCheckboxes();
  pollPoolStatus();
  pollSub2ApiPoolStatus();
  loadSub2ApiAccounts();
  initThemeSwitch();
  initCollapsibles();
  initDataPanelTabs();

  DOM.checkProxyBtn.addEventListener('click', checkProxy);
  if (DOM.saveProxyBtn) DOM.saveProxyBtn.addEventListener('click', saveProxy);
  DOM.btnStart.addEventListener('click', startTask);
  DOM.btnStop.addEventListener('click', stopTask);
  DOM.clearLogBtn.addEventListener('click', clearLog);
  if (DOM.unlockFocusBtn) DOM.unlockFocusBtn.addEventListener('click', unlockFocusWorker);

  // 任务控制区开关/输入变更时自动保存
  if (DOM.multithreadCheck) DOM.multithreadCheck.addEventListener('change', saveTaskControl);
  if (DOM.threadCountInput) DOM.threadCountInput.addEventListener('change', saveTaskControl);
  if (DOM.autoRegisterCheck) DOM.autoRegisterCheck.addEventListener('change', saveTaskControl);

  DOM.saveSyncConfigBtn.addEventListener('click', saveSyncConfig);
  if (DOM.uploadModeSaveBtn) DOM.uploadModeSaveBtn.addEventListener('click', saveUploadMode);
  DOM.cpaTestBtn.addEventListener('click', testCpaConnection);
  DOM.cpaSaveBtn.addEventListener('click', savePoolConfig);
  if (DOM.localMaintainBtn) DOM.localMaintainBtn.addEventListener('click', triggerLocalPoolMaintain);
  if (DOM.localMaintainSaveBtn) DOM.localMaintainSaveBtn.addEventListener('click', saveLocalPoolConfig);
  DOM.mailTestBtn.addEventListener('click', testMailConnection);
  DOM.mailSaveBtn.addEventListener('click', saveMailConfig);
  if (DOM.registerVersionSaveBtn) DOM.registerVersionSaveBtn.addEventListener('click', saveRegisterVersion);

  DOM.poolRefreshBtn.addEventListener('click', pollPoolStatus);
  DOM.poolMaintainBtn.addEventListener('click', triggerMaintenance);
  if (DOM.poolCopyRtBtn) DOM.poolCopyRtBtn.addEventListener('click', copyAllRt);
  if (DOM.poolExportBtn) DOM.poolExportBtn.addEventListener('click', exportLocalTokens);
  if (DOM.poolPwSyncBtn) DOM.poolPwSyncBtn.addEventListener('click', batchSync);
  if (DOM.tokenFilterApplyBtn) DOM.tokenFilterApplyBtn.addEventListener('click', applyTokenFilter);
  if (DOM.tokenFilterResetBtn) DOM.tokenFilterResetBtn.addEventListener('click', resetTokenFilter);
  if (DOM.tokenFilterKeyword) {
    DOM.tokenFilterKeyword.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') applyTokenFilter();
    });
  }
  if (DOM.sub2apiPoolRefreshBtn) {
    DOM.sub2apiPoolRefreshBtn.addEventListener('click', () => {
      pollSub2ApiPoolStatus();
      loadSub2ApiAccounts();
    });
  }
  if (DOM.sub2apiPoolMaintainBtn) DOM.sub2apiPoolMaintainBtn.addEventListener('click', triggerSub2ApiMaintenance);
  if (DOM.sub2apiTestPoolBtn) DOM.sub2apiTestPoolBtn.addEventListener('click', testSub2ApiPoolConnection);
  if (DOM.sub2apiAccountApplyBtn) DOM.sub2apiAccountApplyBtn.addEventListener('click', applySub2ApiAccountFilter);
  if (DOM.sub2apiAccountResetBtn) DOM.sub2apiAccountResetBtn.addEventListener('click', resetSub2ApiAccountFilter);
  if (DOM.sub2apiAccountKeyword) {
    DOM.sub2apiAccountKeyword.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') applySub2ApiAccountFilter();
    });
  }

  window.addEventListener('pageshow', () => {
    clearSub2ApiAccountKeywordInput();
  });
  if (DOM.sub2apiAccountPrevBtn) DOM.sub2apiAccountPrevBtn.addEventListener('click', () => changeSub2ApiAccountPage(-1));
  if (DOM.sub2apiAccountNextBtn) DOM.sub2apiAccountNextBtn.addEventListener('click', () => changeSub2ApiAccountPage(1));
  if (DOM.sub2apiAccountPageSize) {
    DOM.sub2apiAccountPageSize.addEventListener('change', () => changeSub2ApiAccountPageSize());
  }
  if (DOM.sub2apiAccountSelectAll) DOM.sub2apiAccountSelectAll.addEventListener('change', toggleSelectAllSub2ApiAccounts);
  if (DOM.sub2apiAccountProbeBtn) DOM.sub2apiAccountProbeBtn.addEventListener('click', triggerSelectedSub2ApiProbe);
  if (DOM.sub2apiAccountExceptionBtn) DOM.sub2apiAccountExceptionBtn.addEventListener('click', triggerSub2ApiExceptionHandling);
  if (DOM.sub2apiDuplicateScanBtn) DOM.sub2apiDuplicateScanBtn.addEventListener('click', previewSub2ApiDuplicates);
  if (DOM.sub2apiDuplicateCleanBtn) DOM.sub2apiDuplicateCleanBtn.addEventListener('click', cleanupSub2ApiDuplicates);
  if (DOM.sub2apiAccountDeleteBtn) DOM.sub2apiAccountDeleteBtn.addEventListener('click', triggerSelectedSub2ApiDelete);
  if (DOM.proxyPoolTestBtn) DOM.proxyPoolTestBtn.addEventListener('click', testProxyPoolFetch);
  if (DOM.proxyPoolSaveBtn) DOM.proxyPoolSaveBtn.addEventListener('click', saveProxyPoolConfig);

  if (DOM.poolTokenList) {
    DOM.poolTokenList.addEventListener('click', async (e) => {
      const copyBtn = e.target.closest('.token-copy-btn');
      if (copyBtn) {
        try {
          const payload = decodeURIComponent(copyBtn.dataset.payload || '');
          await copyToken(payload);
        } catch { showToast('复制失败', 'error'); }
        return;
      }
      const deleteBtn = e.target.closest('.token-delete-btn');
      if (deleteBtn) {
        const filename = decodeURIComponent(deleteBtn.dataset.filename || '');
        if (filename) deleteToken(filename);
      }
    });
  }

  if (DOM.sub2apiAccountList) {
    DOM.sub2apiAccountList.addEventListener('click', async (e) => {
      const probeBtn = e.target.closest('.sub2api-account-probe-btn');
      if (probeBtn) {
        const accountId = parseInt(probeBtn.dataset.accountId, 10);
        if (Number.isInteger(accountId) && accountId > 0) {
          await runSub2ApiAccountProbe([accountId], `账号 ${accountId}`);
        }
        return;
      }
      const deleteBtn = e.target.closest('.sub2api-account-delete-btn');
      if (deleteBtn) {
        const accountId = parseInt(deleteBtn.dataset.accountId, 10);
        const email = decodeURIComponent(deleteBtn.dataset.email || '');
        if (Number.isInteger(accountId) && accountId > 0) {
          await runSub2ApiAccountDelete([accountId], email || `账号 ${accountId}`);
        }
      }
    });
    DOM.sub2apiAccountList.addEventListener('change', (e) => {
      const checkbox = e.target.closest('.sub2api-account-check');
      if (!checkbox) return;
      const accountId = parseInt(checkbox.dataset.accountId, 10);
      if (!Number.isInteger(accountId) || accountId <= 0) return;
      if (checkbox.checked) state.ui.selectedSub2ApiAccountIds.add(accountId);
      else state.ui.selectedSub2ApiAccountIds.delete(accountId);
      const row = checkbox.closest('.sub2api-account-item');
      if (row) row.classList.toggle('selected', checkbox.checked);
      refreshSub2ApiSelectionState();
    });
  }

  DOM.logBody.addEventListener('scroll', () => {
    const el = DOM.logBody;
    const isAtBottom = (el.scrollTop + el.clientHeight >= el.scrollHeight - 20);
    state.ui.autoScroll = isAtBottom;
    if (DOM.autoScrollCheck) DOM.autoScrollCheck.checked = isAtBottom;
  });

  if (DOM.autoScrollCheck) {
    DOM.autoScrollCheck.checked = state.ui.autoScroll;
    DOM.autoScrollCheck.addEventListener('change', () => {
      state.ui.autoScroll = DOM.autoScrollCheck.checked;
      if (state.ui.autoScroll) DOM.logBody.scrollTop = DOM.logBody.scrollHeight;
    });
  }

  setInterval(requestStatusSnapshot, 5000);
  setInterval(loadTokens, 60000);
  setInterval(pollPoolStatus, 30000);
  setInterval(pollSub2ApiPoolStatus, 30000);
  setInterval(loadLocalPoolStatus, 30000);
  setInterval(() => loadSub2ApiAccounts({ silent: true }), 60000);

  initTabs();
});

// ==========================================
// Tab 导航切换 — iOS Segmented Control
// ==========================================
function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  if (!tabBtns.length) return;

  tabBtns.forEach((btn, index) => {
    btn.addEventListener('click', () => {
      switchMainTab(btn.dataset.tab || 'tabDashboard');
    });
  });

  const activeTab = Array.from(tabBtns).find(btn => btn.classList.contains('active'))?.dataset.tab || 'tabDashboard';
  switchMainTab(activeTab);
}

function switchMainTab(tabId) {
  const nextTab = tabId === 'tabConfig' ? 'tabConfig' : 'tabDashboard';
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabBtns.forEach((btn, index) => {
    const active = btn.dataset.tab === nextTab;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
    if (active && DOM.segmentIndicator) {
      DOM.segmentIndicator.setAttribute('data-active', String(index));
    }
  });

  tabPanels.forEach((panel) => {
    panel.classList.toggle('active', panel.id === nextTab);
  });
}

function initDataPanelTabs() {
  const defaultTab = 'dataPanelSub2Api';
  const tabButtons = [DOM.headerSub2apiChip, DOM.headerCpaChip, DOM.headerLocalTokenChip].filter(Boolean);
  if (!tabButtons.length) return;

  tabButtons.forEach((btn, index) => {
    btn.addEventListener('click', () => {
      switchDataPanelTab(btn.dataset.panelTab || defaultTab);
    });

    btn.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();

      let nextIndex = index;
      if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabButtons.length;
      if (event.key === 'ArrowLeft') nextIndex = (index - 1 + tabButtons.length) % tabButtons.length;
      if (event.key === 'Home') nextIndex = 0;
      if (event.key === 'End') nextIndex = tabButtons.length - 1;

      const targetBtn = tabButtons[nextIndex];
      if (!targetBtn) return;
      targetBtn.focus();
      switchDataPanelTab(targetBtn.dataset.panelTab || defaultTab);
    });
  });

  if (DOM.headerSub2apiChip) DOM.headerSub2apiChip.dataset.panelTab = 'dataPanelSub2Api';
  if (DOM.headerCpaChip) DOM.headerCpaChip.dataset.panelTab = 'dataPanelCpa';
  if (DOM.headerLocalTokenChip) DOM.headerLocalTokenChip.dataset.panelTab = 'dataPanelLocalTokens';

  switchDataPanelTab(state.ui.dataPanelTab || defaultTab);
}

function switchDataPanelTab(tabId) {
  const nextTab = ['dataPanelSub2Api', 'dataPanelCpa', 'dataPanelLocalTokens'].includes(tabId) ? tabId : 'dataPanelSub2Api';
  state.ui.dataPanelTab = nextTab;

  const panelMap = {
    dataPanelSub2Api: DOM.dataPanelSub2Api,
    dataPanelCpa: DOM.dataPanelCpa,
    dataPanelLocalTokens: DOM.dataPanelLocalTokens,
  };
  const buttonMap = {
    dataPanelSub2Api: DOM.headerSub2apiChip,
    dataPanelCpa: DOM.headerCpaChip,
    dataPanelLocalTokens: DOM.headerLocalTokenChip,
  };

  Object.entries(panelMap).forEach(([id, panel]) => {
    if (!panel) return;
    panel.classList.toggle('active', id === nextTab);
  });
  Object.entries(buttonMap).forEach(([id, btn]) => {
    if (!btn) return;
    const active = id === nextTab;
    btn.classList.toggle('active-view', active);
    btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    btn.tabIndex = active ? 0 : -1;
  });

  const dashboardActive = document.getElementById('tabDashboard')?.classList.contains('active');
  if (!dashboardActive) {
    switchMainTab('tabDashboard');
  }
}

// ==========================================
// 折叠面板
// ==========================================
function initCollapsibles() {
  document.querySelectorAll('.collapsible-trigger').forEach(trigger => {
    trigger.addEventListener('click', () => {
      const section = trigger.closest('.collapsible');
      if (!section) return;
      const body = section.querySelector('.collapsible-body');
      if (!body) return;
      const icon = trigger.querySelector('.collapse-icon');
      const isOpen = section.classList.contains('open');
      if (isOpen) {
        section.classList.remove('open');
        body.style.display = 'none';
        if (icon) icon.classList.remove('open');
      } else {
        section.classList.add('open');
        body.style.display = 'block';
        if (icon) icon.classList.add('open');
      }
    });
  });
}

// ==========================================
// SSE / 快照同步
// ==========================================
function connectSSE() {
  if (state.ui.eventSource) state.ui.eventSource.close();
  const es = new EventSource('/api/logs');
  state.ui.eventSource = es;

  const handleEvent = (sourceType, raw) => {
    try {
      const payload = raw?.data ? JSON.parse(raw.data) : {};
      const event = payload && typeof payload === 'object' ? { ...payload } : {};
      if (!event.type && sourceType && sourceType !== 'message') event.type = sourceType;
      if (!event.type && event.event) event.type = event.event;

      if (event.type) {
        applySseEvent(event);
        return;
      }

      if (Object.prototype.hasOwnProperty.call(event, 'task')
        || Object.prototype.hasOwnProperty.call(event, 'runtime')
        || Object.prototype.hasOwnProperty.call(event, 'stats')) {
        applyStatusSnapshot(event);
      }
    } catch { }
  };

  ['connected', 'snapshot', 'task.updated', 'worker.updated', 'worker.step.updated', 'stats.updated', 'log.appended', 'task.finished']
    .forEach((eventName) => {
      es.addEventListener(eventName, (e) => handleEvent(eventName, e));
    });

  es.onmessage = (e) => handleEvent('message', e);
  es.onerror = () => setTimeout(connectSSE, 3000);
}

// ==========================================
// 日志渲染
// ==========================================
const LEVEL_ICON = { info: '›', success: '✓', error: '✗', warn: '⚠', connected: '⟳' };

function appendLog(event) {
  const { ts, level, message, step } = event;
  state.ui.logCount++;
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-ts">${escapeHtml(ts || '')}</span>
    <span class="log-icon">${LEVEL_ICON[level] || '·'}</span>
    <span class="log-msg ${escapeHtml(level || 'info')}">${escapeHtml(message || '')}</span>
    ${step ? `<span class="log-step">${escapeHtml(getStepDisplayLabel(step))}</span>` : ''}
  `;
  DOM.logBody.appendChild(entry);
  DOM.logCount.textContent = state.ui.logCount;
  if (state.ui.autoScroll) DOM.logBody.scrollTop = DOM.logBody.scrollHeight;
  if (DOM.logBody.children.length > 2000) {
    DOM.logBody.firstElementChild.remove();
  }
}

function clearLog() {
  DOM.logBody.innerHTML = '';
  state.ui.logCount = 0;
  DOM.logCount.textContent = '0';
}

function normalizeRevision(value, fallback = -1) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function normalizeRunId(runId) {
  if (runId === null || runId === undefined || runId === '') return null;
  const value = String(runId).trim();
  return value || null;
}

function normalizeWorkerId(workerId) {
  if (workerId === null || workerId === undefined || workerId === '') return null;
  const value = String(workerId).trim();
  return value || null;
}

function normalizeTaskSnapshot(task, serverTime = null) {
  const source = task && typeof task === 'object' ? task : {};
  return {
    ...state.task,
    ...source,
    status: source.status || 'idle',
    run_id: normalizeRunId(source.run_id) || null,
    revision: normalizeRevision(source.revision, state.task.revision),
    server_time: serverTime || source.server_time || state.task.server_time || null,
  };
}

function normalizeStatsSnapshot(stats) {
  const source = stats && typeof stats === 'object' ? stats : {};
  const success = Number(source.success || 0);
  const fail = Number(source.fail || 0);
  const total = Number.isFinite(Number(source.total)) ? Number(source.total) : (success + fail);
  return {
    ...state.stats,
    ...source,
    success,
    fail,
    total,
  };
}

function normalizeWorkerStep(step, fallbackIndex = 0) {
  if (!step) return null;

  const id = String(step.id || step.step_id || step.step || '').trim();
  if (!id) return null;
  const rawStatus = String(step.status || step.state || 'pending').toLowerCase();
  let status = rawStatus;
  if (['done', 'completed', 'ok'].includes(rawStatus)) status = 'done';
  else if (['error', 'failed', 'fail'].includes(rawStatus)) status = 'error';
  else if (['active', 'running', 'in_progress'].includes(rawStatus)) status = 'active';
  else if (['skipped'].includes(rawStatus)) status = 'skipped';
  else status = 'pending';

  return {
    ...step,
    id,
    step_id: step.step_id || id,
    label: step.label || id,
    status,
    message: step.message || '',
    index: Number.isFinite(Number(step.index)) ? Number(step.index) : fallbackIndex,
    started_at: step.started_at || '',
    finished_at: step.finished_at || '',
    updated_at: step.updated_at || step.finished_at || step.started_at || '',
  };
}

const MAX_WORKER_STEP_ITEMS = 16;

function normalizeWorkerSteps(steps) {
  const normalized = Array.isArray(steps)
    ? steps
      .map((step, index) => normalizeWorkerStep(step, index))
      .filter(Boolean)
    : (steps && typeof steps === 'object')
      ? Object.entries(steps)
        .map(([id, status], index) => normalizeWorkerStep({ id, status, index }, index))
        .filter(Boolean)
      : [];

  if (!normalized.length) return [];

  const deduped = new Map();
  normalized.forEach((step, index) => {
    const key = String(step.step_id || step.id || '').trim();
    if (!key) return;

    const normalizedIndex = Number.isFinite(Number(step.index)) ? Number(step.index) : index;
    const nextStep = { ...step, step_id: key, id: key, index: normalizedIndex };
    const previous = deduped.get(key);
    if (!previous) {
      deduped.set(key, nextStep);
      return;
    }

    const previousUpdated = String(previous.updated_at || previous.finished_at || previous.started_at || '');
    const nextUpdated = String(nextStep.updated_at || nextStep.finished_at || nextStep.started_at || '');
    if (nextUpdated >= previousUpdated) {
      deduped.set(key, { ...previous, ...nextStep, index: Math.min(previous.index, normalizedIndex) });
    }
  });

  return [...deduped.values()]
    .sort((a, b) => {
      const ai = Number.isFinite(a.index) ? a.index : Number.MAX_SAFE_INTEGER;
      const bi = Number.isFinite(b.index) ? b.index : Number.MAX_SAFE_INTEGER;
      if (ai !== bi) return ai - bi;
      return String(a.updated_at || '').localeCompare(String(b.updated_at || ''));
    })
    .slice(-MAX_WORKER_STEP_ITEMS);
}

function normalizeWorker(worker, fallbackId = null) {
  const source = worker && typeof worker === 'object' ? worker : {};
  const workerId = normalizeWorkerId(source.worker_id ?? fallbackId);
  if (!workerId) return null;

  return {
    ...source,
    worker_id: workerId,
    worker_label: source.worker_label || `W${workerId}`,
    status: source.status || 'idle',
    phase: source.phase || 'idle',
    revision: normalizeRevision(source.revision ?? source.runtime_revision, -1),
    current_step: source.current_step || '',
    message: source.message || '',
    email: source.email || source.account_email || '',
    mail_provider: source.mail_provider || '',
    updated_at: source.updated_at || source.ts || '',
    steps: normalizeWorkerSteps(source.steps),
  };
}

function normalizeRuntimeSnapshot(runtime, taskRunId = null) {
  const source = runtime && typeof runtime === 'object' ? runtime : {};
  const workers = Array.isArray(source.workers)
    ? source.workers.map(worker => normalizeWorker(worker)).filter(Boolean)
    : Object.entries(source.workers || {}).map(([workerId, worker]) => normalizeWorker(worker, workerId)).filter(Boolean);

  return {
    ...state.runtime,
    ...source,
    run_id: normalizeRunId(source.run_id) || taskRunId || null,
    revision: normalizeRevision(source.revision, state.runtime.revision),
    focus_worker_id: normalizeWorkerId(source.focus_worker_id),
    completion_semantics: source.completion_semantics || state.runtime.completion_semantics || 'registration_only',
    workers,
  };
}

function getKnownRevision(runId) {
  const key = normalizeRunId(runId);
  if (!key) return -1;
  return normalizeRevision(state.ui.latestRevisionByRun[key], -1);
}

function rememberRevision(runId, revision) {
  const key = normalizeRunId(runId);
  if (!key || !Number.isFinite(revision)) return;
  state.ui.latestRevisionByRun[key] = Math.max(getKnownRevision(key), revision);
}

function shouldIgnoreEvent(runId, revision) {
  const key = normalizeRunId(runId) || normalizeRunId(state.task.run_id) || normalizeRunId(state.runtime.run_id);
  if (!key || !Number.isFinite(revision)) return false;
  const known = getKnownRevision(key);
  if (known >= 0 && revision < known) return true;
  if (known >= 0 && revision > known + 1) requestStatusSnapshot();
  rememberRevision(key, revision);
  return false;
}

function requestStatusSnapshot() {
  if (state.ui.snapshotRequested) return;
  state.ui.snapshotRequested = true;
  fetch('/api/status')
    .then(res => res.json())
    .then(payload => applyStatusSnapshot(payload, { force: true }))
    .catch(() => {})
    .finally(() => {
      state.ui.snapshotRequested = false;
    });
}

function applyStatusSnapshot(payload, { force = false } = {}) {
  if (!payload || typeof payload !== 'object') return;

  const nextTask = normalizeTaskSnapshot(payload.task, payload.server_time || null);
  const nextRuntime = normalizeRuntimeSnapshot(payload.runtime, nextTask.run_id);
  const snapshotRevision = Math.max(nextTask.revision, nextRuntime.revision);
  const snapshotRunId = normalizeRunId(nextTask.run_id) || normalizeRunId(nextRuntime.run_id);

  if (!force && shouldIgnoreEvent(snapshotRunId, snapshotRevision)) return;
  rememberRevision(snapshotRunId, snapshotRevision);

  state.task = nextTask;
  state.runtime = nextRuntime;
  state.stats = normalizeStatsSnapshot(payload.stats);

  ensureFocusWorker();
  syncTaskChrome();
  renderRuntimePanels();
}

function applySseEvent(event) {
  if (!event || typeof event !== 'object') return;
  const type = String(event.type || event.event || '').trim();
  const runId = normalizeRunId(event.run_id || event.task?.run_id || event.runtime?.run_id || event.worker?.run_id);
  const revision = normalizeRevision(event.revision ?? event.task?.revision ?? event.runtime?.revision ?? event.worker?.revision, NaN);

  if (type && shouldIgnoreEvent(runId, revision)) return;

  if (type === 'connected') {
    appendLog({ ts: event.ts || '', level: 'connected', message: event.message || '实时事件已连接' });
    if (event.snapshot) applyStatusSnapshot(event.snapshot, { force: true });
    else requestStatusSnapshot();
    return;
  }

  if (type === 'snapshot') {
    applyStatusSnapshot(event.snapshot || event.payload || event, { force: true });
    return;
  }

  if (type === 'log.appended') {
    const logEvent = event.log && typeof event.log === 'object' ? event.log : event;
    appendLog(logEvent);
    if (logEvent.level === 'token_saved') {
      debouncedLoadTokens();
      showToast('新 Token 已保存: ' + (logEvent.message || ''), 'success');
    }
    if (logEvent.level === 'sync_ok') {
      showToast('已自动同步: ' + (logEvent.message || ''), 'success');
    }
    if (logEvent.step === 'wait' && logEvent.message) {
      const match = String(logEvent.message).match(/(\d+)\s*秒/);
      if (match) startCountdown(parseInt(match[1], 10));
    }
    return;
  }

  if (type === 'task.updated' || type === 'task.finished') {
    state.task = normalizeTaskSnapshot({ ...state.task, ...(event.task || event) }, event.server_time || state.task.server_time);
    if (type === 'task.finished') requestStatusSnapshot();
    syncTaskChrome();
    renderRuntimePanels();
    return;
  }

  if (type === 'stats.updated') {
    state.stats = normalizeStatsSnapshot({ ...state.stats, ...(event.stats || event) });
    syncTaskChrome();
    renderRuntimePanels();
    return;
  }

  if (type === 'worker.updated') {
    mergeWorkerIntoRuntime(event.worker || event.runtime || event);
    return;
  }

  if (type === 'worker.step.updated') {
    mergeWorkerStepUpdate(event);
    return;
  }

  if (Object.prototype.hasOwnProperty.call(event, 'task')
    || Object.prototype.hasOwnProperty.call(event, 'runtime')
    || Object.prototype.hasOwnProperty.call(event, 'stats')) {
    applyStatusSnapshot(event);
  }
}

// ==========================================
// 代理检测
// ==========================================
async function checkProxy() {
  const proxy = DOM.proxyInput.value.trim();
  if (!proxy) { showToast('请先填写代理地址', 'error'); return; }
  DOM.proxyStatus.className = 'proxy-status';
  DOM.proxyStatus.innerHTML = '<span>检测中...</span>';
  DOM.checkProxyBtn.disabled = true;
  try {
    const res = await fetch('/api/check-proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxy }),
    });
    const data = await res.json();
    if (data.ok) {
      DOM.proxyStatus.className = 'proxy-status ok';
      DOM.proxyStatus.innerHTML = `<span>可用 · 所在地: <b>${escapeHtml(data.loc || '')}</b></span>`;
    } else {
      DOM.proxyStatus.className = 'proxy-status fail';
      DOM.proxyStatus.innerHTML = `<span>不可用 · ${escapeHtml(data.error || '')}</span>`;
    }
  } catch {
    DOM.proxyStatus.className = 'proxy-status fail';
    DOM.proxyStatus.innerHTML = '<span>检测请求失败</span>';
  } finally {
    DOM.checkProxyBtn.disabled = false;
  }
}

// ==========================================
// 代理保存
// ==========================================
async function saveProxy() {
  const proxy = DOM.proxyInput.value.trim();
  try {
    const res = await fetch('/api/proxy/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxy }),
    });
    if (res.ok) {
      showToast('代理配置已保存', 'success');
    } else {
      showToast('保存失败', 'error');
    }
  } catch (e) {
    showToast('保存请求失败: ' + e.message, 'error');
  }
}

// ==========================================
// 任务控制设置自动保存
// ==========================================
async function loadTaskControl() {
  try {
    const res = await fetch('/api/task-control');
    const cfg = await res.json();
    if (DOM.multithreadCheck) DOM.multithreadCheck.checked = !!cfg.multithread;
    if (DOM.threadCountInput) DOM.threadCountInput.value = cfg.thread_count || 3;
    if (DOM.autoRegisterCheck) DOM.autoRegisterCheck.checked = !!cfg.auto_register;
  } catch { }
}

async function saveTaskControl() {
  const multithread = DOM.multithreadCheck ? DOM.multithreadCheck.checked : false;
  const thread_count = DOM.threadCountInput ? parseInt(DOM.threadCountInput.value, 10) || 3 : 3;
  const auto_register = DOM.autoRegisterCheck ? DOM.autoRegisterCheck.checked : false;
  try {
    const res = await fetch('/api/task-control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ multithread, thread_count, auto_register }),
    });
    if (res.ok) {
      showToast('任务控制配置已保存', 'success');
    }
  } catch { }
}

// ==========================================
// 启动 / 停止任务
// ==========================================
function getRequestedWorkerCount() {
  const multithread = DOM.multithreadCheck ? DOM.multithreadCheck.checked : false;
  if (!multithread) return 1;
  return Math.max(1, DOM.threadCountInput ? (parseInt(DOM.threadCountInput.value, 10) || 1) : 1);
}

async function startTask() {
  const proxy = DOM.proxyInput.value.trim();
  const worker_count = getRequestedWorkerCount();
  const targetEl = document.getElementById('targetCountInput');
  const target_count = targetEl ? Math.max(0, parseInt(targetEl.value, 10) || 0) : 0;
  try {
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxy, worker_count, target_count }),
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || '启动失败', 'error');
      return;
    }
    applyStatusSnapshot(data, { force: true });
    const workerMsg = worker_count > 1 ? ` (${worker_count} 线程)` : '';
    const targetMsg = target_count > 0 ? ` 目标 ${target_count} 个` : '';
    showToast('注册任务已启动' + workerMsg + targetMsg, 'success');
  } catch (e) {
    showToast('启动请求失败: ' + e.message, 'error');
  }
}

async function stopTask() {
  try {
    const res = await fetch('/api/stop', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || '停止失败', 'error');
      return;
    }
    applyStatusSnapshot(data, { force: true });
    showToast('正在停止任务...', 'info');
    requestStatusSnapshot();
  } catch (e) {
    showToast('停止请求失败: ' + e.message, 'error');
  }
}

// ==========================================
// 状态更新 / 渲染
// ==========================================
function syncTaskChrome() {
  const status = state.task.status || 'idle';
  DOM.statusBadge.className = `status-badge ${status}`;
  DOM.statusText.textContent = formatTaskStatusLabel(status);

  const hasLiveRun = Boolean(state.task.run_id) && !state.task.finished_at;
  const isActive = ['starting', 'running'].includes(status);
  const isStopping = status === 'stopping';
  const canStop = hasLiveRun && ['starting', 'running', 'failed'].includes(status);
  DOM.btnStart.disabled = hasLiveRun || isStopping;
  DOM.btnStop.disabled = !canStop;
  DOM.progressFill.className = isActive
    ? 'progress-fill running'
    : (isStopping ? 'progress-fill stopping' : 'progress-fill');

  if (DOM.statSuccess) DOM.statSuccess.textContent = state.stats.success;
  if (DOM.statFail) DOM.statFail.textContent = state.stats.fail;
  if (DOM.statTotal) DOM.statTotal.textContent = state.stats.total;

  if (status === 'idle' && state.ui.countdownTimer) {
    clearInterval(state.ui.countdownTimer);
    state.ui.countdownTimer = null;
  }
}

function formatTaskStatusLabel(status) {
  return STATUS_LABEL_MAP[status] || (status ? String(status) : '等待开始');
}

function getStepDisplayLabel(stepId) {
  return STEP_DISPLAY_LABELS[stepId] || (stepId ? String(stepId) : '等待开始');
}

function getWorkerStatusLabel(status) {
  return STATUS_LABEL_MAP[status] || (status ? String(status) : '等待开始');
}

function getPhaseLabel(phase) {
  return PHASE_LABEL_MAP[phase] || (phase ? String(phase) : '等待任务');
}

function getCompletionSemanticsLabel(value) {
  return COMPLETION_SEMANTICS_MAP[value] || '注册完成即结束';
}

function getWorkerSortKey(worker) {
  return [
    WORKER_STATUS_PRIORITY[worker?.status] || 0,
    worker?.updated_at || '',
    Number(worker?.worker_id || 0),
  ];
}

function compareWorkerRuntime(a, b) {
  const [sa, ua, wa] = getWorkerSortKey(a);
  const [sb, ub, wb] = getWorkerSortKey(b);
  if (sa !== sb) return sb - sa;
  if (ua !== ub) return ub.localeCompare(ua);
  return wb - wa;
}

function sortWorkers(workers) {
  return [...workers].sort(compareWorkerRuntime);
}

function ensureFocusWorker() {
  const workers = sortWorkers(state.runtime.workers || []);
  const lockedId = normalizeWorkerId(state.ui.focusWorkerId);
  if (state.ui.focusLocked && lockedId && workers.some(worker => worker.worker_id === lockedId)) return;

  const backendFocus = normalizeWorkerId(state.runtime.focus_worker_id);
  if (backendFocus && workers.some(worker => worker.worker_id === backendFocus)) {
    state.ui.focusWorkerId = backendFocus;
    return;
  }

  state.ui.focusWorkerId = workers[0]?.worker_id || null;
}

function getFocusWorker() {
  const focusId = normalizeWorkerId(state.ui.focusWorkerId);
  if (!focusId) return null;
  return (state.runtime.workers || []).find(worker => worker.worker_id === focusId) || null;
}

function selectFocusWorker(nextId, { lock = false } = {}) {
  const normalizedId = normalizeWorkerId(nextId);
  if (!normalizedId) return;
  if (!(state.runtime.workers || []).some(worker => worker.worker_id === normalizedId)) return;
  state.ui.focusWorkerId = normalizedId;
  if (lock) state.ui.focusLocked = true;
  renderRuntimePanels();
}

function unlockFocusWorker() {
  state.ui.focusLocked = false;
  ensureFocusWorker();
  renderRuntimePanels();
}

function mergeWorkerIntoRuntime(workerPatch) {
  const normalizedWorker = normalizeWorker(workerPatch);
  if (!normalizedWorker) return;

  const workers = [...(state.runtime.workers || [])];
  const index = workers.findIndex(worker => worker.worker_id === normalizedWorker.worker_id);
  if (index >= 0) {
    const prevWorker = workers[index];
    workers[index] = normalizeWorker({
      ...prevWorker,
      ...normalizedWorker,
      steps: normalizedWorker.steps.length ? normalizedWorker.steps : prevWorker.steps,
    }, normalizedWorker.worker_id);
  } else {
    workers.push(normalizedWorker);
  }

  state.runtime = {
    ...state.runtime,
    run_id: normalizeRunId(normalizedWorker.run_id) || state.runtime.run_id || state.task.run_id,
    focus_worker_id: normalizeWorkerId(state.runtime.focus_worker_id) || normalizedWorker.worker_id,
    workers: sortWorkers(workers),
  };

  ensureFocusWorker();
  renderRuntimePanels();
}

function upsertWorkerStep(existingSteps, stepPatch) {
  const steps = normalizeWorkerSteps(existingSteps);
  const normalizedStep = normalizeWorkerStep(stepPatch, steps.length);
  if (!normalizedStep) return steps;

  const next = [...steps];
  const index = next.findIndex(step => step.id === normalizedStep.id);
  if (index >= 0) next[index] = { ...next[index], ...normalizedStep };
  else next.push(normalizedStep);
  return normalizeWorkerSteps(next);
}

function mergeWorkerStepUpdate(event) {
  const workerSource = event.worker && typeof event.worker === 'object' ? event.worker : event;
  const workerId = normalizeWorkerId(workerSource.worker_id || event.worker_id);
  if (!workerId) {
    requestStatusSnapshot();
    return;
  }

  const workers = [...(state.runtime.workers || [])];
  const index = workers.findIndex(worker => worker.worker_id === workerId);
  const baseWorker = index >= 0 ? workers[index] : normalizeWorker({ worker_id: workerId, worker_label: `W${workerId}` }, workerId);
  const nextWorker = normalizeWorker({
    ...baseWorker,
    ...workerSource,
    worker_id: workerId,
    steps: workerSource.steps || upsertWorkerStep(baseWorker?.steps || [], event.step || workerSource.step || workerSource),
  }, workerId);

  if (index >= 0) workers[index] = nextWorker;
  else workers.push(nextWorker);

  state.runtime = {
    ...state.runtime,
    workers: sortWorkers(workers),
    focus_worker_id: normalizeWorkerId(event.focus_worker_id) || state.runtime.focus_worker_id || workerId,
  };

  ensureFocusWorker();
  renderRuntimePanels();
}

function getWorkerPrimaryStep(worker) {
  if (!worker) return null;
  const steps = Array.isArray(worker.steps) ? worker.steps : [];
  const activeStep = steps.find(step => step.status === 'active');
  if (activeStep) return activeStep;
  return steps[steps.length - 1] || null;
}

function renderTaskOverview(task, runtime, stats) {
  if (!DOM.taskOverview) return;
  const workers = Array.isArray(runtime?.workers) ? runtime.workers : [];
  const activeWorkers = workers.filter(worker => !['idle', 'stopped'].includes(String(worker.status || 'idle'))).length;
  const cards = [
    { label: '任务状态', value: formatTaskStatusLabel(task?.status || 'idle'), hint: task?.status || 'idle', status: `task-status-${task?.status || 'idle'}` },
    { label: '运行标识', value: task?.run_id || '--', hint: `revision ${normalizeRevision(task?.revision, 0)}`, status: 'task-status-meta' },
    { label: 'Worker', value: `${activeWorkers}/${workers.length}`, hint: `focus ${runtime?.focus_worker_id || '--'}`, status: 'task-status-meta' },
    { label: '成功 / 失败', value: `${stats?.success || 0} / ${stats?.fail || 0}`, hint: `total ${stats?.total || 0}`, status: 'task-status-meta' },
  ];

  if (!task?.run_id && (task?.status || 'idle') === 'idle' && workers.length === 0) {
    DOM.taskOverview.innerHTML = '<div class="task-overview-card empty">等待任务启动</div>';
    return;
  }

  DOM.taskOverview.innerHTML = cards.map(card => `
    <div class="task-overview-card ${escapeHtml(card.status)}">
      <span class="task-overview-label">${escapeHtml(card.label)}</span>
      <span class="task-overview-value">${escapeHtml(card.value)}</span>
      <span class="task-overview-hint">${escapeHtml(card.hint)}</span>
    </div>
  `).join('');
}

function renderWorkerList(workers, focusWorkerId) {
  if (!DOM.workerList) return;
  const entries = sortWorkers(Array.isArray(workers) ? workers : []);
  if (!entries.length) {
    DOM.workerList.innerHTML = '<div class="worker-card empty">暂无 Worker 运行</div>';
    return;
  }

  DOM.workerList.innerHTML = entries.map((worker) => {
    const workerId = worker.worker_id;
    const focused = normalizeWorkerId(focusWorkerId) === workerId;
    const primaryStep = getWorkerPrimaryStep(worker);
    const stepLabel = primaryStep ? primaryStep.label : '等待开始';
    const email = worker.email || '等待邮箱创建';
    const updatedAt = worker.updated_at || '--';
    const status = String(worker.status || 'idle');
    return `
      <button class="worker-card worker-card-${escapeHtml(status)} ${focused ? 'focused' : ''}" type="button" data-worker-id="${escapeHtml(workerId)}">
        <div class="worker-card-head">
          <span class="worker-card-label">${escapeHtml(worker.worker_label || `W${workerId}`)}</span>
          <span class="worker-status-badge ${escapeHtml(status)}">${escapeHtml(getWorkerStatusLabel(status))}</span>
        </div>
        <div class="worker-card-email">${escapeHtml(email)}</div>
        <div class="worker-card-row">
          <span class="worker-card-meta">${escapeHtml(stepLabel)}</span>
          <span class="worker-card-meta">${escapeHtml(updatedAt)}</span>
        </div>
      </button>
    `;
  }).join('');

  DOM.workerList.querySelectorAll('[data-worker-id]').forEach((button) => {
    button.addEventListener('click', () => selectFocusWorker(button.dataset.workerId, { lock: true }));
  });
}

function renderWorkerDetail(focusWorker) {
  if (!DOM.workerDetail) return;
  if (!focusWorker) {
    DOM.workerDetail.className = 'worker-detail-card empty';
    DOM.workerDetail.innerHTML = '等待任务启动';
    if (DOM.unlockFocusBtn) DOM.unlockFocusBtn.disabled = !state.ui.focusLocked;
    return;
  }

  const status = String(focusWorker.status || 'idle');
  const completionSemantics = getCompletionSemanticsLabel(state.runtime.completion_semantics || 'registration_only');
  const metaItems = [
    { label: 'Worker', value: focusWorker.worker_label || `W${focusWorker.worker_id}` },
    { label: '状态', value: `${getWorkerStatusLabel(status)} · ${getPhaseLabel(focusWorker.phase || 'idle')}` },
    { label: '邮箱', value: focusWorker.email || '等待邮箱创建' },
    { label: '邮箱提供商', value: focusWorker.mail_provider || '--' },
    { label: '当前步骤', value: getWorkerPrimaryStep(focusWorker)?.label || '等待开始' },
    { label: '完成语义', value: completionSemantics },
    { label: '更新时间', value: focusWorker.updated_at || '--' },
    { label: '进度消息', value: focusWorker.message || '等待后端步骤更新', wide: true },
  ];

  const steps = Array.isArray(focusWorker.steps) ? focusWorker.steps : [];
  const stepsHtml = steps.length
    ? steps.map((step) => `
        <div class="step-track-item step-status-${escapeHtml(step.status || 'pending')}">
          <div class="step-track-head">
            <span class="step-track-label">${escapeHtml(step.label || step.step_id || step.id || '未命名步骤')}</span>
            <span class="step-track-badge">${escapeHtml(step.status || 'pending')}</span>
          </div>
          ${step.message ? `<div class="step-track-message">${escapeHtml(step.message)}</div>` : ''}
          ${step.updated_at ? `<div class="step-track-time">${escapeHtml(step.updated_at)}</div>` : ''}
        </div>
      `).join('')
    : '<div class="step-track-empty">暂无步骤轨道</div>';

  DOM.workerDetail.className = `worker-detail-card worker-detail-${escapeHtml(status)}`;
  DOM.workerDetail.innerHTML = `
    <div class="worker-detail-meta">
      ${metaItems.map((item) => `
        <div class="worker-detail-meta-item ${item.wide ? 'wide' : ''}">
          <span class="worker-detail-meta-label">${escapeHtml(item.label)}</span>
          <span class="worker-detail-meta-value">${escapeHtml(item.value)}</span>
        </div>
      `).join('')}
    </div>
    <div class="worker-detail-steps">
      <div class="worker-detail-steps-title">步骤轨道</div>
      <div class="step-track-list">${stepsHtml}</div>
    </div>
  `;

  if (DOM.unlockFocusBtn) DOM.unlockFocusBtn.disabled = !state.ui.focusLocked;
}

function renderRuntimePanels() {
  renderTaskOverview(state.task, state.runtime, state.stats);
  renderWorkerList(state.runtime.workers, state.ui.focusWorkerId);
  renderWorkerDetail(getFocusWorker());
}

function startCountdown(seconds) {
  if (state.ui.countdownTimer) clearInterval(state.ui.countdownTimer);
  let remaining = seconds;
  const entries = DOM.logBody.querySelectorAll('.log-entry');
  const countdownEntry = entries.length > 0 ? entries[entries.length - 1] : null;
  const countdownMsgEl = countdownEntry ? countdownEntry.querySelector('.log-msg') : null;
  state.ui.countdownTimer = setInterval(() => {
    remaining--;
    if (remaining <= 0) { clearInterval(state.ui.countdownTimer); state.ui.countdownTimer = null; return; }
    if (countdownMsgEl) countdownMsgEl.textContent = `休息中... 剩余 ${remaining} 秒`;
  }, 1000);
}

// ==========================================
// Token 列表
// ==========================================
function debouncedLoadTokens() {
  if (state.ui._loadTokensTimer) clearTimeout(state.ui._loadTokensTimer);
  state.ui._loadTokensTimer = setTimeout(() => {
    loadTokens();
    state.ui._loadTokensTimer = null;
  }, 1000);
}

async function loadTokens() {
  try {
    const res = await fetch('/api/tokens');
    const data = await res.json();
    state.ui.tokens = data.tokens || [];
    renderTokenList();
  } catch { }
}

function getFilteredTokens(tokens) {
  const status = state.ui.tokenFilter.status || 'all';
  const keyword = (state.ui.tokenFilter.keyword || '').trim().toLowerCase();

  return (tokens || []).filter((t) => {
    const platforms = getTokenUploadedPlatforms(t);
    const uploaded = platforms.length > 0;
    if (status === 'synced' && !uploaded) return false;
    if (status === 'unsynced' && uploaded) return false;
    if (status === 'cpa' && !platforms.includes('cpa')) return false;
    if (status === 'sub2api' && !platforms.includes('sub2api')) return false;
    if (status === 'both' && !(platforms.includes('cpa') && platforms.includes('sub2api'))) return false;

    if (!keyword) return true;
    const email = String(t.email || '').toLowerCase();
    const fname = String(t.filename || '').toLowerCase();
    return email.includes(keyword) || fname.includes(keyword);
  });
}

function getTokenUploadedPlatforms(token) {
  const platforms = new Set();
  const fromTop = Array.isArray(token && token.uploaded_platforms) ? token.uploaded_platforms : [];
  const content = (token && token.content) || {};
  const fromContent = Array.isArray(content.uploaded_platforms) ? content.uploaded_platforms : [];
  [...fromTop, ...fromContent].forEach((p) => {
    const name = String(p || '').toLowerCase().trim();
    if (name === 'cpa' || name === 'sub2api') platforms.add(name);
  });
  if (content.cpa_uploaded || content.cpa_synced) platforms.add('cpa');
  if (content.sub2api_uploaded || content.sub2api_synced || content.synced) platforms.add('sub2api');
  return ['cpa', 'sub2api'].filter((p) => platforms.has(p));
}

function renderTokenList() {
  const allTokens = state.ui.tokens || [];
  const filteredTokens = getFilteredTokens(allTokens);
  updateHeaderLocalTokens(allTokens);

  if (!DOM.poolTokenList) return;
  if (filteredTokens.length === 0) {
    const msg = allTokens.length === 0 ? '暂无 Token' : '暂无符合筛选条件的 Token';
    DOM.poolTokenList.innerHTML = `<div class="empty-state"><div class="empty-icon">🔑</div><span>${msg}</span></div>`;
    return;
  }
  DOM.poolTokenList.innerHTML = filteredTokens.map(t => renderTokenItem(t)).join('');
}

function applyTokenFilter() {
  state.ui.tokenFilter.status = DOM.tokenFilterStatus ? DOM.tokenFilterStatus.value : 'all';
  state.ui.tokenFilter.keyword = DOM.tokenFilterKeyword ? DOM.tokenFilterKeyword.value.trim() : '';
  renderTokenList();
}

function resetTokenFilter() {
  state.ui.tokenFilter.status = 'all';
  state.ui.tokenFilter.keyword = '';
  if (DOM.tokenFilterStatus) DOM.tokenFilterStatus.value = 'all';
  if (DOM.tokenFilterKeyword) DOM.tokenFilterKeyword.value = '';
  renderTokenList();
}

function renderTokenItem(t) {
  const platforms = getTokenUploadedPlatforms(t);
  const uploaded = platforms.length > 0;
  const content = t.content || {};
  const platformBadges = platforms.length > 0
    ? platforms.map((p) => `<span class="platform-badge ${p}">${p === 'cpa' ? 'CPA' : 'Sub2Api'}</span>`).join('')
    : '<span class="platform-badge none">未上传</span>';
  const localStatus = String(content.local_status || '').trim();
  const localRecoveredStatus = String(content.local_recovered_status || '').trim();
  const localStatusText = localStatus
    ? `本地状态: ${escapeHtml(localStatus)}${content.next_check_at ? ` / 下次检查 ${escapeHtml(formatTime(content.next_check_at))}` : ''}`
    : (localRecoveredStatus ? `恢复状态: ${escapeHtml(localRecoveredStatus)}` : '本地状态: 正常');
  const usedPercentText = content.last_used_percent != null ? ` / 最近用量 ${escapeHtml(String(content.last_used_percent))}%` : '';
  const expiredStr = formatTime(t.expired);
  const tokenPayload = encodeURIComponent(JSON.stringify(content));
  const filePayload = encodeURIComponent(t.filename || '');
  return `
    <div class="token-item${uploaded ? ' synced' : ''}" id="token-${cssEscape(t.filename)}">
      <div class="token-info">
        <div class="token-email" title="${escapeHtml(t.email)}">
          <span class="token-email-text">${escapeHtml(t.email || t.filename)}</span>
        </div>
        <div class="token-meta token-platforms">${platformBadges}</div>
        <div class="token-meta">${localStatusText}${usedPercentText}</div>
        <div class="token-meta">过期: ${expiredStr}</div>
      </div>
      <div class="token-actions">
        <button class="btn btn-ghost btn-sm token-copy-btn" data-payload="${tokenPayload}">复制</button>
        <button class="btn btn-danger btn-sm token-delete-btn" data-filename="${filePayload}">删除</button>
      </div>
    </div>`;
}

function formatTime(timeStr) {
  if (!timeStr) return '未知';
  try {
    const d = new Date(timeStr);
    if (isNaN(d.getTime())) return timeStr;
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  } catch { return timeStr; }
}

async function copyToken(jsonStr) {
  const ok = await copyText(jsonStr);
  showToast(ok ? 'Token 已复制到剪贴板' : '复制失败', ok ? 'success' : 'error');
}

async function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try { await navigator.clipboard.writeText(text); return true; } catch { }
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch { return false; }
}

async function copyAllRt() {
  try {
    const visibleTokens = getFilteredTokens(state.ui.tokens || []);
    const rts = visibleTokens.map(t => (t.content || {}).refresh_token || '').filter(Boolean);
    if (rts.length === 0) { showToast('没有可用的 Refresh Token', 'error'); return; }
    const ok = await copyText(rts.join('\n'));
    showToast(ok ? `已复制 ${rts.length} 个 RT（当前筛选）` : '复制失败', ok ? 'success' : 'error');
  } catch (e) { showToast('复制失败: ' + e.message, 'error'); }
}

function downloadBlob(filename, blob) {
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function exportLocalTokens() {
  try {
    const visibleTokens = getFilteredTokens(state.ui.tokens || []);
    if (visibleTokens.length === 0) {
      showToast('没有可导出的 Token（当前筛选）', 'error');
      return;
    }

    const exportPayload = {
      exported_at: new Date().toISOString(),
      total: visibleTokens.length,
      filter: {
        status: state.ui.tokenFilter.status || 'all',
        keyword: state.ui.tokenFilter.keyword || '',
      },
      tokens: visibleTokens.map((t) => ({
        filename: t.filename || '',
        email: t.email || '',
        uploaded_platforms: getTokenUploadedPlatforms(t),
        content: t.content || {},
      })),
    };

    const status = String(state.ui.tokenFilter.status || 'all').replace(/[^a-z0-9_-]/gi, '_');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `local_tokens_${status}_${stamp}.json`;
    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    downloadBlob(filename, blob);
    showToast(`已导出 ${visibleTokens.length} 条 Token（当前筛选）`, 'success');
  } catch (e) {
    showToast('导出失败: ' + e.message, 'error');
  }
}

async function deleteToken(filename) {
  if (!confirm(`确认删除 ${filename}？`)) return;
  try {
    const res = await fetch(`/api/tokens/${encodeURIComponent(filename)}`, { method: 'DELETE' });
    if (res.ok) { showToast('已删除', 'info'); loadTokens(); }
    else showToast('删除失败', 'error');
  } catch { showToast('删除请求失败', 'error'); }
}

function isSub2ApiAbnormalStatus(status) {
  return SUB2API_ABNORMAL_STATUSES.has(String(status || '').trim().toLowerCase());
}

function getSub2ApiMaintainActionsFromForm() {
  return {
    refresh_abnormal_accounts: DOM.sub2apiMaintainRefreshAbnormal ? DOM.sub2apiMaintainRefreshAbnormal.checked : true,
    delete_abnormal_accounts: DOM.sub2apiMaintainDeleteAbnormal ? DOM.sub2apiMaintainDeleteAbnormal.checked : true,
    dedupe_duplicate_accounts: DOM.sub2apiMaintainDedupe ? DOM.sub2apiMaintainDedupe.checked : true,
  };
}

function describeSub2ApiMaintainActions(actions = getSub2ApiMaintainActionsFromForm()) {
  const labels = [];
  if (actions.refresh_abnormal_accounts) labels.push('异常测活');
  if (actions.delete_abnormal_accounts) labels.push('异常清理');
  if (actions.dedupe_duplicate_accounts) labels.push('重复清理');
  return labels.length ? labels.join('、') : '无动作';
}

function getFilteredSub2ApiAccounts(accounts = state.ui.sub2apiAccounts || []) {
  return Array.isArray(accounts) ? accounts : [];
}

function applySub2ApiAccountFilter() {
  state.ui.sub2apiAccountFilter.status = DOM.sub2apiAccountStatusFilter ? DOM.sub2apiAccountStatusFilter.value : 'all';
  state.ui.sub2apiAccountFilter.keyword = DOM.sub2apiAccountKeyword ? DOM.sub2apiAccountKeyword.value.trim() : '';
  state.ui.sub2apiAccountPager.page = 1;
  loadSub2ApiAccounts();
}

function resetSub2ApiAccountFilter() {
  state.ui.sub2apiAccountFilter.status = 'all';
  state.ui.sub2apiAccountFilter.keyword = '';
  if (DOM.sub2apiAccountStatusFilter) DOM.sub2apiAccountStatusFilter.value = 'all';
  if (DOM.sub2apiAccountKeyword) DOM.sub2apiAccountKeyword.value = '';
  state.ui.sub2apiAccountPager.page = 1;
  loadSub2ApiAccounts();
}

async function loadSub2ApiAccounts({ silent = false } = {}) {
  if (!DOM.sub2apiAccountList || state.ui.sub2apiAccountsLoading) return;
  state.ui.sub2apiAccountsLoading = true;
  if (!silent && DOM.sub2apiAccountActionStatus && !state.ui.sub2apiAccountActionBusy) {
    DOM.sub2apiAccountActionStatus.textContent = '正在加载 Sub2Api 账号列表...';
  }
  try {
    const params = new URLSearchParams({
      page: String(state.ui.sub2apiAccountPager.page || 1),
      page_size: String(state.ui.sub2apiAccountPager.pageSize || 20),
      status: String(state.ui.sub2apiAccountFilter.status || 'all'),
      keyword: String(state.ui.sub2apiAccountFilter.keyword || ''),
    });
    const res = await fetch(`/api/sub2api/accounts?${params.toString()}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Sub2Api 账号列表加载失败');

    if (!data.configured) {
      state.ui.sub2apiAccounts = [];
      state.ui.selectedSub2ApiAccountIds.clear();
      state.ui.sub2apiAccountPager.total = 0;
      state.ui.sub2apiAccountPager.filteredTotal = 0;
      state.ui.sub2apiAccountPager.totalPages = 1;
      state.ui.sub2apiAccountPager.page = 1;
      renderSub2ApiAccountList('请先完成 Sub2Api 平台配置');
      if (DOM.sub2apiAccountActionStatus && !state.ui.sub2apiAccountActionBusy) {
        DOM.sub2apiAccountActionStatus.textContent = data.error || 'Sub2Api 未配置';
      }
      return;
    }

    state.ui.sub2apiAccounts = Array.isArray(data.items) ? data.items : [];
    state.ui.sub2apiAccountPager.page = parseInt(data.page, 10) || 1;
    state.ui.sub2apiAccountPager.pageSize = parseInt(data.page_size, 10) || state.ui.sub2apiAccountPager.pageSize || 20;
    state.ui.sub2apiAccountPager.total = parseInt(data.total, 10) || 0;
    state.ui.sub2apiAccountPager.filteredTotal = parseInt(data.filtered_total, 10) || 0;
    state.ui.sub2apiAccountPager.totalPages = parseInt(data.total_pages, 10) || 1;
    renderSub2ApiAccountList();
    if (!silent && DOM.sub2apiAccountActionStatus && !state.ui.sub2apiAccountActionBusy) {
      DOM.sub2apiAccountActionStatus.textContent = `已加载第 ${state.ui.sub2apiAccountPager.page}/${state.ui.sub2apiAccountPager.totalPages} 页，共 ${state.ui.sub2apiAccountPager.filteredTotal} 个账号`;
    }
  } catch (e) {
    state.ui.sub2apiAccounts = [];
    state.ui.sub2apiAccountPager.filteredTotal = 0;
    state.ui.sub2apiAccountPager.totalPages = 1;
    renderSub2ApiAccountList('Sub2Api 账号列表加载失败');
    if (DOM.sub2apiAccountActionStatus && !state.ui.sub2apiAccountActionBusy) {
      DOM.sub2apiAccountActionStatus.textContent = '账号列表加载失败: ' + e.message;
    }
  } finally {
    state.ui.sub2apiAccountsLoading = false;
    refreshSub2ApiSelectionState();
  }
}

function updateSub2ApiPagerUI() {
  const pager = state.ui.sub2apiAccountPager || {};
  const page = pager.page || 1;
  const totalPages = pager.totalPages || 1;
  const pageSize = pager.pageSize || 20;
  if (DOM.sub2apiAccountPageInfo) {
    DOM.sub2apiAccountPageInfo.textContent = `第 ${page}/${totalPages} 页 · 每页 ${pageSize} 条`;
  }
  if (DOM.sub2apiAccountPageSize && String(DOM.sub2apiAccountPageSize.value) !== String(pageSize)) {
    DOM.sub2apiAccountPageSize.value = String(pageSize);
  }
  if (DOM.sub2apiAccountPrevBtn) DOM.sub2apiAccountPrevBtn.disabled = state.ui.sub2apiAccountActionBusy || page <= 1;
  if (DOM.sub2apiAccountNextBtn) DOM.sub2apiAccountNextBtn.disabled = state.ui.sub2apiAccountActionBusy || page >= totalPages;
}

function changeSub2ApiAccountPage(delta) {
  const nextPage = (state.ui.sub2apiAccountPager.page || 1) + delta;
  const totalPages = state.ui.sub2apiAccountPager.totalPages || 1;
  if (nextPage < 1 || nextPage > totalPages) return;
  state.ui.sub2apiAccountPager.page = nextPage;
  loadSub2ApiAccounts();
}

function changeSub2ApiAccountPageSize() {
  const nextPageSize = DOM.sub2apiAccountPageSize ? parseInt(DOM.sub2apiAccountPageSize.value, 10) || 20 : 20;
  state.ui.sub2apiAccountPager.pageSize = nextPageSize;
  state.ui.sub2apiAccountPager.page = 1;
  loadSub2ApiAccounts();
}

function renderSub2ApiAccountList(emptyMessage = '') {
  const pageAccounts = getFilteredSub2ApiAccounts(state.ui.sub2apiAccounts || []);
  const pager = state.ui.sub2apiAccountPager || {};
  if (!DOM.sub2apiAccountList) return;
  if (pageAccounts.length === 0) {
    const hasAny = (pager.filteredTotal || 0) > 0 || (pager.total || 0) > 0;
    const msg = emptyMessage || (!hasAny ? '暂无 Sub2Api 账号' : '暂无符合筛选条件的账号');
    DOM.sub2apiAccountList.innerHTML = `<div class="empty-state"><div class="empty-icon">□</div><span>${escapeHtml(msg)}</span></div>`;
    updateSub2ApiPagerUI();
    refreshSub2ApiSelectionState();
    return;
  }
  DOM.sub2apiAccountList.innerHTML = pageAccounts.map(account => renderSub2ApiAccountItem(account)).join('');
  updateSub2ApiPagerUI();
  refreshSub2ApiSelectionState();
}

function renderSub2ApiAccountItem(account) {
  const accountId = Number(account.id || 0);
  const email = account.email || account.name || `账号 ${accountId}`;
  const status = String(account.status || 'unknown').trim().toLowerCase();
  const isAbnormal = isSub2ApiAbnormalStatus(status);
  const selected = state.ui.selectedSub2ApiAccountIds.has(accountId);
  const statusLabel = {
    error: '异常',
    disabled: '禁用',
    normal: '正常',
    active: '正常',
    ok: '正常',
    unknown: '未知',
  }[status] || status || '未知';
  const statusClass = status === 'disabled' ? 'warn' : (isAbnormal ? 'danger' : 'ok');
  const duplicateBadges = [];
  if (account.is_duplicate) {
    duplicateBadges.push(`<span class="account-flag-badge duplicate">重复 ${account.duplicate_group_size || 0}</span>`);
    if (account.duplicate_keep) duplicateBadges.push('<span class="account-flag-badge keep">保留</span>');
    if (account.duplicate_delete_candidate) duplicateBadges.push('<span class="account-flag-badge delete">候删</span>');
  }
  return `
    <div class="token-item sub2api-account-item${selected ? ' selected' : ''}" id="sub2api-account-${accountId}">
      <label class="account-check-wrap">
        <input type="checkbox" class="sub2api-account-check" data-account-id="${accountId}" ${selected ? 'checked' : ''} />
      </label>
      <div class="token-info">
        <div class="token-email" title="${escapeHtml(email)}">
          <span class="token-email-text">${escapeHtml(email)}</span>
          <span class="account-status-badge ${statusClass}">${escapeHtml(statusLabel)}</span>
          ${duplicateBadges.join('')}
        </div>
        <div class="token-meta">ID: ${accountId} · 更新时间: ${escapeHtml(formatTime(account.updated_at))}</div>
      </div>
      <div class="token-actions">
        <button class="btn btn-ghost btn-sm sub2api-account-probe-btn" data-account-id="${accountId}">测活</button>
        <button class="btn btn-danger btn-sm sub2api-account-delete-btn" data-account-id="${accountId}" data-email="${encodeURIComponent(email)}">删除</button>
      </div>
    </div>`;
}

function updateHeaderLocalTokens(tokens = state.ui.tokens || []) {
  const allTokens = Array.isArray(tokens) ? tokens : [];
  const total = allTokens.length;
  const now = Date.now();
  const validCount = allTokens.filter((token) => {
    const timeStr = token && token.expired;
    if (!timeStr) return true;
    const timestamp = new Date(timeStr).getTime();
    return !Number.isNaN(timestamp) ? timestamp > now : true;
  }).length;
  const fillPct = total > 0 ? Math.round((validCount / total) * 100) : 0;
  const stateName = total === 0 ? 'idle' : (fillPct >= 85 ? 'ok' : fillPct >= 50 ? 'warn' : 'danger');

  if (DOM.headerLocalTokenLabel) DOM.headerLocalTokenLabel.textContent = `${validCount} / ${total}`;
  if (DOM.headerLocalTokenDelta) DOM.headerLocalTokenDelta.textContent = `${fillPct}%`;
  if (DOM.headerLocalTokenBar) {
    DOM.headerLocalTokenBar.style.width = `${Math.min(100, Math.max(fillPct, 0))}%`;
    DOM.headerLocalTokenBar.className = `pool-chip-fill ${stateName === 'idle' ? '' : stateName}`.trim();
  }
  setHeaderChipStatus(DOM.headerLocalTokenChip, stateName);
  if (DOM.headerLocalTokenDelta) {
    DOM.headerLocalTokenDelta.className = `pool-chip-delta ${stateName === 'idle' ? '' : stateName}`.trim();
  }
}

function refreshSub2ApiSelectionState() {
  const visibleAccounts = state.ui.sub2apiAccounts || [];
  const visibleIds = visibleAccounts
    .map(item => item.id)
    .filter(id => Number.isInteger(id) && id > 0);
  const selectedVisible = visibleIds.filter(id => state.ui.selectedSub2ApiAccountIds.has(id)).length;
  const selectedTotal = Array.from(state.ui.selectedSub2ApiAccountIds).length;

  if (DOM.sub2apiAccountSelection) {
    DOM.sub2apiAccountSelection.textContent = `已选 ${selectedTotal} 个，当前页 ${visibleIds.length} 个`;
  }
  if (DOM.sub2apiAccountSelectAll) {
    const allSelected = visibleIds.length > 0 && selectedVisible === visibleIds.length;
    DOM.sub2apiAccountSelectAll.checked = allSelected;
    DOM.sub2apiAccountSelectAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleIds.length;
  }
}

function toggleSelectAllSub2ApiAccounts() {
  const visibleAccounts = state.ui.sub2apiAccounts || [];
  const shouldSelect = !!(DOM.sub2apiAccountSelectAll && DOM.sub2apiAccountSelectAll.checked);
  visibleAccounts.forEach((account) => {
    const accountId = Number(account.id || 0);
    if (!Number.isInteger(accountId) || accountId <= 0) return;
    if (shouldSelect) state.ui.selectedSub2ApiAccountIds.add(accountId);
    else state.ui.selectedSub2ApiAccountIds.delete(accountId);
  });
  renderSub2ApiAccountList();
}

function getSelectedSub2ApiAccountIds() {
  return Array.from(state.ui.selectedSub2ApiAccountIds)
    .filter(id => Number.isInteger(id) && id > 0)
    .sort((a, b) => a - b);
}

function setSub2ApiAccountBusy(busy) {
  state.ui.sub2apiAccountActionBusy = busy;
  [
    DOM.sub2apiAccountApplyBtn,
    DOM.sub2apiAccountResetBtn,
    DOM.sub2apiAccountProbeBtn,
    DOM.sub2apiAccountExceptionBtn,
    DOM.sub2apiDuplicateScanBtn,
    DOM.sub2apiDuplicateCleanBtn,
    DOM.sub2apiAccountDeleteBtn,
    DOM.sub2apiAccountPrevBtn,
    DOM.sub2apiAccountNextBtn,
  ].forEach((btn) => {
    if (btn) btn.disabled = busy;
  });
  if (DOM.sub2apiAccountSelectAll) DOM.sub2apiAccountSelectAll.disabled = busy;
  if (DOM.sub2apiAccountPageSize) DOM.sub2apiAccountPageSize.disabled = busy;
  if (!busy) updateSub2ApiPagerUI();
}

async function runSub2ApiAccountProbe(accountIds, label = '选中账号') {
  if (state.ui.sub2apiAccountActionBusy) return;
  const ids = (accountIds || []).filter(id => Number.isInteger(id) && id > 0);
  if (!ids.length) {
    showToast('请先选择至少一个账号', 'error');
    return;
  }

  setSub2ApiAccountBusy(true);
  if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = `正在测活 ${ids.length} 个账号...`;
  try {
    const res = await fetch('/api/sub2api/accounts/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_ids: ids, timeout: 30 }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || '账号测活失败');
    const msg = `${label}: 刷新成功 ${data.refreshed_ok || 0}, 恢复 ${data.recovered || 0}, 仍异常 ${data.still_abnormal || 0}`;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'success');
    await loadSub2ApiAccounts({ silent: true });
    pollSub2ApiPoolStatus();
  } catch (e) {
    const msg = '账号测活失败: ' + e.message;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'error');
  } finally {
    setSub2ApiAccountBusy(false);
  }
}

async function triggerSelectedSub2ApiProbe() {
  await runSub2ApiAccountProbe(getSelectedSub2ApiAccountIds());
}

async function runSub2ApiExceptionHandling(accountIds = []) {
  if (state.ui.sub2apiAccountActionBusy) return;
  const ids = (accountIds || []).filter(id => Number.isInteger(id) && id > 0);

  setSub2ApiAccountBusy(true);
  if (DOM.sub2apiAccountActionStatus) {
    DOM.sub2apiAccountActionStatus.textContent = ids.length
      ? `正在处理 ${ids.length} 个异常账号...`
      : '正在处理整池异常账号...';
  }
  try {
    const res = await fetch('/api/sub2api/accounts/handle-exception', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_ids: ids, timeout: 30, delete_unresolved: true }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || '异常账号处理失败');
    const msg = `异常处理完成: 目标 ${data.targeted || 0}, 恢复 ${data.recovered || 0}, 删除 ${data.deleted_ok || 0}, 失败 ${data.deleted_fail || 0}`;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'success');
    await loadSub2ApiAccounts({ silent: true });
    pollSub2ApiPoolStatus();
  } catch (e) {
    const msg = '异常账号处理失败: ' + e.message;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'error');
  } finally {
    setSub2ApiAccountBusy(false);
  }
}

async function triggerSub2ApiExceptionHandling() {
  const ids = getSelectedSub2ApiAccountIds();
  if (ids.length) {
    if (!confirm(`确认处理 ${ids.length} 个已选账号？系统会先测活，仍异常的账号会被删除。`)) return;
    await runSub2ApiExceptionHandling(ids);
    return;
  }
  if (!confirm('未选择账号，将处理整个 Sub2Api 池中的异常账号。是否继续？')) return;
  await runSub2ApiExceptionHandling([]);
}

async function runSub2ApiAccountDelete(accountIds, label = '选中账号', requireConfirm = true) {
  if (state.ui.sub2apiAccountActionBusy) return;
  const ids = (accountIds || []).filter(id => Number.isInteger(id) && id > 0);
  if (!ids.length) {
    showToast('请先选择至少一个账号', 'error');
    return;
  }
  if (requireConfirm && !confirm(`确认删除 ${label}（共 ${ids.length} 个）？`)) return;

  setSub2ApiAccountBusy(true);
  if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = `正在删除 ${ids.length} 个账号...`;
  try {
    const res = await fetch('/api/sub2api/accounts/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_ids: ids, timeout: 20 }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || '批量删除失败');
    ids.forEach(id => state.ui.selectedSub2ApiAccountIds.delete(id));
    const msg = `批量删除完成: 成功 ${data.deleted_ok || 0}, 失败 ${data.deleted_fail || 0}`;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'success');
    await loadSub2ApiAccounts({ silent: true });
    pollSub2ApiPoolStatus();
  } catch (e) {
    const msg = '批量删除失败: ' + e.message;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'error');
  } finally {
    setSub2ApiAccountBusy(false);
  }
}

async function triggerSelectedSub2ApiDelete() {
  await runSub2ApiAccountDelete(getSelectedSub2ApiAccountIds());
}

async function previewSub2ApiDuplicates() {
  if (state.ui.sub2apiAccountActionBusy) return;
  setSub2ApiAccountBusy(true);
  if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = '正在检测重复账号...';
  try {
    const res = await fetch('/api/sub2api/pool/dedupe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dry_run: true, timeout: 20 }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || '重复账号检测失败');
    const msg = `重复预检完成: 重复组 ${data.duplicate_groups || 0}, 重复账号 ${data.duplicate_accounts || 0}, 可删 ${data.to_delete || 0}`;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'success');
    await loadSub2ApiAccounts({ silent: true });
  } catch (e) {
    const msg = '重复账号检测失败: ' + e.message;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'error');
  } finally {
    setSub2ApiAccountBusy(false);
  }
}

async function cleanupSub2ApiDuplicates() {
  if (state.ui.sub2apiAccountActionBusy) return;
  if (!confirm('确认清理 Sub2Api 中的重复账号？系统会保留每组中更新时间最新的账号。')) return;
  setSub2ApiAccountBusy(true);
  if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = '正在清理重复账号...';
  try {
    const res = await fetch('/api/sub2api/pool/dedupe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dry_run: false, timeout: 20 }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || '重复账号清理失败');
    const msg = `重复清理完成: 删除成功 ${data.deleted_ok || 0}, 删除失败 ${data.deleted_fail || 0}`;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'success');
    await loadSub2ApiAccounts({ silent: true });
    pollSub2ApiPoolStatus();
  } catch (e) {
    const msg = '重复账号清理失败: ' + e.message;
    if (DOM.sub2apiAccountActionStatus) DOM.sub2apiAccountActionStatus.textContent = msg;
    showToast(msg, 'error');
  } finally {
    setSub2ApiAccountBusy(false);
  }
}

// ==========================================
// Sub2Api 同步配置
// ==========================================
async function loadSyncConfig() {
  if (DOM.syncStatus) DOM.syncStatus.textContent = '';
  try {
    const res = await fetch('/api/sync-config');
    const cfg = await res.json();
    DOM.sub2apiBaseUrl.value = cfg.base_url || '';
    if (cfg.email) DOM.sub2apiEmail.value = cfg.email;
    DOM.autoSyncCheck.checked = !!cfg.auto_sync;
    if (DOM.uploadMode) DOM.uploadMode.value = cfg.upload_mode || 'snapshot';
    if (DOM.uploadModeStatus) DOM.uploadModeStatus.textContent = '';
    if (DOM.sub2apiMinCandidates) DOM.sub2apiMinCandidates.value = cfg.sub2api_min_candidates || 200;
    if (DOM.sub2apiInterval) DOM.sub2apiInterval.value = cfg.sub2api_maintain_interval_minutes || 30;
    if (DOM.sub2apiAutoMaintain) DOM.sub2apiAutoMaintain.checked = !!cfg.sub2api_auto_maintain;
    const maintainActions = cfg.sub2api_maintain_actions || {};
    if (DOM.sub2apiMaintainRefreshAbnormal) {
      DOM.sub2apiMaintainRefreshAbnormal.checked = maintainActions.refresh_abnormal_accounts !== false;
    }
    if (DOM.sub2apiMaintainDeleteAbnormal) {
      DOM.sub2apiMaintainDeleteAbnormal.checked = maintainActions.delete_abnormal_accounts !== false;
    }
    if (DOM.sub2apiMaintainDedupe) {
      DOM.sub2apiMaintainDedupe.checked = maintainActions.dedupe_duplicate_accounts !== false;
    }
    if (cfg.proxy && DOM.proxyInput) DOM.proxyInput.value = cfg.proxy;
    if (DOM.syncStatus) DOM.syncStatus.textContent = '';
  } catch { }
}

async function loadProxyPoolConfig() {
  try {
    const res = await fetch('/api/proxy-pool/config');
    const cfg = await res.json();
    if (DOM.proxyPoolEnabled) DOM.proxyPoolEnabled.checked = !!cfg.proxy_pool_enabled;
    if (DOM.proxyPoolApiUrl) DOM.proxyPoolApiUrl.value = cfg.proxy_pool_api_url || 'https://zenproxy.top/api/fetch';
    if (DOM.proxyPoolAuthMode) DOM.proxyPoolAuthMode.value = cfg.proxy_pool_auth_mode || 'query';
    if (DOM.proxyPoolCount) DOM.proxyPoolCount.value = cfg.proxy_pool_count || 1;
    if (DOM.proxyPoolCountry) DOM.proxyPoolCountry.value = (cfg.proxy_pool_country || 'US').toUpperCase();
    if (DOM.proxyPoolApiKey) {
      DOM.proxyPoolApiKey.value = '';
      DOM.proxyPoolApiKey.placeholder = cfg.proxy_pool_api_key_preview
        ? `已保存: ${cfg.proxy_pool_api_key_preview}`
        : '请输入代理池 API Key';
    }
    if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = '';
  } catch { }
}

async function saveProxyPoolConfig() {
  if (!DOM.proxyPoolSaveBtn) return;
  const payload = {
    proxy_pool_enabled: DOM.proxyPoolEnabled ? DOM.proxyPoolEnabled.checked : true,
    proxy_pool_api_url: DOM.proxyPoolApiUrl ? DOM.proxyPoolApiUrl.value.trim() : 'https://zenproxy.top/api/fetch',
    proxy_pool_auth_mode: DOM.proxyPoolAuthMode ? DOM.proxyPoolAuthMode.value : 'query',
    proxy_pool_api_key: DOM.proxyPoolApiKey ? DOM.proxyPoolApiKey.value.trim() : '',
    proxy_pool_count: DOM.proxyPoolCount ? (parseInt(DOM.proxyPoolCount.value, 10) || 1) : 1,
    proxy_pool_country: DOM.proxyPoolCountry ? DOM.proxyPoolCountry.value.trim().toUpperCase() : 'US',
  };
  if (!payload.proxy_pool_api_url) {
    showToast('请填写代理池 API 地址', 'error');
    return;
  }
  if (payload.proxy_pool_count < 1) payload.proxy_pool_count = 1;
  if (!payload.proxy_pool_country) payload.proxy_pool_country = 'US';

  DOM.proxyPoolSaveBtn.disabled = true;
  const oldText = DOM.proxyPoolSaveBtn.textContent;
  DOM.proxyPoolSaveBtn.textContent = '保存中...';
  if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = '正在保存代理池配置...';
  try {
    const res = await fetch('/api/proxy-pool/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.detail || '保存失败';
      if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = msg;
      showToast(msg, 'error');
      return;
    }
    if (DOM.proxyPoolApiKey && payload.proxy_pool_api_key) {
      DOM.proxyPoolApiKey.value = '';
      DOM.proxyPoolApiKey.placeholder = `已保存: ${payload.proxy_pool_api_key.slice(0, 8)}...`;
    }
    const msg = '代理池配置已保存';
    if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = msg;
    showToast(msg, 'success');
  } catch (e) {
    const msg = '请求失败: ' + e.message;
    if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = msg;
    showToast(msg, 'error');
  } finally {
    DOM.proxyPoolSaveBtn.disabled = false;
    DOM.proxyPoolSaveBtn.textContent = oldText || '保存代理池配置';
  }
}

async function saveSyncConfig() {
  const base_url = DOM.sub2apiBaseUrl.value.trim();
  const email = DOM.sub2apiEmail.value.trim();
  const password = DOM.sub2apiPassword.value.trim();
  const auto_sync = !!DOM.autoSyncCheck.checked;
  const upload_mode = DOM.uploadMode ? DOM.uploadMode.value : 'snapshot';
  const sub2api_min_candidates = parseInt(DOM.sub2apiMinCandidates.value) || 200;
  const sub2api_auto_maintain = DOM.sub2apiAutoMaintain.checked;
  const sub2api_maintain_interval_minutes = parseInt(DOM.sub2apiInterval.value) || 30;
  const sub2api_maintain_actions = getSub2ApiMaintainActionsFromForm();

  if (!base_url) { showToast('请填写平台地址', 'error'); return; }
  if (!email) { showToast('请填写邮箱', 'error'); return; }

  DOM.saveSyncConfigBtn.disabled = true;
  DOM.saveSyncConfigBtn.textContent = '验证中...';
  DOM.syncStatus.textContent = '正在验证账号密码...';
  try {
    const res = await fetch('/api/sync-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        base_url, email, password, account_name: 'AutoReg', auto_sync,
        upload_mode,
        sub2api_min_candidates, sub2api_auto_maintain, sub2api_maintain_interval_minutes,
        sub2api_maintain_actions,
      }),
    });
    const data = await res.json();
    if (res.ok) {
      showToast('验证通过，配置已保存', 'success');
      DOM.syncStatus.textContent = '验证通过，配置已保存';
      pollSub2ApiPoolStatus();
      loadSub2ApiAccounts();
    } else {
      showToast(data.detail || '验证失败', 'error');
      DOM.syncStatus.textContent = data.detail || '验证失败';
    }
  } catch (e) {
    showToast('请求失败: ' + e.message, 'error');
    DOM.syncStatus.textContent = '请求失败: ' + e.message;
  } finally {
    DOM.saveSyncConfigBtn.disabled = false;
    DOM.saveSyncConfigBtn.textContent = '保存';
  }
}

async function saveUploadMode() {
  const upload_mode = DOM.uploadMode ? DOM.uploadMode.value : 'snapshot';
  if (!DOM.uploadModeSaveBtn) return;
  DOM.uploadModeSaveBtn.disabled = true;
  const oldText = DOM.uploadModeSaveBtn.textContent;
  DOM.uploadModeSaveBtn.textContent = '保存中...';
  if (DOM.uploadModeStatus) DOM.uploadModeStatus.textContent = '正在保存策略...';
  try {
    const res = await fetch('/api/upload-mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ upload_mode }),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.detail || '保存失败';
      showToast(msg, 'error');
      if (DOM.uploadModeStatus) DOM.uploadModeStatus.textContent = msg;
      return;
    }
    const label = upload_mode === 'decoupled' ? '双平台同传（单账号双上传）' : '串行补平台（先CPA后Sub2Api）';
    showToast('上传策略已保存：' + label, 'success');
    if (DOM.uploadModeStatus) DOM.uploadModeStatus.textContent = '已保存：' + label;
  } catch (e) {
    showToast('请求失败: ' + e.message, 'error');
    if (DOM.uploadModeStatus) DOM.uploadModeStatus.textContent = '请求失败: ' + e.message;
  } finally {
    DOM.uploadModeSaveBtn.disabled = false;
    DOM.uploadModeSaveBtn.textContent = oldText || '保存策略';
  }
}

async function batchSync() {
  const btn = DOM.poolPwSyncBtn;
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = '导入中...';
  showToast('批量导入开始', 'info');
  try {
    const res = await fetch('/api/sync-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filenames: [] }),
    });
    const data = await res.json();
    if (!res.ok) { showToast(data.detail || '导入失败', 'error'); return; }
    const msg = `导入完成：共 ${data.total}，成功 ${data.ok}，失败 ${data.fail}`;
    showToast(msg, data.fail > 0 ? 'info' : 'success');
  } catch (e) {
    showToast('导入失败: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '批量导入';
  }
}

// ==========================================
// CPA 配置
// ==========================================
async function loadPoolConfig() {
  try {
    const res = await fetch('/api/pool/config');
    const cfg = await res.json();
    DOM.cpaBaseUrl.value = cfg.cpa_base_url || '';
    DOM.cpaMinCandidates.value = cfg.min_candidates || 800;
    DOM.cpaUsedPercent.value = cfg.used_percent_threshold || 95;
    DOM.cpaAutoMaintain.checked = !!cfg.auto_maintain;
    DOM.cpaInterval.value = cfg.maintain_interval_minutes || 30;
    if (DOM.cpaStatus) DOM.cpaStatus.textContent = '';
  } catch { }
}

async function savePoolConfig() {
  const payload = {
    cpa_base_url: DOM.cpaBaseUrl.value.trim(),
    cpa_token: DOM.cpaToken.value.trim(),
    min_candidates: parseInt(DOM.cpaMinCandidates.value) || 800,
    used_percent_threshold: parseInt(DOM.cpaUsedPercent.value) || 95,
    auto_maintain: DOM.cpaAutoMaintain.checked,
    maintain_interval_minutes: parseInt(DOM.cpaInterval.value) || 30,
  };
  DOM.cpaSaveBtn.disabled = true;
  try {
    const res = await fetch('/api/pool/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      showToast('CPA 配置已保存', 'success');
      DOM.cpaStatus.textContent = '配置已保存';
      pollPoolStatus();
    } else {
      const data = await res.json();
      showToast(data.detail || '保存失败', 'error');
      DOM.cpaStatus.textContent = data.detail || '保存失败';
    }
  } catch (e) {
    showToast('请求失败: ' + e.message, 'error');
    DOM.cpaStatus.textContent = '请求失败';
  } finally {
    DOM.cpaSaveBtn.disabled = false;
  }
}

async function loadLocalPoolConfig() {
  try {
    const res = await fetch('/api/local-pool/config');
    const cfg = await res.json();
    if (DOM.localMaintainEnabled) DOM.localMaintainEnabled.checked = !!cfg.local_maintain_enabled;
    if (DOM.localMaintainInterval) DOM.localMaintainInterval.value = cfg.local_maintain_interval_minutes || 60;
    if (DOM.localRefreshThreshold) DOM.localRefreshThreshold.value = cfg.local_refresh_threshold_pct || 60;
    if (DOM.localCheckIntervalHours) DOM.localCheckIntervalHours.value = cfg.local_check_interval_hours || 6;
    if (DOM.localMaintainThreadCount) DOM.localMaintainThreadCount.value = cfg.local_maintain_thread_count || 3;
  } catch { }
}

async function loadLocalPoolStatus() {
  try {
    const res = await fetch('/api/local-pool/status');
    const data = await res.json();
    if (DOM.localPoolStats) {
      DOM.localPoolStats.textContent = `cooling ${data.cooling || 0} / reauth ${data.reauth_pending || 0} / 总 ${data.total || 0}`;
    }
    if (DOM.localMaintainStatus && !DOM.localMaintainStatus.textContent) {
      DOM.localMaintainStatus.textContent = data.enabled ? '自动维护已启用' : '自动维护未启用';
    }
  } catch (e) {
    if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = '状态加载失败';
  }
}

async function saveLocalPoolConfig() {
  const payload = {
    local_maintain_enabled: DOM.localMaintainEnabled ? DOM.localMaintainEnabled.checked : false,
    local_maintain_interval_minutes: DOM.localMaintainInterval ? (parseInt(DOM.localMaintainInterval.value) || 60) : 60,
    local_refresh_threshold_pct: DOM.localRefreshThreshold ? (parseFloat(DOM.localRefreshThreshold.value) || 60) : 60,
    local_check_interval_hours: DOM.localCheckIntervalHours ? (parseInt(DOM.localCheckIntervalHours.value) || 6) : 6,
    local_maintain_thread_count: DOM.localMaintainThreadCount ? (parseInt(DOM.localMaintainThreadCount.value, 10) || 3) : 3,
  };
  if (DOM.localMaintainSaveBtn) DOM.localMaintainSaveBtn.disabled = true;
  if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = '保存中...';
  try {
    const res = await fetch('/api/local-pool/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (res.ok) {
      if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = '配置已保存';
      showToast('本地池配置已保存', 'success');
      loadLocalPoolStatus();
    } else {
      if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = data.detail || '保存失败';
      showToast(data.detail || '保存失败', 'error');
    }
  } catch (e) {
    if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = '请求失败';
    showToast('本地池配置保存失败', 'error');
  } finally {
    if (DOM.localMaintainSaveBtn) DOM.localMaintainSaveBtn.disabled = false;
  }
}

async function triggerLocalPoolMaintain() {
  if (DOM.localMaintainBtn) DOM.localMaintainBtn.disabled = true;
  if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = '维护中...';
  try {
    const res = await fetch('/api/local-pool/maintain', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      const msg = `维护完成: 回推 ${data.uploaded || 0}, 等待 ${data.waiting || 0}, 删除 ${data.deleted || 0}`;
      if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = msg;
      showToast(msg, 'success');
      loadLocalPoolStatus();
      loadTokens();
    } else {
      if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = data.detail || '维护失败';
      showToast(data.detail || '维护失败', 'error');
    }
  } catch (e) {
    if (DOM.localMaintainStatus) DOM.localMaintainStatus.textContent = '请求失败';
    showToast('本地池维护请求失败', 'error');
  } finally {
    if (DOM.localMaintainBtn) DOM.localMaintainBtn.disabled = false;
  }
}

async function testCpaConnection() {
  DOM.cpaTestBtn.disabled = true;
  DOM.cpaStatus.textContent = '测试中...';
  try {
    const res = await fetch('/api/pool/check', { method: 'POST' });
    const data = await res.json();
    if (data.ok) {
      DOM.cpaStatus.textContent = data.message || '连接成功';
      showToast('CPA 连接成功', 'success');
    } else {
      DOM.cpaStatus.textContent = data.message || data.detail || '连接失败';
      showToast('CPA 连接失败', 'error');
    }
  } catch (e) {
    DOM.cpaStatus.textContent = '请求失败: ' + e.message;
  } finally {
    DOM.cpaTestBtn.disabled = false;
  }
}

// ==========================================
// 池状态轮询
// ==========================================
async function pollPoolStatus() {
  try {
    const res = await fetch('/api/pool/status');
    const data = await res.json();

    if (!data.configured) {
      if (DOM.poolTotal) DOM.poolTotal.textContent = '--';
      if (DOM.poolCandidates) DOM.poolCandidates.textContent = '--';
      if (DOM.poolError) DOM.poolError.textContent = '--';
      if (DOM.poolThreshold) DOM.poolThreshold.textContent = '--';
      if (DOM.poolPercent) DOM.poolPercent.textContent = '--';
      updateHeaderCpa(null);
      return;
    }

    const candidates = data.candidates || 0;
    const errorCount = data.error_count || 0;
    const threshold = data.threshold || 0;
    const fillPct = threshold > 0 ? Math.round(candidates / threshold * 100) : 100;

    if (DOM.poolTotal) DOM.poolTotal.textContent = data.total || 0;
    if (DOM.poolCandidates) DOM.poolCandidates.textContent = candidates;
    if (DOM.poolError) {
      DOM.poolError.textContent = errorCount;
      DOM.poolError.className = `stat-value ${errorCount > 0 ? 'red' : 'green'}`;
    }
    if (DOM.poolThreshold) DOM.poolThreshold.textContent = threshold;
    if (DOM.poolPercent) {
      DOM.poolPercent.textContent = fillPct + '%';
      DOM.poolPercent.className = `stat-value ${fillPct >= 100 ? 'green' : fillPct >= 80 ? 'yellow' : 'red'}`;
    }

    updateHeaderCpa({ candidates, threshold, fillPct, errorCount });
  } catch { }
}

async function triggerMaintenance() {
  DOM.poolMaintainBtn.disabled = true;
  DOM.poolMaintainBtn.textContent = '维护中...';
  DOM.poolMaintainStatus.textContent = '正在探测并清理无效账号...';
  try {
    const res = await fetch('/api/pool/maintain', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      const msg = `维护完成: 无效 ${data.invalid_count || 0}, 已删除 ${data.deleted_ok || 0}, 失败 ${data.deleted_fail || 0}`;
      DOM.poolMaintainStatus.textContent = msg;
      showToast(msg, 'success');
      pollPoolStatus();
    } else {
      DOM.poolMaintainStatus.textContent = data.detail || '维护失败';
      showToast(data.detail || '维护失败', 'error');
    }
  } catch (e) {
    DOM.poolMaintainStatus.textContent = '请求失败: ' + e.message;
    showToast('维护请求失败', 'error');
  } finally {
    DOM.poolMaintainBtn.disabled = false;
    DOM.poolMaintainBtn.textContent = '维护';
  }
}

// ==========================================
// Sub2Api 池状态轮询
// ==========================================
async function pollSub2ApiPoolStatus() {
  try {
    const res = await fetch('/api/sub2api/pool/status');
    const data = await res.json();

    if (data.configured && data.error) {
      if (DOM.sub2apiPoolMaintainStatus) DOM.sub2apiPoolMaintainStatus.textContent = 'Sub2Api 状态获取失败: ' + data.error;
      updateHeaderSub2Api(null);
      return;
    }

    if (!data.configured) {
      if (DOM.sub2apiPoolTotal) DOM.sub2apiPoolTotal.textContent = '--';
      if (DOM.sub2apiPoolNormal) DOM.sub2apiPoolNormal.textContent = '--';
      if (DOM.sub2apiPoolError) DOM.sub2apiPoolError.textContent = '--';
      if (DOM.sub2apiPoolThreshold) DOM.sub2apiPoolThreshold.textContent = '--';
      if (DOM.sub2apiPoolPercent) DOM.sub2apiPoolPercent.textContent = '--';
      updateHeaderSub2Api(null);
      return;
    }

    const normal = data.candidates || 0;
    const error = data.error_count || 0;
    const total = data.total || 0;
    const threshold = data.threshold || 0;
    // 充足率: 正常账号 / 目标阈值
    const fillPct = threshold > 0 ? Math.round(normal / threshold * 100) : 100;
    // 健康率: 正常账号 / 总账号 (无异常就是 100%)
    const healthPct = total > 0 ? Math.round(normal / total * 100) : 100;

    if (DOM.sub2apiPoolTotal) DOM.sub2apiPoolTotal.textContent = total;
    if (DOM.sub2apiPoolNormal) DOM.sub2apiPoolNormal.textContent = normal;
    if (DOM.sub2apiPoolError) {
      DOM.sub2apiPoolError.textContent = error;
      DOM.sub2apiPoolError.className = `stat-value ${error > 0 ? 'red' : 'green'}`;
    }
    if (DOM.sub2apiPoolThreshold) DOM.sub2apiPoolThreshold.textContent = threshold;
    if (DOM.sub2apiPoolPercent) {
      DOM.sub2apiPoolPercent.textContent = fillPct + '%';
      DOM.sub2apiPoolPercent.className = `stat-value ${fillPct >= 100 ? 'green' : fillPct >= 80 ? 'yellow' : 'red'}`;
    }

    updateHeaderSub2Api({ normal, threshold, fillPct, error });
  } catch { }
}

function updateHeaderSub2Api(data) {
  if (!data) {
    if (DOM.headerSub2apiLabel) DOM.headerSub2apiLabel.textContent = '-- / --';
    if (DOM.headerSub2apiDelta) DOM.headerSub2apiDelta.textContent = '--';
    if (DOM.headerSub2apiBar) DOM.headerSub2apiBar.style.width = '0%';
    setHeaderChipStatus(DOM.headerSub2apiChip, 'idle');
    if (DOM.headerSub2apiBar) DOM.headerSub2apiBar.className = 'pool-chip-fill';
    if (DOM.headerSub2apiDelta) DOM.headerSub2apiDelta.className = 'pool-chip-delta';
    return;
  }
  const { normal, threshold, fillPct, error: errorCount } = data;
  const state = _headerPoolState(fillPct, errorCount);
  if (DOM.headerSub2apiLabel) DOM.headerSub2apiLabel.textContent = `${normal} / ${threshold}`;
  if (DOM.headerSub2apiDelta) DOM.headerSub2apiDelta.textContent = _headerPoolDelta(fillPct);
  if (DOM.headerSub2apiBar) {
    DOM.headerSub2apiBar.style.width = Math.min(100, fillPct) + '%';
    DOM.headerSub2apiBar.className = `pool-chip-fill ${state}`;
  }
  setHeaderChipStatus(DOM.headerSub2apiChip, state);
  if (DOM.headerSub2apiDelta) DOM.headerSub2apiDelta.className = `pool-chip-delta ${state}`;
}

function updateHeaderCpa(data) {
  if (!data) {
    if (DOM.headerCpaLabel) DOM.headerCpaLabel.textContent = '-- / --';
    if (DOM.headerCpaDelta) DOM.headerCpaDelta.textContent = '--';
    if (DOM.headerCpaBar) DOM.headerCpaBar.style.width = '0%';
    setHeaderChipStatus(DOM.headerCpaChip, 'idle');
    if (DOM.headerCpaBar) DOM.headerCpaBar.className = 'pool-chip-fill';
    if (DOM.headerCpaDelta) DOM.headerCpaDelta.className = 'pool-chip-delta';
    return;
  }
  const { candidates, threshold, fillPct, errorCount } = data;
  const state = _headerPoolState(fillPct, errorCount);
  if (DOM.headerCpaLabel) DOM.headerCpaLabel.textContent = `${candidates} / ${threshold}`;
  if (DOM.headerCpaDelta) DOM.headerCpaDelta.textContent = _headerPoolDelta(fillPct);
  if (DOM.headerCpaBar) {
    DOM.headerCpaBar.style.width = Math.min(100, fillPct) + '%';
    DOM.headerCpaBar.className = `pool-chip-fill ${state}`;
  }
  setHeaderChipStatus(DOM.headerCpaChip, state);
  if (DOM.headerCpaDelta) DOM.headerCpaDelta.className = `pool-chip-delta ${state}`;
}

function setHeaderChipStatus(chip, state) {
  if (!chip) return;
  chip.classList.remove('status-idle', 'status-warn', 'status-danger', 'status-ok', 'status-over');
  chip.classList.add(`status-${state}`);
}

function _headerPoolState(fillPct, errorCount) {
  if (errorCount > 0) return 'danger';
  if (fillPct > 110) return 'over';
  if (fillPct >= 100) return 'ok';
  if (fillPct >= 80) return 'warn';
  return 'danger';
}

function _headerPoolDelta(fillPct) {
  if (!Number.isFinite(fillPct)) return '--';
  const delta = Math.round(fillPct - 100);
  if (delta === 0) return '0%';
  return `${delta > 0 ? '+' : ''}${delta}%`;
}

async function triggerSub2ApiMaintenance() {
  const actionsText = describeSub2ApiMaintainActions();
  DOM.sub2apiPoolMaintainBtn.disabled = true;
  DOM.sub2apiPoolMaintainBtn.textContent = '维护中...';
  DOM.sub2apiPoolMaintainStatus.textContent = `正在维护（${actionsText}）...`;
  try {
    const res = await fetch('/api/sub2api/pool/maintain', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      const sec = Math.max(0, Number(data.duration_ms || 0) / 1000).toFixed(2);
      const msg = `维护完成(${actionsText}): 异常 ${data.error_count || 0}, 刷新恢复 ${data.refreshed || 0}, 重复组 ${data.duplicate_groups || 0}, 删除 ${data.deleted_ok || 0}, 失败 ${data.deleted_fail || 0}, ${sec}s`;
      DOM.sub2apiPoolMaintainStatus.textContent = msg;
      showToast(msg, 'success');
      pollSub2ApiPoolStatus();
      loadSub2ApiAccounts({ silent: true });
    } else {
      DOM.sub2apiPoolMaintainStatus.textContent = data.detail || '维护失败';
      showToast(data.detail || '维护失败', 'error');
    }
  } catch (e) {
    DOM.sub2apiPoolMaintainStatus.textContent = '请求失败: ' + e.message;
    showToast('Sub2Api 维护请求失败', 'error');
  } finally {
    DOM.sub2apiPoolMaintainBtn.disabled = false;
    DOM.sub2apiPoolMaintainBtn.textContent = '维护';
  }
}

async function testProxyPoolFetch() {
  if (!DOM.proxyPoolTestBtn) return;
  DOM.proxyPoolTestBtn.disabled = true;
  const oldText = DOM.proxyPoolTestBtn.textContent;
  if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = '正在测试代理池取号...';
  DOM.proxyPoolTestBtn.textContent = '测试取号中...';
  try {
    const payload = {
      enabled: DOM.proxyPoolEnabled ? DOM.proxyPoolEnabled.checked : true,
      api_url: DOM.proxyPoolApiUrl ? DOM.proxyPoolApiUrl.value.trim() : 'https://zenproxy.top/api/fetch',
      auth_mode: DOM.proxyPoolAuthMode ? DOM.proxyPoolAuthMode.value : 'query',
      api_key: DOM.proxyPoolApiKey ? DOM.proxyPoolApiKey.value.trim() : '',
      count: DOM.proxyPoolCount ? (parseInt(DOM.proxyPoolCount.value, 10) || 1) : 1,
      country: DOM.proxyPoolCountry ? DOM.proxyPoolCountry.value.trim().toUpperCase() : 'US',
    };
    const res = await fetch('/api/proxy-pool/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      const msg = data.error || data.detail || '代理池取号失败';
      if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = msg;
      showToast(msg, 'error');
      return;
    }
    const locText = data.loc ? ` loc=${data.loc}` : '';
    const supportText = data.supported === null || data.supported === undefined
      ? ''
      : (data.supported ? ' 可用' : ' 不可用(CN/HK)');
    const traceWarn = data.trace_error ? `；trace失败: ${data.trace_error}` : '';
    const msg = `取号成功: ${data.proxy}${locText}${supportText}${traceWarn}`;
    if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = msg;
    showToast('代理池取号成功', 'success');
  } catch (e) {
    const msg = '测试请求失败: ' + e.message;
    if (DOM.proxyPoolStatus) DOM.proxyPoolStatus.textContent = msg;
    showToast(msg, 'error');
  } finally {
    DOM.proxyPoolTestBtn.disabled = false;
    if (DOM.syncStatus) DOM.syncStatus.textContent = '';
    DOM.proxyPoolTestBtn.textContent = oldText || '测试代理池取号';
  }
}

async function testSub2ApiPoolConnection() {
  DOM.sub2apiTestPoolBtn.disabled = true;
  DOM.syncStatus.textContent = '测试连接中...';
  try {
    const res = await fetch('/api/sub2api/pool/check', { method: 'POST' });
    const data = await res.json();
    if (data.ok) {
      DOM.syncStatus.textContent = data.message || '连接成功';
      showToast('Sub2Api 池连接成功', 'success');
    } else {
      DOM.syncStatus.textContent = data.message || data.detail || '连接失败';
      showToast('Sub2Api 池连接失败', 'error');
    }
  } catch (e) {
    DOM.syncStatus.textContent = '请求失败: ' + e.message;
  } finally {
    DOM.sub2apiTestPoolBtn.disabled = false;
  }
}

// ==========================================
// 邮箱配置（多选）
// ==========================================

function initMailCheckboxes() {
  document.querySelectorAll('.mail-provider-check').forEach(cb => {
    cb.setAttribute('aria-expanded', cb.checked);
    cb.addEventListener('change', () => {
      const item = cb.closest('.provider-item');
      const config = item.querySelector('.provider-config');
      if (config) config.style.display = cb.checked ? 'block' : 'none';
      cb.setAttribute('aria-expanded', cb.checked);
    });
  });
}

async function loadMailConfig() {
  try {
    const res = await fetch('/api/mail/config');
    const data = await res.json();
    const providers = data.mail_providers || [data.mail_provider || 'mailtm'];
    const configs = data.mail_provider_configs || {};
    const strategy = data.mail_strategy || 'round_robin';

    // 设置 checkboxes
    document.querySelectorAll('.mail-provider-check').forEach(cb => {
      const name = cb.value;
      cb.checked = providers.includes(name);
      const item = cb.closest('.provider-item');
      const configDiv = item.querySelector('.provider-config');
      if (configDiv) configDiv.style.display = cb.checked ? 'block' : 'none';

      // 填充 per-provider 配置
      const pcfg = configs[name] || {};
      item.querySelectorAll('[data-key]').forEach(input => {
        const key = input.dataset.key;
        const previewKey = key + '_preview';
        if (pcfg[key]) input.value = pcfg[key];
        else if (pcfg[previewKey]) input.placeholder = pcfg[previewKey];
      });
    });

    // 兼容旧格式
    if (!data.mail_providers && data.mail_config) {
      const mc = data.mail_config;
      const activeProvider = data.mail_provider || 'mailtm';
      const item = document.querySelector(`.provider-item[data-provider="${activeProvider}"]`);
      if (item) {
        const apiBaseInput = item.querySelector('[data-key="api_base"]');
        if (apiBaseInput && mc.api_base) apiBaseInput.value = mc.api_base;
      }
    }

    if (DOM.mailStrategySelect) DOM.mailStrategySelect.value = strategy;

    // 加载 use_register_version 配置
    if (DOM.registerVersionSelect) {
      const version = data.use_register_version || "v1";
      DOM.registerVersionSelect.value = version;
    }
  } catch { }
}

async function saveMailConfig() {
  const checkedProviders = [];
  const providerConfigs = {};

  document.querySelectorAll('.mail-provider-check').forEach(cb => {
    const name = cb.value;
    if (cb.checked) {
      checkedProviders.push(name);
      const item = cb.closest('.provider-item');
      const cfg = {};
      item.querySelectorAll('[data-key]').forEach(input => {
        cfg[input.dataset.key] = input.value.trim();
      });
      providerConfigs[name] = cfg;
    }
  });

  if (checkedProviders.length === 0) {
    showToast('请至少选择一个邮箱提供商', 'error');
    return false;
  }

  const strategy = DOM.mailStrategySelect ? DOM.mailStrategySelect.value : 'round_robin';
  DOM.mailSaveBtn.disabled = true;
  try {
    const res = await fetch('/api/mail/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mail_provider: checkedProviders[0],
        mail_config: providerConfigs[checkedProviders[0]] || {},
        mail_providers: checkedProviders,
        mail_provider_configs: providerConfigs,
        mail_strategy: strategy,
      }),
    });
    if (res.ok) {
      showToast('邮箱配置已保存', 'success');
      DOM.mailStatus.textContent = '配置已保存';
      return true;
    } else {
      const data = await res.json();
      DOM.mailStatus.textContent = data.detail || '保存失败';
      showToast(DOM.mailStatus.textContent, 'error');
      return false;
    }
  } catch (e) {
    DOM.mailStatus.textContent = '请求失败: ' + e.message;
    showToast(DOM.mailStatus.textContent, 'error');
    return false;
  } finally {
    DOM.mailSaveBtn.disabled = false;
  }
}

async function testMailConnection() {
  DOM.mailTestBtn.disabled = true;
  DOM.mailStatus.textContent = '测试中...';
  try {
    const saved = await saveMailConfig();
    if (!saved) return;
    const res = await fetch('/api/mail/test', { method: 'POST' });
    const data = await res.json();
    if (data.results) {
      const msgs = data.results.map(r => `${r.provider}: ${r.ok ? 'OK' : r.message}`);
      DOM.mailStatus.textContent = msgs.join(' | ');
    } else {
      DOM.mailStatus.textContent = data.message || (data.ok ? '连接成功' : '连接失败');
    }
    showToast(data.ok ? '邮箱测试通过' : '邮箱测试失败', data.ok ? 'success' : 'error');
  } catch (e) {
    DOM.mailStatus.textContent = '请求失败: ' + e.message;
  } finally {
    DOM.mailTestBtn.disabled = false;
  }
}

async function saveRegisterVersion() {
  if (!DOM.registerVersionSaveBtn) return;
  DOM.registerVersionSaveBtn.disabled = true;
  DOM.registerVersionStatus.textContent = '保存中...';
  try {
    const version = DOM.registerVersionSelect.value;
    const res = await fetch('/api/mail/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ use_register_version: version }),
    });
    if (res.ok) {
      showToast(`已切换到 ${version.toUpperCase()} 注册流程（无需重启）`, 'success');
      DOM.registerVersionStatus.textContent = '已保存';
    } else {
      const data = await res.json();
      DOM.registerVersionStatus.textContent = data.detail || '保存失败';
      showToast(DOM.registerVersionStatus.textContent, 'error');
    }
  } catch (e) {
    DOM.registerVersionStatus.textContent = '请求失败: ' + e.message;
    showToast(DOM.registerVersionStatus.textContent, 'error');
  } finally {
    DOM.registerVersionSaveBtn.disabled = false;
  }
}

// ==========================================
// Toast 通知 — 带图标和退出动画
// ==========================================
const TOAST_ICONS = {
  success: '&#10003;',
  error: '&#10007;',
  info: '&#8505;',
};

const THEME_STORAGE_KEY = 'oai_registrar_theme_v1';

function initThemeSwitch() {
  const btn = DOM.themeToggleBtn;
  if (!btn) return;

  let saved = 'dark';
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY);
    if (value === 'light' || value === 'dark') saved = value;
  } catch { }

  applyTheme(saved);

  btn.addEventListener('click', () => {
    const isLight = document.body.classList.contains('theme-light');
    const nextTheme = isLight ? 'dark' : 'light';
    applyTheme(nextTheme);
    try { localStorage.setItem(THEME_STORAGE_KEY, nextTheme); } catch { }
  });
}

function applyTheme(theme) {
  const isLight = theme === 'light';
  document.body.classList.toggle('theme-light', isLight);
  updateThemeToggleLabel(isLight);
}

function updateThemeToggleLabel(isLight) {
  const btn = DOM.themeToggleBtn;
  if (!btn) return;
  const currentLabel = isLight ? '\u660e\u4eae' : '\u9ed1\u6697';
  const nextLabel = isLight ? '\u9ed1\u6697' : '\u660e\u4eae';
  const toggleLabel = btn.querySelector('.theme-toggle-label');
  if (toggleLabel) toggleLabel.textContent = currentLabel;
  btn.setAttribute('aria-label', `\u5207\u6362\u5230${nextLabel}\u4e3b\u9898`);
  btn.setAttribute('title', `\u5207\u6362\u5230${nextLabel}\u4e3b\u9898`);
}

function showToast(msg, type = 'info') {
  const container = $('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  const iconHtml = TOAST_ICONS[type] || TOAST_ICONS.info;
  toast.innerHTML = `<span class="toast-icon">${iconHtml}</span><span>${escapeHtml(msg)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'toast-out .25s var(--ease-spring) forwards';
    toast.addEventListener('animationend', () => toast.remove());
  }, 3200);
}

// ==========================================
// 工具函数
// ==========================================
function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function cssEscape(str) {
  return str.replace(/[^a-zA-Z0-9_-]/g, '_');
}

// ==========================================
// 拖拽调整栏宽度 + localStorage 持久化
// ==========================================
(function initResizable() {
  const STORAGE_KEY = 'oai_registrar_layout_v3';
  const shell = document.querySelector('.app-shell');
  const resizeLeft = document.getElementById('resizeLeft');
  const resizeRight = document.getElementById('resizeRight');
  if (!shell) return;

  function getTrackPx(index) {
    const tracks = getComputedStyle(shell).gridTemplateColumns.match(/[\d.]+px/g) || [];
    const val = tracks[index] ? parseFloat(tracks[index]) : NaN;
    return Number.isFinite(val) ? val : NaN;
  }

  function loadLayout() {
    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
      if (!saved) return;
      const maxW = shell.getBoundingClientRect().width || window.innerWidth;
      if (saved.left && saved.left >= 220 && saved.left <= maxW * 0.4) {
        shell.style.setProperty('--col-left', saved.left + 'px');
      }
      if (saved.right && saved.right >= 260 && saved.right <= maxW * 0.4) {
        shell.style.setProperty('--col-right', saved.right + 'px');
      }
    } catch { }
  }

  function saveLayout() {
    const left = getTrackPx(0);
    const right = getTrackPx(4);
    const data = {};
    if (Number.isFinite(left) && left > 0) data.left = left;
    if (Number.isFinite(right) && right > 0) data.right = right;
    if (Object.keys(data).length) {
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch { }
    }
  }

  function initHandle(handle, prop, minW, getStart) {
    if (!handle) return;
    handle.addEventListener('mousedown', (e) => {
      e.preventDefault();
      document.body.classList.add('resizing');
      handle.classList.add('active');
      const startX = e.clientX;
      const startVal = getStart();
      const totalW = shell.getBoundingClientRect().width;

      const onMove = (ev) => {
        const dx = ev.clientX - startX;
        const delta = prop === '--col-left' ? dx : -dx;
        shell.style.setProperty(prop, Math.max(minW, Math.min(startVal + delta, totalW * 0.4)) + 'px');
      };
      const onUp = () => {
        document.body.classList.remove('resizing');
        handle.classList.remove('active');
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        saveLayout();
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  }

  initHandle(resizeLeft, '--col-left', 220, () => getTrackPx(0) || 280);
  initHandle(resizeRight, '--col-right', 260, () => getTrackPx(4) || 340);

  loadLayout();
})();
