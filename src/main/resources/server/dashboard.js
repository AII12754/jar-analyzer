let dom = {};
let buildPollTimer = 0;

const SECURITY_PRESETS = [
    {
        id: 'runtime-exec',
        shortTitle: 'Runtime.exec',
        title: '命令执行 / Runtime.exec',
        description: '从 Runtime.exec 反推上游调用链，优先排查命令注入与 RCE。',
        sinkClass: 'java/lang/Runtime',
        sinkMethod: 'exec',
        sinkDesc: '(Ljava/lang/String;)Ljava/lang/Process;',
        depth: 10,
        limit: 10,
        fromSink: true,
        searchNullSource: true
    },
    {
        id: 'processbuilder-start',
        shortTitle: 'ProcessBuilder.start',
        title: '命令执行 / ProcessBuilder.start',
        description: '适合排查通过 ProcessBuilder 间接启动系统命令的路径。',
        sinkClass: 'java/lang/ProcessBuilder',
        sinkMethod: 'start',
        sinkDesc: '()Ljava/lang/Process;',
        depth: 10,
        limit: 10,
        fromSink: true,
        searchNullSource: true
    },
    {
        id: 'jndi-lookup',
        shortTitle: 'JNDI lookup',
        title: 'JNDI / lookup',
        description: '结合外部可控名称时，常用于排查 JNDI 注入与远程命名服务访问。',
        sinkClass: 'javax/naming/Context',
        sinkMethod: 'lookup',
        sinkDesc: '',
        depth: 8,
        limit: 8,
        fromSink: true,
        searchNullSource: true
    },
    {
        id: 'deserialization',
        shortTitle: 'readObject',
        title: '反序列化 / readObject',
        description: '命中 ObjectInputStream.readObject 的调用链，适合做反序列化入口审查。',
        sinkClass: 'java/io/ObjectInputStream',
        sinkMethod: 'readObject',
        sinkDesc: '()Ljava/lang/Object;',
        depth: 8,
        limit: 8,
        fromSink: true,
        searchNullSource: true
    },
    {
        id: 'script-eval',
        shortTitle: 'ScriptEngine.eval',
        title: '脚本执行 / ScriptEngine.eval',
        description: '适合排查脚本注入、模板执行或 DSL 动态求值。',
        sinkClass: 'javax/script/ScriptEngine',
        sinkMethod: 'eval',
        sinkDesc: '',
        depth: 8,
        limit: 8,
        fromSink: true,
        searchNullSource: true
    },
    {
        id: 'ssrf-url',
        shortTitle: 'URL.openConnection',
        title: '网络出站 / URL.openConnection',
        description: '适合把外部 URL 输入一路追到网络请求，验证 SSRF 风险。',
        sinkClass: 'java/net/URL',
        sinkMethod: 'openConnection',
        sinkDesc: '()Ljava/net/URLConnection;',
        depth: 8,
        limit: 8,
        fromSink: true,
        searchNullSource: true
    },
    {
        id: 'file-write',
        shortTitle: 'FileOutputStream',
        title: '文件写入 / FileOutputStream',
        description: '适合排查路径穿越、任意文件写入和导出落地类问题。',
        sinkClass: 'java/io/FileOutputStream',
        sinkMethod: '<init>',
        sinkDesc: '',
        depth: 8,
        limit: 8,
        fromSink: true,
        searchNullSource: true
    },
    {
        id: 'reflection-invoke',
        shortTitle: 'Method.invoke',
        title: '反射调用 / Method.invoke',
        description: '适合锁定动态执行面，再转入方法工作台查看真实调用图。',
        sinkClass: 'java/lang/reflect/Method',
        sinkMethod: 'invoke',
        sinkDesc: '',
        depth: 8,
        limit: 8,
        fromSink: true,
        searchNullSource: true
    }
];

const SECURITY_PRESET_MAP = SECURITY_PRESETS.reduce((result, preset) => {
    result[preset.id] = preset;
    return result;
}, {});

const state = {
    selectedMethod: null,
    reportMarkdown: '',
    reportHtml: '',
    reportReady: false,
    methodGraphHtml: '',
    taintGraphHtml: '',
    lastBuildFinishedAt: 0,
    activePage: 'overview',
    securityLoaded: false,
    securityData: null,
    securityActionRows: [],
    securityEntryRows: []
};

document.addEventListener('DOMContentLoaded', () => {
    cacheDom();
    bindEvents();
    restoreToken();
    renderSelectedMethod();
    renderDfsPresetButtons();
    renderSecurityPresetBoard();
    refreshReportStandaloneLink(false, '生成成功后，可从这里直接打开完整报告页面。');
    setFramePlaceholder(dom.methodGraphFrame, '方法调用图', '选中方法后，可直接在这里生成调用图。');
    setFramePlaceholder(dom.taintGraphFrame, '污点与 DFS 图', '执行 DFS 或点击“生成污点图”后，图结果会显示在这里。');
    syncPageFromHash();
    refreshStatus();
    refreshBuildStatus(true);
});

function cacheDom() {
    dom = {
        globalNotice: document.getElementById('globalNotice'),
        refreshStatusBtn: document.getElementById('refreshStatusBtn'),
        quickControllersBtn: document.getElementById('quickControllersBtn'),
        goBuildPageBtn: document.getElementById('goBuildPageBtn'),
        engineMetricValue: document.getElementById('engineMetricValue'),
        engineMetricMeta: document.getElementById('engineMetricMeta'),
        jarMetricValue: document.getElementById('jarMetricValue'),
        jarMetricMeta: document.getElementById('jarMetricMeta'),
        cacheMetricValue: document.getElementById('cacheMetricValue'),
        cacheMetricMeta: document.getElementById('cacheMetricMeta'),
        authMetricValue: document.getElementById('authMetricValue'),
        authMetricMeta: document.getElementById('authMetricMeta'),
        statusRefreshTime: document.getElementById('statusRefreshTime'),
        statusMessage: document.getElementById('statusMessage'),
        jarList: document.getElementById('jarList'),
        authTokenInput: document.getElementById('authTokenInput'),
        saveTokenBtn: document.getElementById('saveTokenBtn'),
        clearTokenBtn: document.getElementById('clearTokenBtn'),
        navPageButtons: Array.from(document.querySelectorAll('[data-page-target]')),
        workspacePages: Array.from(document.querySelectorAll('[data-page]')),
        selectedMethodCard: document.getElementById('selectedMethodCard'),
        buildForm: document.getElementById('buildForm'),
        buildFileInput: document.getElementById('buildFileInput'),
        buildSourcePathInput: document.getElementById('buildSourcePathInput'),
        buildRtJarPathInput: document.getElementById('buildRtJarPathInput'),
        buildQuickMode: document.getElementById('buildQuickMode'),
        buildFixClass: document.getElementById('buildFixClass'),
        buildCleanBeforeBuild: document.getElementById('buildCleanBeforeBuild'),
        refreshBuildStatusBtn: document.getElementById('refreshBuildStatusBtn'),
        buildStatusPill: document.getElementById('buildStatusPill'),
        buildProgressBar: document.getElementById('buildProgressBar'),
        buildProgressValue: document.getElementById('buildProgressValue'),
        buildProgressMeta: document.getElementById('buildProgressMeta'),
        buildSourceMeta: document.getElementById('buildSourceMeta'),
        buildInfoChips: document.getElementById('buildInfoChips'),
        buildLogs: document.getElementById('buildLogs'),
        searchByClassForm: document.getElementById('searchByClassForm'),
        searchByStringForm: document.getElementById('searchByStringForm'),
        searchClassInput: document.getElementById('searchClassInput'),
        searchStringInput: document.getElementById('searchStringInput'),
        loadJarListBtn: document.getElementById('loadJarListBtn'),
        loadControllersBtn: document.getElementById('loadControllersBtn'),
        searchResultMeta: document.getElementById('searchResultMeta'),
        searchResults: document.getElementById('searchResults'),
        methodClassInput: document.getElementById('methodClassInput'),
        methodNameInput: document.getElementById('methodNameInput'),
        methodDescInput: document.getElementById('methodDescInput'),
        methodResultMeta: document.getElementById('methodResultMeta'),
        methodResults: document.getElementById('methodResults'),
        methodActionButtons: Array.from(document.querySelectorAll('[data-method-action]')),
        methodGraphBtn: document.getElementById('methodGraphBtn'),
        openMethodGraphBtn: document.getElementById('openMethodGraphBtn'),
        methodGraphMeta: document.getElementById('methodGraphMeta'),
        methodGraphFrame: document.getElementById('methodGraphFrame'),
        dfsPresetQuickList: document.getElementById('dfsPresetQuickList'),
        dfsForm: document.getElementById('dfsForm'),
        dfsSinkClass: document.getElementById('dfsSinkClass'),
        dfsSinkMethod: document.getElementById('dfsSinkMethod'),
        dfsSinkDesc: document.getElementById('dfsSinkDesc'),
        dfsSourceClass: document.getElementById('dfsSourceClass'),
        dfsSourceMethod: document.getElementById('dfsSourceMethod'),
        dfsSourceDesc: document.getElementById('dfsSourceDesc'),
        dfsDepth: document.getElementById('dfsDepth'),
        dfsLimit: document.getElementById('dfsLimit'),
        dfsFromSink: document.getElementById('dfsFromSink'),
        dfsSearchNullSource: document.getElementById('dfsSearchNullSource'),
        dfsResultMeta: document.getElementById('dfsResultMeta'),
        dfsResults: document.getElementById('dfsResults'),
        taintGraphBtn: document.getElementById('taintGraphBtn'),
        openTaintGraphBtn: document.getElementById('openTaintGraphBtn'),
        taintGraphMeta: document.getElementById('taintGraphMeta'),
        taintGraphFrame: document.getElementById('taintGraphFrame'),
        refreshSecurityBtn: document.getElementById('refreshSecurityBtn'),
        goDfsFromSecurityBtn: document.getElementById('goDfsFromSecurityBtn'),
        securitySummary: document.getElementById('securitySummary'),
        securityPriorityBoard: document.getElementById('securityPriorityBoard'),
        securityAssetBoard: document.getElementById('securityAssetBoard'),
        securityHuntBoard: document.getElementById('securityHuntBoard'),
        securityPresetBoard: document.getElementById('securityPresetBoard'),
        securityEntryPoints: document.getElementById('securityEntryPoints'),
        reportEndpointInput: document.getElementById('reportEndpointInput'),
        reportModelInput: document.getElementById('reportModelInput'),
        reportApiKeyInput: document.getElementById('reportApiKeyInput'),
        reportAnalyzeBtn: document.getElementById('reportAnalyzeBtn'),
        reportCacheBtn: document.getElementById('reportCacheBtn'),
        reportStandaloneLink: document.getElementById('reportStandaloneLink'),
        reportLinkHint: document.getElementById('reportLinkHint'),
        reportSummaryPill: document.getElementById('reportSummaryPill'),
        reportLogs: document.getElementById('reportLogs')
    };
}

function bindEvents() {
    dom.refreshStatusBtn.addEventListener('click', () => {
        refreshStatus();
        refreshBuildStatus();
    });
    dom.quickControllersBtn.addEventListener('click', loadSpringControllers);
    dom.goBuildPageBtn.addEventListener('click', () => activatePage('build'));
    dom.saveTokenBtn.addEventListener('click', saveToken);
    dom.clearTokenBtn.addEventListener('click', clearToken);
    dom.navPageButtons.forEach((button) => {
        button.addEventListener('click', () => activatePage(button.dataset.pageTarget));
    });
    dom.buildForm.addEventListener('submit', startBuild);
    dom.refreshBuildStatusBtn.addEventListener('click', () => refreshBuildStatus());
    dom.searchByClassForm.addEventListener('submit', onSearchByClass);
    dom.searchByStringForm.addEventListener('submit', onSearchByString);
    dom.loadJarListBtn.addEventListener('click', loadJarList);
    dom.loadControllersBtn.addEventListener('click', loadSpringControllers);
    dom.methodActionButtons.forEach((button) => {
        button.addEventListener('click', () => runMethodAction(button.dataset.methodAction));
    });
    dom.methodGraphBtn.addEventListener('click', loadMethodGraph);
    dom.openMethodGraphBtn.addEventListener('click', () => openHtmlWindow(state.methodGraphHtml, 'method-graph.html', '当前没有可打开的调用图。'));
    dom.dfsPresetQuickList.addEventListener('click', handlePresetBoardClick);
    dom.dfsForm.addEventListener('submit', runDfsAnalyze);
    dom.taintGraphBtn.addEventListener('click', () => loadTaintGraph(null, false));
    dom.openTaintGraphBtn.addEventListener('click', () => openHtmlWindow(state.taintGraphHtml, 'taint-graph.html', '当前没有可打开的污点图。'));
    dom.refreshSecurityBtn.addEventListener('click', () => loadSecurityOverview(false));
    dom.goDfsFromSecurityBtn.addEventListener('click', () => activatePage('dfs'));
    dom.securityPriorityBoard.addEventListener('click', handleSecurityHuntClick);
    dom.securityPresetBoard.addEventListener('click', handlePresetBoardClick);
    dom.securityHuntBoard.addEventListener('click', handleSecurityHuntClick);
    dom.securityEntryPoints.addEventListener('click', handleSecurityEntryClick);
    dom.reportAnalyzeBtn.addEventListener('click', () => runReport(true));
    dom.reportCacheBtn.addEventListener('click', () => runReport(false));
    window.addEventListener('hashchange', syncPageFromHash);
}

function syncPageFromHash() {
    const rawHash = window.location.hash.replace(/^#/, '').trim();
    const pageAliases = {
        'overview-panel': 'overview',
        'build-panel': 'build',
        'search-panel': 'search',
        'method-panel': 'method',
        'dfs-panel': 'dfs',
        'security-panel': 'security',
        'report-panel': 'report'
    };
    const targetPage = pageAliases[rawHash] || rawHash || 'overview';
    activatePage(targetPage, true);
}

function activatePage(page, fromHash) {
    const targetPage = hasPage(targetPageName(page)) ? targetPageName(page) : 'overview';
    state.activePage = targetPage;

    dom.workspacePages.forEach((section) => {
        section.classList.toggle('workspace-page-active', section.dataset.page === targetPage);
    });
    dom.navPageButtons.forEach((button) => {
        button.classList.toggle('nav-link-active', button.dataset.pageTarget === targetPage);
    });

    maybeLoadPageData(targetPage);

    if (!fromHash) {
        window.history.replaceState(null, '', `#${targetPage}`);
    }
}

function maybeLoadPageData(page) {
    if (page === 'security' && !state.securityLoaded) {
        loadSecurityOverview(true);
    }
}

function hasPage(page) {
    return dom.workspacePages.some((section) => section.dataset.page === page);
}

function targetPageName(page) {
    return page == null ? '' : String(page).trim();
}

function restoreToken() {
    const saved = localStorage.getItem('jar-analyzer-browser-token');
    if (saved) {
        dom.authTokenInput.value = saved;
    }
}

function saveToken() {
    const value = dom.authTokenInput.value.trim();
    localStorage.setItem('jar-analyzer-browser-token', value);
    showNotice('success', value ? 'Token 已保存，后续请求会自动带上 Token Header。' : '空 Token 已保存。');
}

function clearToken() {
    dom.authTokenInput.value = '';
    localStorage.removeItem('jar-analyzer-browser-token');
    showNotice('info', '已清空本地保存的 Token。');
}

async function refreshStatus() {
    setText(dom.statusMessage, '正在刷新运行状态...');
    dom.statusRefreshTime.textContent = '刷新中';
    renderEmpty(dom.jarList, '正在读取当前已加载 JAR 列表...');
    try {
        const data = await apiRequest('/api/server_status');
        renderStatus(data);
    } catch (error) {
        renderStatusError(error);
    }
}

function renderStatus(data) {
    const engineReady = Boolean(data.engine_ready);
    setText(dom.engineMetricValue, engineReady ? 'Ready' : 'Pending');
    setText(dom.engineMetricMeta, data.message || '');
    setText(dom.jarMetricValue, String(data.jar_count || 0));
    setText(dom.jarMetricMeta, engineReady ? '已加载输入包' : '尚未构建');
    setText(dom.cacheMetricValue, `${data.dfa_count || 0} / ${data.gadget_count || 0}`);
    setText(dom.cacheMetricMeta, data.one_click_cached ? '可直接复用缓存' : '尚未生成缓存');
    setText(dom.authMetricValue, data.auth_enabled ? 'ON' : 'OFF');
    setText(dom.authMetricMeta, data.auth_enabled ? 'API 需要 Token' : '浏览器可直接调用');
    setText(dom.statusMessage, data.message || '');
    dom.statusRefreshTime.textContent = `最近刷新: ${formatTime(new Date())}`;
    renderJarChips(Array.isArray(data.jars) ? data.jars : []);
}

function renderStatusError(error) {
    setText(dom.engineMetricValue, 'Error');
    setText(dom.engineMetricMeta, '状态查询失败');
    setText(dom.jarMetricValue, '--');
    setText(dom.jarMetricMeta, '无法读取');
    setText(dom.cacheMetricValue, '--');
    setText(dom.cacheMetricMeta, '无法读取');
    setText(dom.authMetricValue, 'Unknown');
    setText(dom.authMetricMeta, '请检查 Token 或服务状态');
    setText(dom.statusMessage, buildFriendlyError(error));
    dom.statusRefreshTime.textContent = '刷新失败';
    renderEmpty(dom.jarList, '当前无法读取 JAR 列表。');
    showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
}

function renderJarChips(jars) {
    if (!jars || jars.length === 0) {
        renderEmpty(dom.jarList, '当前没有已加载的输入包。');
        return;
    }
    dom.jarList.innerHTML = jars
        .map((jar) => `<span>${escapeHtml(baseName(jar))}</span>`)
        .join('');
}

async function startBuild(event) {
    event.preventDefault();
    const file = dom.buildFileInput.files && dom.buildFileInput.files[0];
    const sourcePath = dom.buildSourcePathInput.value.trim();
    if (!file && !sourcePath) {
        showNotice('warning', '请上传一个 JAR/WAR，或填写服务器本机路径。');
        return;
    }

    const params = {
        fix_class: String(dom.buildFixClass.checked),
        quick_mode: String(dom.buildQuickMode.checked),
        clean_before_build: String(dom.buildCleanBeforeBuild.checked),
        rt_jar_path: dom.buildRtJarPathInput.value.trim()
    };

    state.securityLoaded = false;
    state.securityData = null;

    setText(dom.buildStatusPill, '提交中');
    setBuildProgress(0, '正在提交浏览器构建任务...');
    renderBuildLogs(['正在提交浏览器构建任务...']);

    try {
        let data;
        if (file) {
            data = await uploadBuildArchive(file, params);
        } else {
            data = await apiRequest('/api/start_project_build', Object.assign({source_path: sourcePath}, params), {method: 'POST'});
        }
        if (!data || data.success === false) {
            throw new Error(data && data.message ? data.message : '构建任务启动失败。');
        }
        dom.buildFileInput.value = '';
        setText(dom.buildSourceMeta, `输入源: ${data.source_name || ''} (${data.source_type || 'unknown'})`);
        showNotice('success', data.message || '浏览器构建任务已启动。');
        refreshBuildStatus(true);
    } catch (error) {
        setText(dom.buildStatusPill, '提交失败');
        renderBuildError(error);
        showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
    }
}

async function uploadBuildArchive(file, params) {
    return apiRequest('/api/start_project_build', params, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/octet-stream',
            'X-File-Name': file.name
        },
        body: await file.arrayBuffer()
    });
}

async function refreshBuildStatus(silent) {
    if (!silent) {
        setText(dom.buildStatusPill, '刷新中');
    }
    try {
        const data = await apiRequest('/api/build_status');
        renderBuildStatus(data);
    } catch (error) {
        stopBuildPolling();
        if (!silent) {
            renderBuildError(error);
            showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
        }
    }
}

function renderBuildStatus(data) {
    if (!data || data.success === false) {
        renderBuildError(new Error(data && data.message ? data.message : '无法读取构建状态。'));
        return;
    }

    const progress = clampProgress(data.progress || 0);
    setBuildProgress(progress, data.message || '等待浏览器发起构建任务。');
    setText(dom.buildStatusPill, resolveBuildPill(data));
    setText(dom.buildSourceMeta, data.source_name
        ? `输入源: ${data.source_name} (${data.source_type || 'unknown'})`
        : '尚未选择输入包。');
    renderBuildInfoChips(data);
    renderBuildLogs(Array.isArray(data.logs) ? data.logs : []);

    if (data.running) {
        scheduleBuildPolling();
    } else {
        stopBuildPolling();
    }

    if (data.finished && data.finished_at && data.finished_at !== state.lastBuildFinishedAt) {
        state.lastBuildFinishedAt = data.finished_at;
        if (data.build_success) {
            state.securityLoaded = false;
            state.securityData = null;
            showNotice('success', '浏览器构建完成，分析引擎已刷新。');
            refreshStatus();
            if (state.activePage === 'security') {
                loadSecurityOverview(true);
            }
        } else {
            showNotice('error', data.error_message || data.message || '构建失败。');
        }
    }
}

function resolveBuildPill(data) {
    if (data.running) {
        return '构建中';
    }
    if (data.finished) {
        return data.build_success ? '已完成' : '失败';
    }
    return '待命';
}

function setBuildProgress(progress, message) {
    const safeProgress = clampProgress(progress);
    dom.buildProgressBar.style.width = `${safeProgress}%`;
    setText(dom.buildProgressValue, `${safeProgress}%`);
    setText(dom.buildProgressMeta, message || '等待浏览器发起构建任务。');
}

function renderBuildInfoChips(data) {
    const chips = [
        `数据库: ${data.db_exists ? data.db_size || '已生成' : '未生成'}`,
        `引擎: ${data.engine_ready ? 'Ready' : 'Pending'}`,
        `任务: ${resolveBuildPill(data)}`
    ];
    if (data.started_at) {
        chips.push(`开始时间: ${formatDateTime(new Date(data.started_at))}`);
    }
    if (data.finished_at) {
        chips.push(`结束时间: ${formatDateTime(new Date(data.finished_at))}`);
    }
    dom.buildInfoChips.innerHTML = chips.map((item) => `<span>${escapeHtml(item)}</span>`).join('');
}

function renderBuildLogs(logs) {
    if (!logs || logs.length === 0) {
        dom.buildLogs.textContent = '等待浏览器发起构建。';
        return;
    }
    dom.buildLogs.innerHTML = logs.map((item) => `<div class="log-item">${escapeHtml(item)}</div>`).join('');
}

function renderBuildError(error) {
    setBuildProgress(0, buildFriendlyError(error));
    setText(dom.buildSourceMeta, '无法读取构建状态。');
    dom.buildInfoChips.innerHTML = '<span>请检查服务端状态</span>';
    renderBuildLogs([buildFriendlyError(error)]);
}

function scheduleBuildPolling() {
    stopBuildPolling();
    buildPollTimer = window.setTimeout(() => refreshBuildStatus(true), 1800);
}

function stopBuildPolling() {
    if (buildPollTimer) {
        window.clearTimeout(buildPollTimer);
        buildPollTimer = 0;
    }
}

async function onSearchByClass(event) {
    event.preventDefault();
    const className = dom.searchClassInput.value.trim();
    if (!className) {
        showNotice('warning', '请先填写类名。');
        dom.searchClassInput.focus();
        return;
    }
    await runSearch('/api/get_methods_by_class', {class: className}, `类 ${className} 的方法列表`);
}

async function onSearchByString(event) {
    event.preventDefault();
    const searchValue = dom.searchStringInput.value.trim();
    if (!searchValue) {
        showNotice('warning', '请先填写需要搜索的字符串。');
        dom.searchStringInput.focus();
        return;
    }
    await runSearch('/api/get_methods_by_str', {str: searchValue}, `字符串 ${searchValue} 的命中方法`);
}

async function loadJarList() {
    await runSearch('/api/get_jars_list', {}, '当前已加载 JAR 列表');
}

async function loadSpringControllers() {
    await runSearch('/api/get_all_spring_controllers', {}, 'Spring Controllers');
}

async function runSearch(path, params, label) {
    dom.searchResultMeta.textContent = `正在执行 ${label}...`;
    renderLoading(dom.searchResults, '查询进行中，请稍候...');
    try {
        const data = await apiRequest(path, params);
        renderDataSet(dom.searchResults, data, {selectable: true});
        dom.searchResultMeta.textContent = summarizeData(label, data);
        if (Array.isArray(data) && data.length > 0 && isMethodLike(data[0])) {
            showNotice('info', '检索结果已加载。点“选中”可直接送入方法工作台。');
        }
    } catch (error) {
        dom.searchResultMeta.textContent = '查询失败';
        renderError(dom.searchResults, error);
        showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
    }
}

function runMethodAction(action) {
    const method = readMethodForm();
    if (!method.className || !method.methodName) {
        showNotice('warning', '请先选中方法，或手动填写类名与方法名。');
        return;
    }

    const actionMap = {
        callers: {path: '/api/get_callers', label: '调用者'},
        callee: {path: '/api/get_callee', label: '被调用'},
        impls: {path: '/api/get_impls', label: '实现类'},
        superImpls: {path: '/api/get_super_impls', label: '父类与接口'},
        cfr: {path: '/api/cfr_code', label: 'CFR 反编译'},
        fernflower: {path: '/api/fernflower_code', label: 'Fernflower 反编译'}
    };
    const config = actionMap[action];
    if (!config) {
        return;
    }

    dom.methodResultMeta.textContent = `正在执行 ${config.label}...`;
    renderLoading(dom.methodResults, '正在读取方法工作台结果...');
    apiRequest(config.path, {
        class: method.className,
        method: method.methodName,
        desc: method.methodDesc
    }).then((data) => {
        if (data && data.success === false) {
            throw new Error(data.message || `${config.label} 失败`);
        }
        if (data && typeof data === 'object' && 'methodCode' in data) {
            renderCodeResult(data);
            dom.methodResultMeta.textContent = `${config.label} 已完成`;
            return;
        }
        renderDataSet(dom.methodResults, data, {selectable: true});
        dom.methodResultMeta.textContent = summarizeData(config.label, data);
    }).catch((error) => {
        dom.methodResultMeta.textContent = `${config.label} 失败`;
        renderError(dom.methodResults, error);
        showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
    });
}

async function loadMethodGraph() {
    const method = readMethodForm();
    if (!method.className || !method.methodName) {
        showNotice('warning', '请先选中方法，或手动填写类名与方法名。');
        return;
    }

    dom.methodGraphMeta.textContent = '正在生成方法调用图...';
    setFramePlaceholder(dom.methodGraphFrame, '方法调用图', '正在生成方法调用图，请稍候...');
    try {
        const html = await requestText('/api/method_graph', {
            class: method.className,
            method: method.methodName,
            desc: method.methodDesc
        });
        state.methodGraphHtml = html;
        dom.methodGraphFrame.srcdoc = html;
        dom.methodGraphMeta.textContent = `${method.className}.${method.methodName} 调用图已更新`;
        showNotice('success', '方法调用图已更新。');
    } catch (error) {
        state.methodGraphHtml = '';
        dom.methodGraphMeta.textContent = '调用图生成失败';
        setFramePlaceholder(dom.methodGraphFrame, '方法调用图', buildFriendlyError(error));
        showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
    }
}

function renderCodeResult(data) {
    const methodCode = data.methodCode || '(没有提取到方法级代码，已回退到类级代码)';
    const fullClassCode = data.fullClassCode || '';
    dom.methodResults.innerHTML = `
        <div class="code-stack">
            <div class="code-card">
                <div class="result-meta">方法级代码</div>
                <pre class="code-surface">${escapeHtml(methodCode)}</pre>
            </div>
            <details class="code-card">
                <summary>展开查看完整类代码</summary>
                <pre class="code-surface">${escapeHtml(fullClassCode)}</pre>
            </details>
        </div>
    `;
}

function renderDfsPresetButtons() {
    if (!dom.dfsPresetQuickList) {
        return;
    }
    dom.dfsPresetQuickList.innerHTML = SECURITY_PRESETS.slice(0, 6)
        .map((preset, index) => `
            <button class="btn ${index === 0 ? 'btn-secondary' : 'btn-ghost'}" data-dfs-preset="${escapeHtml(preset.id)}" type="button">${escapeHtml(preset.shortTitle)}</button>
        `)
        .join('');
}

function renderSecurityPresetBoard() {
    if (!dom.securityPresetBoard) {
        return;
    }
    dom.securityPresetBoard.innerHTML = SECURITY_PRESETS
        .map((preset) => `
            <article class="preset-card">
                <div class="section-kicker">DFS Preset</div>
                <h3>${escapeHtml(preset.title)}</h3>
                <p>${escapeHtml(preset.description)}</p>
                <div class="preset-meta">
                    <span>${escapeHtml(formatClassName(preset.sinkClass))}</span>
                    <span>${escapeHtml(preset.sinkMethod)}</span>
                    <span>Depth ${escapeHtml(String(preset.depth))}</span>
                </div>
                <div class="security-actions">
                    <button class="btn btn-secondary" data-dfs-preset="${escapeHtml(preset.id)}" type="button">套用到 DFS</button>
                </div>
            </article>
        `)
        .join('');
}

function handlePresetBoardClick(event) {
    const button = event.target.closest('[data-dfs-preset]');
    if (!button) {
        return;
    }
    applyDfsPreset(button.dataset.dfsPreset);
}

function fillRuntimePreset() {
    applyDfsPreset('runtime-exec');
}

function applyDfsPreset(presetId) {
    const preset = SECURITY_PRESET_MAP[presetId] || SECURITY_PRESET_MAP['runtime-exec'];
    if (!preset) {
        return;
    }

    dom.dfsSinkClass.value = preset.sinkClass;
    dom.dfsSinkMethod.value = preset.sinkMethod;
    dom.dfsSinkDesc.value = preset.sinkDesc || '';
    dom.dfsSourceClass.value = '';
    dom.dfsSourceMethod.value = '';
    dom.dfsSourceDesc.value = '';
    dom.dfsDepth.value = String(preset.depth || 10);
    dom.dfsLimit.value = String(preset.limit || 10);
    dom.dfsFromSink.checked = preset.fromSink !== false;
    dom.dfsSearchNullSource.checked = preset.searchNullSource !== false;
    state.taintGraphHtml = '';
    dom.taintGraphMeta.textContent = `已填充 ${preset.title} 预设，可重新生成污点图。`;
    setFramePlaceholder(dom.taintGraphFrame, '污点与 DFS 图', `已填充 ${preset.title} 预设，点击“执行 DFS”或“生成污点图”继续分析。`);
    activatePage('dfs');
    showNotice('info', `已填充 ${preset.title} 预设。`);
}

async function loadSecurityOverview(silent) {
    if (!dom.securitySummary) {
        return;
    }
    renderSecurityLoading('正在聚合入口资产与危险调用者...');
    try {
        const data = await apiRequest('/api/security_overview');
        if (!data || data.success === false) {
            throw new Error(data && data.message ? data.message : '安全巡航生成失败。');
        }
        state.securityLoaded = true;
        state.securityData = data;
        renderSecurityOverview(data);
        if (!silent) {
            showNotice('success', '安全巡航结果已刷新。');
        }
    } catch (error) {
        state.securityLoaded = false;
        state.securityData = null;
        renderSecurityError(error);
        if (!silent) {
            showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
        }
    }
}

function renderSecurityLoading(message) {
    const summary = [
        {label: 'Web 入口资产', value: '--', meta: message},
        {label: 'Spring 路由', value: '--', meta: '等待聚合'},
        {label: '命中风险类别', value: '--', meta: '等待聚合'},
        {label: '风险得分', value: '--', meta: '等待聚合'}
    ];
    dom.securitySummary.innerHTML = summary.map((item) => buildSecuritySummaryCard(item)).join('');
    renderEmpty(dom.securityPriorityBoard, message);
    renderEmpty(dom.securityAssetBoard, message);
    renderEmpty(dom.securityHuntBoard, message);
    renderEmpty(dom.securityEntryPoints, message);
}

function renderSecurityError(error) {
    const message = buildFriendlyError(error);
    const summary = [
        {label: 'Web 入口资产', value: 'Error', meta: message},
        {label: 'Spring 路由', value: 'Error', meta: '请检查引擎状态'},
        {label: '命中风险类别', value: 'Error', meta: '请检查鉴权或索引'},
        {label: '风险得分', value: 'Error', meta: '请稍后重试'}
    ];
    dom.securitySummary.innerHTML = summary.map((item) => buildSecuritySummaryCard(item)).join('');
    renderError(dom.securityPriorityBoard, error);
    renderError(dom.securityAssetBoard, error);
    renderError(dom.securityHuntBoard, error);
    renderError(dom.securityEntryPoints, error);
}

function renderSecurityOverview(data) {
    const summary = resolveSecuritySummary(data);
    renderSecuritySummary(summary);
    renderSecurityPriorities(Array.isArray(data.hunts) ? data.hunts : []);
    renderSecurityAssets(data.assets || {}, summary);
    renderSecurityHunts(Array.isArray(data.hunts) ? data.hunts : []);
    renderSecurityEntryPoints((data.assets && Array.isArray(data.assets.mappings)) ? data.assets.mappings : []);
}

function renderSecuritySummary(summary) {
    const cards = [
        {label: 'Web 入口资产', value: String(summary.entrypointCount), meta: `Controller / Servlet / Filter / Listener 共 ${summary.entrypointCount} 个`},
        {label: 'Spring 路由', value: String(summary.mappingCount), meta: '已提取到的 HTTP 路径映射数量'},
        {label: '命中风险类别', value: String(summary.positiveHuntCount), meta: `共发现 ${summary.totalFindingCount} 条待排查线索`},
        {label: '风险得分', value: String(summary.riskScore), meta: `${summary.highPriorityCount} 条高优先级线索需要优先核查`}
    ];
    dom.securitySummary.innerHTML = cards.map((item) => buildSecuritySummaryCard(item)).join('');
}

function buildSecuritySummaryCard(item) {
    return `
        <article class="security-summary-card">
            <span class="metric-label">${escapeHtml(item.label)}</span>
            <strong>${escapeHtml(item.value)}</strong>
            <span>${escapeHtml(item.meta)}</span>
        </article>
    `;
}

function renderSecurityPriorities(hunts) {
    const positive = hunts
        .filter((item) => Number(item.callerCount || 0) > 0)
        .sort((left, right) => {
            const scoreDiff = scoreHuntSeverity(right.severity) - scoreHuntSeverity(left.severity);
            if (scoreDiff !== 0) {
                return scoreDiff;
            }
            return Number(right.callerCount || 0) - Number(left.callerCount || 0);
        });

    if (positive.length === 0) {
        renderEmpty(dom.securityPriorityBoard, '当前没有命中内置危险 Sink。可以先导入样本或手动在方法检索页搜索。');
        return;
    }

    const maxCount = Math.max.apply(null, positive.map((item) => Number(item.callerCount || 0)));
    dom.securityPriorityBoard.innerHTML = `
        <div class="priority-stack">
            ${positive.map((item) => {
                const width = maxCount > 0 ? Math.max(8, Math.round((Number(item.callerCount || 0) / maxCount) * 100)) : 0;
                return `
                    <div class="priority-row">
                        <div class="priority-head">
                            <div>
                                <strong>${escapeHtml(item.title || '')}</strong>
                                <span>${escapeHtml(item.summary || '')}</span>
                            </div>
                            <span class="severity-badge ${resolveSeverityClass(item.severity)}">${escapeHtml(resolveSeverityLabel(item.severity))}</span>
                        </div>
                        <div class="priority-meter"><span style="width: ${width}%"></span></div>
                        <div class="security-actions">
                            <span class="tiny-note">命中 ${escapeHtml(String(item.callerCount || 0))} 条</span>
                            <button class="mini-btn" data-security-preset="${escapeHtml(item.presetId || '')}" type="button">DFS 预设</button>
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

function renderSecurityAssets(assets, summary) {
    const groups = [
        {title: 'Spring Controllers', count: safeLength(assets.controllers), items: assets.controllers},
        {title: 'Servlets', count: safeLength(assets.servlets), items: assets.servlets},
        {title: 'Filters', count: safeLength(assets.filters), items: assets.filters},
        {title: 'Listeners', count: safeLength(assets.listeners), items: assets.listeners}
    ];
    dom.securityAssetBoard.innerHTML = `
        <div class="asset-grid">
            ${groups.map((group) => `
                <article class="asset-card">
                    <div class="asset-card-head">
                        <strong>${escapeHtml(group.title)}</strong>
                        <span>${escapeHtml(String(group.count))} 个</span>
                    </div>
                    <div class="asset-tags">
                        ${topAssetNames(group.items).map((item) => `<span>${escapeHtml(item)}</span>`).join('') || '<span>未发现</span>'}
                    </div>
                </article>
            `).join('')}
        </div>
        <p class="entrypoint-note">当前共识别 ${escapeHtml(String(summary.entrypointCount))} 个 Web 入口资产，Spring 路由 ${escapeHtml(String(summary.mappingCount))} 条。</p>
    `;
}

function renderSecurityHunts(hunts) {
    state.securityActionRows = [];
    if (!hunts || hunts.length === 0) {
        renderEmpty(dom.securityHuntBoard, '当前没有可展示的内置漏洞排查结果。');
        return;
    }
    dom.securityHuntBoard.innerHTML = `
        <div class="hunt-stack">
            ${hunts.map((hunt) => {
                const findings = Array.isArray(hunt.findings) ? hunt.findings : [];
                const preview = findings.slice(0, 5).map((row) => {
                    const index = state.securityActionRows.push(Object.assign({presetId: hunt.presetId}, row)) - 1;
                    return `
                        <div class="security-finding">
                            <div class="security-finding-top">
                                <div class="security-finding-main">
                                    <strong>${escapeHtml(formatClassName(row.className || ''))}</strong>
                                    <code>${escapeHtml(`${row.methodName || ''} ${row.methodDesc || ''}`)}</code>
                                </div>
                                <span class="tiny-note">${escapeHtml(row.matchedSink || '')}</span>
                            </div>
                            <div class="security-actions">
                                <button class="mini-btn" data-security-select-index="${index}" type="button">送入工作台</button>
                                <button class="mini-btn" data-security-graph-index="${index}" type="button">调用图</button>
                            </div>
                        </div>
                    `;
                }).join('');
                return `
                    <article class="hunt-card">
                        <div class="hunt-head">
                            <div>
                                <strong>${escapeHtml(hunt.title || '')}</strong>
                                <span>${escapeHtml(hunt.summary || '')}</span>
                            </div>
                            <span class="severity-badge ${resolveSeverityClass(hunt.severity)}">${escapeHtml(resolveSeverityLabel(hunt.severity))}</span>
                        </div>
                        <div class="security-actions">
                            <span class="tiny-note">命中 ${escapeHtml(String(hunt.callerCount || 0))} 条</span>
                            <button class="mini-btn" data-security-preset="${escapeHtml(hunt.presetId || '')}" type="button">套用 DFS 预设</button>
                        </div>
                        ${findings.length > 0
                            ? `<div class="hunt-list">${preview}</div>${findings.length > 5 ? `<div class="tiny-note">其余 ${escapeHtml(String(findings.length - 5))} 条可以继续在方法检索或方法工作台中展开。</div>` : ''}`
                            : '<div class="result-empty">当前未命中。</div>'}
                    </article>
                `;
            }).join('')}
        </div>
    `;
}

function handleSecurityHuntClick(event) {
    const presetButton = event.target.closest('[data-security-preset]');
    if (presetButton) {
        applyDfsPreset(presetButton.dataset.securityPreset);
        return;
    }

    const selectButton = event.target.closest('[data-security-select-index]');
    if (selectButton) {
        const row = state.securityActionRows[Number(selectButton.dataset.securitySelectIndex)];
        if (row) {
            setSelectedMethod(row);
            activatePage('method');
            showNotice('info', '已将安全线索方法送入工作台。');
        }
        return;
    }

    const graphButton = event.target.closest('[data-security-graph-index]');
    if (graphButton) {
        const row = state.securityActionRows[Number(graphButton.dataset.securityGraphIndex)];
        if (row) {
            setSelectedMethod(row);
            activatePage('method');
            loadMethodGraph();
            showNotice('info', '已根据安全线索生成调用图。');
        }
    }
}

function renderSecurityEntryPoints(mappings) {
    state.securityEntryRows = Array.isArray(mappings) ? mappings : [];
    if (!state.securityEntryRows.length) {
        renderEmpty(dom.securityEntryPoints, '当前没有提取到 Spring 入口映射。');
        return;
    }
    const displayRows = state.securityEntryRows.slice(0, 18);
    dom.securityEntryPoints.innerHTML = `
        <div class="entrypoint-stack">
            ${displayRows.map((row, index) => `
                <div class="entrypoint-row">
                    <div>
                        <div class="entrypoint-path">${escapeHtml((row.restfulType || 'REQUEST') + ' ' + (row.actualPath || '/'))}</div>
                        <div class="tiny-note">Spring MVC 入口</div>
                    </div>
                    <div class="entrypoint-main">
                        <strong>${escapeHtml(formatClassName(row.className || ''))}</strong>
                        <div class="entrypoint-code">${escapeHtml(`${row.methodName || ''} ${row.methodDesc || ''}`)}</div>
                    </div>
                    <div class="entrypoint-actions">
                        <button class="mini-btn" data-security-entry-select-index="${index}" type="button">送入工作台</button>
                        <button class="mini-btn" data-security-entry-graph-index="${index}" type="button">调用图</button>
                    </div>
                </div>
            `).join('')}
            ${state.securityEntryRows.length > displayRows.length
                ? `<div class="tiny-note">当前仅展示前 ${escapeHtml(String(displayRows.length))} 条入口映射，完整结果建议结合方法检索页继续展开。</div>`
                : ''}
        </div>
    `;
}

function handleSecurityEntryClick(event) {
    const selectButton = event.target.closest('[data-security-entry-select-index]');
    if (selectButton) {
        const row = state.securityEntryRows[Number(selectButton.dataset.securityEntrySelectIndex)];
        if (row) {
            setSelectedMethod(row);
            activatePage('method');
            showNotice('info', '已将入口方法送入工作台。');
        }
        return;
    }

    const graphButton = event.target.closest('[data-security-entry-graph-index]');
    if (graphButton) {
        const row = state.securityEntryRows[Number(graphButton.dataset.securityEntryGraphIndex)];
        if (row) {
            setSelectedMethod(row);
            activatePage('method');
            loadMethodGraph();
            showNotice('info', '已根据入口方法生成调用图。');
        }
    }
}

function resolveSecuritySummary(data) {
    const assets = data && data.assets ? data.assets : {};
    const hunts = Array.isArray(data && data.hunts) ? data.hunts : [];
    const entrypointCount = safeLength(assets.controllers)
        + safeLength(assets.servlets)
        + safeLength(assets.filters)
        + safeLength(assets.listeners);
    const mappingCount = safeLength(assets.mappings);
    const positive = hunts.filter((item) => Number(item.callerCount || 0) > 0);
    const totalFindingCount = positive.reduce((sum, item) => sum + Number(item.callerCount || 0), 0);
    const highPriorityCount = positive
        .filter((item) => scoreHuntSeverity(item.severity) >= 3)
        .reduce((sum, item) => sum + Number(item.callerCount || 0), 0);
    const riskScore = Math.min(100, entrypointCount * 2 + mappingCount + positive.reduce((sum, item) => {
        return sum + Math.min(Number(item.callerCount || 0), 8) * scoreHuntSeverity(item.severity);
    }, 0));
    return {
        entrypointCount,
        mappingCount,
        positiveHuntCount: positive.length,
        totalFindingCount,
        highPriorityCount,
        riskScore
    };
}

function resolveSeverityClass(severity) {
    const normalized = String(severity || '').toLowerCase();
    if (normalized === 'critical') {
        return 'severity-critical';
    }
    if (normalized === 'high') {
        return 'severity-high';
    }
    return 'severity-medium';
}

function resolveSeverityLabel(severity) {
    const normalized = String(severity || '').toLowerCase();
    if (normalized === 'critical') {
        return '严重';
    }
    if (normalized === 'high') {
        return '高危';
    }
    return '中危';
}

function scoreHuntSeverity(severity) {
    const normalized = String(severity || '').toLowerCase();
    if (normalized === 'critical') {
        return 4;
    }
    if (normalized === 'high') {
        return 3;
    }
    return 2;
}

function topAssetNames(items) {
    return (Array.isArray(items) ? items : [])
        .slice(0, 5)
        .map((item) => shortClassName(item.className || ''));
}

function safeLength(value) {
    return Array.isArray(value) ? value.length : 0;
}

async function runDfsAnalyze(event) {
    event.preventDefault();
    const params = readDfsParams();
    if (!validateDfsParams(params)) {
        return;
    }

    dom.dfsResultMeta.textContent = '正在执行 DFS...';
    renderLoading(dom.dfsResults, 'DFS 分析执行中，请稍候...');
    try {
        const data = await apiRequest('/api/dfs_analyze', params);
        renderDataSet(dom.dfsResults, data, {selectable: true});
        dom.dfsResultMeta.textContent = summarizeData('DFS 分析结果', data);
        loadTaintGraph(params, true);
    } catch (error) {
        dom.dfsResultMeta.textContent = 'DFS 执行失败';
        renderError(dom.dfsResults, error);
        showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
    }
}

async function loadTaintGraph(preparedParams, silentNotice) {
    const params = preparedParams || readDfsParams();
    if (!validateDfsParams(params)) {
        return;
    }

    dom.taintGraphMeta.textContent = '正在生成污点与 DFS 图...';
    setFramePlaceholder(dom.taintGraphFrame, '污点与 DFS 图', '正在生成污点图，请稍候...');
    try {
        const html = await requestText('/api/taint_graph', params);
        state.taintGraphHtml = html;
        dom.taintGraphFrame.srcdoc = html;
        dom.taintGraphMeta.textContent = '污点与 DFS 图已更新';
        if (!silentNotice) {
            showNotice('success', '污点与 DFS 图已更新。');
        }
    } catch (error) {
        state.taintGraphHtml = '';
        dom.taintGraphMeta.textContent = '污点图生成失败';
        setFramePlaceholder(dom.taintGraphFrame, '污点与 DFS 图', buildFriendlyError(error));
        showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
    }
}

function readDfsParams() {
    return {
        sink_class: dom.dfsSinkClass.value.trim(),
        sink_method: dom.dfsSinkMethod.value.trim(),
        sink_method_desc: dom.dfsSinkDesc.value.trim(),
        source_class: dom.dfsSourceClass.value.trim(),
        source_method: dom.dfsSourceMethod.value.trim(),
        source_method_desc: dom.dfsSourceDesc.value.trim(),
        depth: dom.dfsDepth.value.trim(),
        limit: dom.dfsLimit.value.trim(),
        from_sink: String(dom.dfsFromSink.checked),
        search_null_source: String(dom.dfsSearchNullSource.checked)
    };
}

function validateDfsParams(params) {
    if (!params.sink_class || !params.sink_method) {
        showNotice('warning', 'DFS 至少需要 sink_class 和 sink_method。');
        return false;
    }
    return true;
}

async function runReport(analyzeFirst) {
    const endpoint = dom.reportEndpointInput.value.trim();
    const apiKey = dom.reportApiKeyInput.value.trim();
    const model = dom.reportModelInput.value.trim();
    if (!endpoint || !apiKey || !model) {
        showNotice('warning', '请先填写完整的 LLM Endpoint、API Key 和模型名。');
        return;
    }

    setReportBusy(analyzeFirst ? '正在执行整项目分析并生成报告...' : '正在基于缓存生成报告...');
    setReportButtonsDisabled(true);
    try {
        const data = await apiRequest('/api/generate_audit_report', {
            endpoint,
            api_key: apiKey,
            model,
            analyze_first: String(analyzeFirst)
        }, {method: 'POST'});
        renderReportResult(data);
        if (data.success) {
            showNotice('success', '浏览器审计报告已生成。');
        } else {
            showNotice('error', data.message || '报告生成失败。');
        }
        refreshStatus();
    } catch (error) {
        renderLogItems([buildFriendlyError(error)]);
        dom.reportSummaryPill.textContent = '生成失败';
        refreshReportStandaloneLink(state.reportReady, '生成失败。独立报告页会保留最近一次成功生成的内容。');
        showNotice(error.requiresToken ? 'warning' : 'error', buildFriendlyError(error));
    } finally {
        setReportButtonsDisabled(false);
    }
}

function setReportBusy(message) {
    dom.reportSummaryPill.textContent = message;
    renderLogItems([message]);
    refreshReportStandaloneLink(state.reportReady, '报告生成进行中。完成后可从这里打开最新独立报告页。');
}

function renderReportResult(data) {
    state.reportMarkdown = data.markdown || '';
    state.reportHtml = data.html || '';
    state.reportReady = Boolean(state.reportHtml);
    const dfaCount = data.dfa_count || 0;
    const gadgetCount = data.gadget_count || 0;
    const targetName = data.target_name || '当前项目';
    dom.reportSummaryPill.textContent = data.success
        ? `${targetName} | DFA ${dfaCount} | Gadget ${gadgetCount}`
        : '报告生成失败';
    renderLogItems(Array.isArray(data.logs) ? data.logs : []);
    refreshReportStandaloneLink(state.reportReady, data.success
        ? `最新报告已生成，可直接打开独立页面查看完整排版。目标：${targetName}`
        : '最近一次生成失败。独立报告页会展示失败说明页面。');
}

function renderLogItems(logs) {
    if (!logs || logs.length === 0) {
        dom.reportLogs.innerHTML = '暂无日志。';
        return;
    }
    dom.reportLogs.innerHTML = logs
        .map((item) => `<div class="log-item">${escapeHtml(item)}</div>`)
        .join('');
}

function refreshReportStandaloneLink(hasFreshReport, hint) {
    const suffix = hasFreshReport ? `?ts=${Date.now()}` : '';
    if (dom.reportStandaloneLink) {
        dom.reportStandaloneLink.href = `/report/latest${suffix}`;
    }
    if (dom.reportLinkHint) {
        dom.reportLinkHint.textContent = hint || '生成成功后，可从这里直接打开完整报告页面。';
    }
}

function setFramePlaceholder(frame, title, message) {
    if (frame) {
        frame.srcdoc = buildPlaceholderHtml(title, message || '等待结果返回。');
    }
}

function buildPlaceholderHtml(title, message) {
    const safeTitle = escapeHtml(title || 'Jar Analyzer Web Console');
    const safeMessage = escapeHtml(message || '等待结果返回。');
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><style>body{margin:0;font-family:Segoe UI Variable Text,Microsoft YaHei UI,sans-serif;background:#f9f6f1;color:#23352d;display:flex;align-items:center;justify-content:center;min-height:100vh}article{max-width:680px;padding:32px;border-radius:24px;background:#fff;border:1px solid rgba(22,41,32,.12);box-shadow:0 16px 40px rgba(22,41,32,.08)}h1{margin:0 0 12px;font-size:28px}p{margin:0;color:#5c6f64;line-height:1.7}</style></head><body><article><h1>${safeTitle}</h1><p>${safeMessage}</p></article></body></html>`;
}

function setReportButtonsDisabled(disabled) {
    [
        dom.reportAnalyzeBtn,
        dom.reportCacheBtn
    ].forEach((button) => {
        button.disabled = disabled;
    });
}

function copyReportMarkdown() {
    if (!state.reportMarkdown) {
        showNotice('warning', '当前没有可复制的 Markdown 报告。');
        return;
    }
    navigator.clipboard.writeText(state.reportMarkdown)
        .then(() => showNotice('success', 'Markdown 报告已复制到剪贴板。'))
        .catch(() => showNotice('error', '复制失败，请检查浏览器权限。'));
}

function downloadReport(type) {
    if (!state.reportReady) {
        showNotice('warning', '当前没有可下载的有效报告。');
        return;
    }
    if (type === 'md') {
        downloadBlob('security-audit-report.md', state.reportMarkdown, 'text/markdown;charset=utf-8');
    } else {
        downloadBlob('security-audit-report.html', state.reportHtml, 'text/html;charset=utf-8');
    }
}

function openReportInWindow() {
    if (!state.reportReady) {
        showNotice('warning', '当前没有可预览的有效报告。');
        return;
    }
    openHtmlWindow(state.reportHtml, 'security-audit-report.html', '当前没有可打开的报告。');
}

function openHtmlWindow(html, filename, emptyMessage) {
    if (!html) {
        showNotice('warning', emptyMessage || '当前没有可打开的 HTML 内容。');
        return;
    }
    const popup = window.open('', '_blank');
    if (!popup) {
        showNotice('warning', '浏览器阻止了新窗口，请允许弹窗后重试。');
        return;
    }
    popup.document.open();
    popup.document.write(ensureHtmlBase(html));
    popup.document.close();
    if (filename) {
        popup.document.title = filename;
    }
}

function readMethodForm() {
    return {
        className: dom.methodClassInput.value.trim(),
        methodName: dom.methodNameInput.value.trim(),
        methodDesc: dom.methodDescInput.value.trim()
    };
}

function setSelectedMethod(method) {
    state.selectedMethod = method;
    dom.methodClassInput.value = method.className || '';
    dom.methodNameInput.value = method.methodName || '';
    dom.methodDescInput.value = method.methodDesc || '';
    state.methodGraphHtml = '';
    dom.methodGraphMeta.textContent = '已更新方法输入，可重新生成调用图。';
    setFramePlaceholder(dom.methodGraphFrame, '方法调用图', '当前图结果可能已过期，请点击“调用图”重新生成。');
    renderSelectedMethod();
}

function renderSelectedMethod() {
    if (!state.selectedMethod) {
        dom.selectedMethodCard.className = 'selection-card selection-card-empty';
        dom.selectedMethodCard.textContent = '暂未选中方法。你可以从“方法检索”结果中点选一行，或在下方手工输入类名、方法名和描述符，然后直接生成调用图。';
        return;
    }
    dom.selectedMethodCard.className = 'selection-card';
    dom.selectedMethodCard.innerHTML = `
        <strong>${escapeHtml(state.selectedMethod.className || '')}</strong>
        <code>${escapeHtml(state.selectedMethod.methodName || '')}</code>
        <code>${escapeHtml(state.selectedMethod.methodDesc || '')}</code>
        <div class="side-note">选中后可以直接查询调用者、实现类、查看 CFR / Fernflower 反编译结果，或生成调用图。</div>
    `;
}

function renderDataSet(container, data, options) {
    if (Array.isArray(data)) {
        renderArray(container, data, options || {});
        return;
    }
    if (data && typeof data === 'object') {
        renderObject(container, data);
        return;
    }
    renderEmpty(container, '返回内容为空。');
}

function renderArray(container, rows, options) {
    if (!rows || rows.length === 0) {
        renderEmpty(container, '没有返回任何结果。');
        return;
    }
    if (typeof rows[0] !== 'object' || rows[0] === null) {
        container.innerHTML = `<pre class="json-block">${escapeHtml(JSON.stringify(rows, null, 2))}</pre>`;
        return;
    }

    const columns = resolveColumns(rows);
    let html = '<div class="table-wrap"><table class="data-table"><thead><tr>';
    if (options.selectable) {
        html += '<th>操作</th>';
    }
    columns.forEach((column) => {
        html += `<th>${escapeHtml(column)}</th>`;
    });
    html += '</tr></thead><tbody>';

    rows.forEach((row, index) => {
        const selectable = options.selectable && isMethodLike(row);
        html += `<tr class="${selectable ? 'selectable-row' : ''}">`;
        if (options.selectable) {
            html += selectable
                ? `<td><button class="mini-btn" type="button" data-select-index="${index}">选中</button></td>`
                : '<td>-</td>';
        }
        columns.forEach((column) => {
            const value = row[column];
            html += `<td data-code="${isCodeishColumn(column)}">${escapeHtml(formatCell(value))}</td>`;
        });
        html += '</tr>';
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;

    container.querySelectorAll('[data-select-index]').forEach((button) => {
        button.addEventListener('click', () => {
            const row = rows[Number(button.dataset.selectIndex)];
            if (row) {
                setSelectedMethod(row);
                activatePage('method');
                showNotice('info', '已将方法送入工作台。');
            }
        });
    });
}

function renderObject(container, data) {
    if (data.success === false) {
        renderError(container, new Error(data.message || '请求失败'));
        return;
    }
    container.innerHTML = `<pre class="json-block">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
}

function renderLoading(container, message) {
    renderEmpty(container, message || '加载中...');
}

function renderEmpty(container, message) {
    container.innerHTML = `<div class="result-empty">${escapeHtml(message)}</div>`;
}

function renderError(container, error) {
    container.innerHTML = `<div class="result-empty">${escapeHtml(buildFriendlyError(error))}</div>`;
}

function resolveColumns(rows) {
    const preferred = ['className', 'methodName', 'methodDesc', 'jarName', 'restfulType', 'actualPath', 'sinkDescription', 'triggerClass', 'triggerMethod', 'sinkClass', 'sinkMethod', 'depth'];
    const keys = [];
    rows.forEach((row) => {
        Object.keys(row).forEach((key) => {
            if (!keys.includes(key)) {
                keys.push(key);
            }
        });
    });
    const ordered = [];
    preferred.forEach((key) => {
        if (keys.includes(key)) {
            ordered.push(key);
        }
    });
    keys.forEach((key) => {
        if (!ordered.includes(key)) {
            ordered.push(key);
        }
    });
    return ordered;
}

function summarizeData(label, data) {
    if (Array.isArray(data)) {
        return `${label}：共 ${data.length} 条结果`;
    }
    if (data && typeof data === 'object') {
        return `${label}：返回对象结果`;
    }
    return `${label}：结果为空`;
}

async function apiRequest(path, params, options) {
    const text = await requestText(path, params, options);
    try {
        return JSON.parse(text);
    } catch (error) {
        throw new Error(text || '服务端返回了非 JSON 内容。');
    }
}

async function requestText(path, params, options) {
    const config = options || {};
    const method = (config.method || 'GET').toUpperCase();
    const headers = Object.assign({}, config.headers || {});
    const token = dom.authTokenInput.value.trim();
    if (token) {
        headers.Token = token;
    }

    const cleanParams = normalizeParams(params || {});
    let url = path;
    const query = new URLSearchParams(cleanParams).toString();
    if (query && (method === 'GET' || config.body !== undefined)) {
        url += (url.indexOf('?') >= 0 ? '&' : '?') + query;
    }

    let body = config.body;
    if (method !== 'GET' && body === undefined) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
        body = query;
    }

    const response = await fetch(url, {
        method,
        headers,
        body
    });
    const text = await response.text();
    if (!response.ok) {
        throw buildHttpError(text, response.status);
    }
    return text;
}

function buildHttpError(text, status) {
    const error = new Error(text || `HTTP ${status}`);
    error.status = status;
    error.requiresToken = /NEED TOKEN HEADER/i.test(text || '');
    return error;
}

function buildFriendlyError(error) {
    const raw = error && error.message ? error.message : '未知错误';
    if (/NEED TOKEN HEADER/i.test(raw)) {
        return '服务端当前启用了 auth。请在左侧填入 server token，然后重新执行操作。';
    }
    if (/CORE ENGINE IS NULL/i.test(raw)) {
        return '当前尚未建立分析索引。请先到“浏览器构建”页导入 JAR/WAR，并完成索引构建。';
    }
    return raw.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function ensureHtmlBase(html) {
    if (!html || /<base\b/i.test(html)) {
        return html;
    }
    const baseHref = `${window.location.origin}/`;
    const baseTag = `<base href="${baseHref}">`;
    if (/<head[^>]*>/i.test(html)) {
        return html.replace(/<head([^>]*)>/i, `<head$1>${baseTag}`);
    }
    return html;
}

function normalizeParams(params) {
    const result = {};
    Object.keys(params).forEach((key) => {
        const value = params[key];
        if (value !== undefined && value !== null && value !== '') {
            result[key] = value;
        }
    });
    return result;
}

function isMethodLike(row) {
    return row && typeof row === 'object' && 'className' in row && 'methodName' in row && 'methodDesc' in row;
}

function isCodeishColumn(column) {
    return /className|methodName|methodDesc|sinkClass|sinkMethod|triggerClass|triggerMethod|actualPath/i.test(column);
}

function formatCell(value) {
    if (value === null || value === undefined) {
        return '';
    }
    if (typeof value === 'object') {
        return JSON.stringify(value);
    }
    return String(value);
}

function formatClassName(value) {
    return String(value || '').replace(/\//g, '.');
}

function shortClassName(value) {
    const text = formatClassName(value);
    const parts = text.split('.');
    return parts[parts.length - 1] || text;
}

function clampProgress(value) {
    return Math.max(0, Math.min(Number(value) || 0, 100));
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function setText(element, value) {
    if (element) {
        element.textContent = value == null ? '' : String(value);
    }
}

function showNotice(type, message) {
    dom.globalNotice.className = `notice notice-${type}`;
    dom.globalNotice.textContent = message;
}

function formatTime(date) {
    return date.toLocaleTimeString('zh-CN', {hour12: false});
}

function formatDateTime(date) {
    return date.toLocaleString('zh-CN', {hour12: false});
}

function baseName(value) {
    const normalized = String(value || '').replace(/\\/g, '/');
    const index = normalized.lastIndexOf('/');
    return index >= 0 ? normalized.slice(index + 1) : normalized;
}

function downloadBlob(filename, content, mimeType, openInsteadOfDownload) {
    const blob = new Blob([content], {type: mimeType});
    const url = URL.createObjectURL(blob);
    if (openInsteadOfDownload) {
        window.open(url, '_blank', 'noopener,noreferrer');
    } else {
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
    }
    setTimeout(() => URL.revokeObjectURL(url), 30000);
}