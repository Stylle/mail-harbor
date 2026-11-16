<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import {
  PhEnvelopeSimple,
  PhTray,
  PhStar,
  PhMagnifyingGlass,
  PhPlus,
  PhArrowLeft,
  PhArrowClockwise,
  PhGearSix,
  PhBell,
  PhShieldCheck,
  PhArchive,
  PhList,
  PhX,
  PhSignOut,
  PhMoon,
  PhSun,
  PhCheck,
  PhArrowDown,
  PhPaperclip,
  PhTelegramLogo,
  PhLink,
  PhSlidersHorizontal,
  PhWarningCircle,
  PhCaretRight,
  PhDotsThree,
  PhDownloadSimple,
  PhUploadSimple,
} from "@phosphor-icons/vue";
interface Account {
  id: string;
  name: string;
  provider: string;
  email: string;
  enabled: boolean;
  hasSecret: boolean;
  authorized: boolean;
  clientId: string;
  lastSync: number;
  lastError: string;
  initialized: boolean;
}
interface Message {
  id: string;
  accountId: string;
  subject: string;
  from: string;
  sender: string;
  date: number;
  read: boolean;
  starred: boolean;
  preview: string;
  attachments: boolean;
}
interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  accountId: string;
  sender: string;
  keyword: string;
  mode: string;
  telegram: boolean;
  webhook: boolean;
}
interface Detail {
  text: string;
  attachments: { index: number; name: string; size: number }[];
}
const providers = [
  {
    id: "qq",
    name: "QQ 邮箱",
    label: "QQ",
    color: "#387cce",
    help: "在 QQ 邮箱设置 → 账号与安全 → 安全设置中开启 IMAP 服务，生成客户端授权码。此处填写授权码。",
  },
  {
    id: "163",
    name: "163 邮箱",
    label: "163",
    color: "#c55252",
    help: "在网页版邮箱设置 → POP3/SMTP/IMAP 中开启 IMAP，生成客户端授权码。服务器会发送客户端 ID 以兼容网易安全检查。",
  },
  {
    id: "gmail",
    name: "Gmail",
    label: "G",
    color: "#b86c38",
    help: "开启 Google 两步验证后生成应用专用密码。若账户未提供此选项（例如组织策略限制），暂不支持通过普通密码接入。",
  },
  {
    id: "outlook",
    name: "Outlook",
    label: "O",
    color: "#367ca7",
    help: "在 Microsoft Entra 注册支持个人 Microsoft 账户的应用，开启“允许公共客户端流”，添加委托权限 Mail.Read、User.Read。填写应用 Client ID，保存后开始授权。",
  },
];
const state = reactive<{
  accounts: Account[];
  messages: Message[];
  rules: Rule[];
  channels: any;
  events: { time: number; kind: string; text: string }[];
  jobs: { pending: number; sent: number; failed: number };
  busy: string[];
}>({
  accounts: [],
  messages: [],
  rules: [],
  channels: {},
  events: [],
  jobs: { pending: 0, sent: 0, failed: 0 },
  busy: [],
});
const session = reactive({
  ready: false,
  configured: false,
  authenticated: false,
  csrf: "",
  username: "",
  version: "0.1.0",
});
const credentials = reactive({ username: "admin", password: "" });
const page = ref("inbox"),
  filter = ref("all"),
  query = ref(""),
  selected = ref(""),
  navOpen = ref(false),
  working = ref(false),
  toast = ref(""),
  toastError = ref(false),
  detail = ref<Detail | null>(null),
  detailError = ref(""),
  loadingDetail = ref(false);
const theme = ref("light");
let refreshTimer: ReturnType<typeof setInterval> | undefined;
let toastTimer: ReturnType<typeof setTimeout> | undefined;
let detailAbort: AbortController | undefined;
let deviceSerial = 0;
function notice(text: string, error = false) {
  toast.value = text;
  toastError.value = error;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (toast.value = ""), 6500);
}
function applyTheme() {
  document.documentElement.dataset.theme = theme.value;
  try {
    localStorage.setItem("mail-harbor.theme", theme.value);
  } catch {}
}
async function api(path: string, data?: any, signal?: AbortSignal) {
  const response = await fetch("/api/" + path, {
    method: data === undefined ? "GET" : "POST",
    headers:
      data === undefined
        ? {}
        : { "Content-Type": "application/json", "X-CSRF-Token": session.csrf },
    body: data === undefined ? undefined : JSON.stringify(data),
    signal,
  });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      session.authenticated = false;
      selected.value = "";
    }
    throw Error(result.error || "请求失败，请稍后重试");
  }
  return result;
}
async function task(fn: () => Promise<void>) {
  if (working.value) return;
  working.value = true;
  try {
    await fn();
  } catch (e) {
    notice(e instanceof Error ? e.message : "操作失败", true);
  } finally {
    working.value = false;
  }
}
async function reload() {
  if (!session.authenticated) return;
  Object.assign(state, await api("state"));
}
async function refreshSession() {
  const result = await api("session");
  Object.assign(session, result, { ready: true });
  if (result.authenticated) await reload();
}
async function login() {
  await task(async () => {
    const result = await api(
      session.configured ? "login" : "setup",
      credentials,
    );
    Object.assign(session, result, { configured: true, authenticated: true });
    credentials.password = "";
    await reload();
  });
}
async function logout() {
  await task(async () => {
    await api("logout", {});
    session.authenticated = false;
    session.csrf = "";
    deviceSerial++;
    state.messages = [];
    state.accounts = [];
    detail.value = null;
    selected.value = "";
  });
}
const totalUnread = computed(
  () => state.messages.filter((m) => !m.read).length,
);
const visible = computed(() =>
  state.messages.filter(
    (m) =>
      (filter.value === "all" ||
        (filter.value === "unread" && !m.read) ||
        (filter.value === "starred" && m.starred) ||
        m.accountId === filter.value) &&
      (!query.value ||
        `${m.subject} ${m.from} ${m.sender} ${m.preview}`
          .toLocaleLowerCase()
          .includes(query.value.toLocaleLowerCase())),
  ),
);
const current = computed(() =>
  state.messages.find((m) => m.id === selected.value),
);
const account = (id: string) => state.accounts.find((a) => a.id === id);
const provider = (id: string) =>
  providers.find((p) => p.id === id) || providers[0];
const unread = (id: string) =>
  state.messages.filter((m) => m.accountId === id && !m.read).length;
const title = computed(() =>
  filter.value === "all"
    ? "全部收件箱"
    : filter.value === "unread"
      ? "未读邮件"
      : filter.value === "starred"
        ? "星标邮件"
        : account(filter.value)?.name || "收件箱",
);
const pages = [
  { id: "accounts", name: "邮箱账户", icon: PhEnvelopeSimple },
  { id: "channels", name: "通知通道", icon: PhBell },
  { id: "rules", name: "推送规则", icon: PhSlidersHorizontal },
  { id: "backup", name: "备份与恢复", icon: PhArchive },
  { id: "events", name: "运行记录", icon: PhList },
  { id: "security", name: "账户安全", icon: PhShieldCheck },
];
const pageTitle = computed(
  () => pages.find((p) => p.id === page.value)?.name || title.value,
);
function navigate(id: string, f = "all") {
  page.value = id;
  filter.value = f;
  navOpen.value = false;
  selected.value = "";
  detailAbort?.abort();
  if (id === "channels")
    Object.assign(channelForm, {
      telegramEnabled: !!state.channels.telegramEnabled,
      token: "",
      clearToken: false,
      webhookEnabled: !!state.channels.webhookEnabled,
      webhookUrl: state.channels.webhookUrl || "",
      webhookSecret: "",
      clearWebhookSecret: false,
    });
  if (id === "rules")
    rulesForm.value = state.rules.map((rule) => ({ ...rule }));
  deviceSerial++;
  device.value = null;
}
const date = (t: number, full = false) =>
  t > 0
    ? new Intl.DateTimeFormat(
        "zh-CN",
        full
          ? { dateStyle: "medium", timeStyle: "short" }
          : { month: "numeric", day: "numeric" },
      ).format(t * 1000)
    : "尚未同步";
const bytes = (n: number) =>
  n > 1048576
    ? (n / 1048576).toFixed(1) + " MB"
    : Math.max(1, Math.round(n / 1024)) + " KB";
async function openMessage(m: Message) {
  selected.value = m.id;
  detail.value = null;
  detailError.value = "";
  loadingDetail.value = true;
  detailAbort?.abort();
  const controller = new AbortController();
  detailAbort = controller;
  try {
    const data = await api(
      "message?id=" + encodeURIComponent(m.id),
      undefined,
      controller.signal,
    );
    if (selected.value === m.id) detail.value = data;
    if (!m.read) {
      await api("message/flags", { id: m.id, read: true });
      m.read = true;
    }
  } catch (e) {
    if (!controller.signal.aborted && selected.value === m.id)
      detailError.value = e instanceof Error ? e.message : "正文加载失败";
  } finally {
    if (selected.value === m.id) loadingDetail.value = false;
  }
}
async function flag(m: Message, name: "read" | "starred") {
  await task(async () => {
    await api("message/flags", { id: m.id, [name]: !m[name] });
    m[name] = !m[name];
  });
}
function back() {
  selected.value = "";
  detailAbort?.abort();
  detail.value = null;
}
const accountDialog = ref<HTMLDialogElement>();
const accountForm = reactive({
  id: "",
  name: "",
  provider: "qq",
  email: "",
  enabled: true,
  password: "",
  clientId: "",
});
function editAccount(acc?: Account) {
  Object.assign(
    accountForm,
    acc
      ? {
          id: acc.id,
          name: acc.name,
          provider: acc.provider,
          email: acc.email,
          enabled: acc.enabled,
          password: "",
          clientId: acc.clientId,
        }
      : {
          id: "",
          name: "",
          provider: "qq",
          email: "",
          enabled: true,
          password: "",
          clientId: "",
        },
  );
  accountDialog.value?.showModal();
}
async function saveAccount() {
  await task(async () => {
    await api("account", { ...accountForm });
    accountForm.password = "";
    accountDialog.value?.close();
    await reload();
    notice("邮箱已保存；首次同步只建立索引，不推送历史邮件");
  });
}
async function testAccount() {
  await task(async () => {
    const result = await api("account/test", { ...accountForm });
    notice(result.message);
  });
}
async function removeAccount(acc: Account) {
  if (!confirm(`断开“${acc.name}”？本地邮件索引会移除，原邮箱不受影响。`))
    return;
  await task(async () => {
    await api("account/delete", { id: acc.id });
    await reload();
    notice("邮箱已断开");
  });
}
async function sync(acc: Account) {
  await task(async () => {
    await api("sync", { id: acc.id });
    await reload();
    notice("同步已开始");
  });
}
const device = ref<{
  id: string;
  code: string;
  url: string;
  interval: number;
  expires: number;
  accountId: string;
} | null>(null);
async function authorize(acc: Account) {
  await task(async () => {
    const result = await api("outlook/start", { id: acc.id });
    device.value = { ...result, accountId: acc.id };
    const serial = ++deviceSerial;
    void pollDevice(serial);
  });
}
async function pollDevice(serial: number) {
  const d = device.value;
  if (!d) return;
  const end = Date.now() + d.expires * 1000;
  while (serial === deviceSerial && Date.now() < end && session.authenticated) {
    await new Promise((resolve) => setTimeout(resolve, d.interval * 1000));
    if (serial !== deviceSerial) return;
    try {
      const r = await api("outlook/poll", { id: d.id });
      if (r.status === "authorized") {
        device.value = null;
        await reload();
        notice("微软邮箱授权成功");
        return;
      }
    } catch (e) {
      if (serial === deviceSerial)
        notice(e instanceof Error ? e.message : "授权失败", true);
      return;
    }
  }
  if (serial === deviceSerial) {
    device.value = null;
    notice("微软授权已过期，请重试", true);
  }
}
const channelForm = reactive({
  telegramEnabled: false,
  token: "",
  clearToken: false,
  webhookEnabled: false,
  webhookUrl: "",
  webhookSecret: "",
  clearWebhookSecret: false,
});
const binding = ref("");
async function saveChannels() {
  await task(async () => {
    await api("channels", { ...channelForm });
    channelForm.token = "";
    channelForm.webhookSecret = "";
    channelForm.clearToken = false;
    channelForm.clearWebhookSecret = false;
    binding.value = "";
    await reload();
    notice("通知设置已保存");
  });
}
async function makeBinding() {
  await task(async () => {
    const r = await api("telegram/bind", {});
    binding.value = r.command;
    notice("绑定码5分钟有效，请私聊机器人发送完整指令");
  });
}
async function unbind() {
  if (!confirm("解除当前Telegram管理员绑定？")) return;
  await task(async () => {
    await api("telegram/unbind", {});
    binding.value = "";
    await reload();
  });
}
async function testWebhook() {
  await task(async () => {
    const r = await api("webhook/test", { ...channelForm });
    notice(r.message);
  });
}
const rulesForm = ref<Rule[]>([]);
function addRule() {
  rulesForm.value.push({
    id: "",
    name: "新邮件提醒",
    enabled: true,
    accountId: "",
    sender: "",
    keyword: "",
    mode: "summary",
    telegram: true,
    webhook: false,
  });
}
async function saveRules() {
  await task(async () => {
    await api("rules", { rules: rulesForm.value });
    await reload();
    rulesForm.value = state.rules.map((rule) => ({ ...rule }));
    notice("推送规则已保存，仅影响后续新邮件");
  });
}
const backupPassword = ref(""),
  backupFile = ref<File | null>(null),
  backupInput = ref<HTMLInputElement>();
async function downloadBackup() {
  await task(async () => {
    const r = await fetch("/api/backup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": session.csrf,
      },
      body: JSON.stringify({ password: backupPassword.value }),
    });
    if (!r.ok) {
      const e = await r.json();
      throw Error(e.error || "备份失败");
    }
    const url = URL.createObjectURL(await r.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download =
      "mail-harbor-" + new Date().toISOString().slice(0, 10) + ".mhbackup";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    backupPassword.value = "";
    notice("加密备份已下载，请妥善保存备份密码");
  });
}
async function restore() {
  if (!backupFile.value) {
    notice("请选择备份包", true);
    return;
  }
  if (
    !confirm(
      "恢复将替换当前邮箱配置、规则和本地索引，并使现有登录失效。确认继续？",
    )
  )
    return;
  await task(async () => {
    const file = backupFile.value!;
    if (file.size > 20 * 1024 * 1024) throw Error("备份包不能超过20MB");
    const data = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(",")[1]);
      reader.onerror = () => reject(Error("备份文件读取失败"));
      reader.readAsDataURL(file);
    });
    await api("restore", { password: backupPassword.value, data });
    backupPassword.value = "";
    session.authenticated = false;
    session.csrf = "";
    selected.value = "";
    detail.value = null;
    deviceSerial++;
    notice("备份已恢复，请使用备份中的管理账户重新登录");
  });
}
const security = reactive({ current: "", username: "", password: "" });
async function changePassword() {
  await task(async () => {
    await api("security", { ...security });
    security.current = "";
    security.password = "";
    session.authenticated = false;
    session.csrf = "";
    notice("管理密码已修改，旧登录已失效，请重新登录");
  });
}
onMounted(async () => {
  try {
    const saved = localStorage.getItem("mail-harbor.theme");
    if (saved === "dark" || saved === "light") theme.value = saved;
    else if (matchMedia("(prefers-color-scheme: dark)").matches)
      theme.value = "dark";
  } catch {}
  applyTheme();
  try {
    await refreshSession();
  } catch (e) {
    session.ready = true;
    notice("服务暂时不可用，请刷新后重试", true);
  }
  refreshTimer = setInterval(() => {
    void reload().catch((e) => {
      if (session.authenticated) notice(e.message, true);
    });
  }, 10000);
});
onUnmounted(() => {
  clearInterval(refreshTimer);
  clearTimeout(toastTimer);
  detailAbort?.abort();
  deviceSerial++;
});
</script>

<template>
  <div v-if="!session.ready" class="startup">正在打开邮屿…</div>
  <div v-else-if="!session.authenticated" class="auth-layout">
    <header class="auth-header">
      <a href="/" class="brand"
        ><span class="brand-mark"
          ><PhEnvelopeSimple :size="25" weight="duotone" /></span
        ><b>邮屿</b></a
      ><button
        class="icon-button"
        aria-label="切换主题"
        @click="
          theme = theme === 'light' ? 'dark' : 'light';
          applyTheme();
        "
      >
        <component :is="theme === 'light' ? PhMoon : PhSun" :size="20" />
      </button>
    </header>
    <form class="login-card" @submit.prevent="login">
      <h1>{{ session.configured ? "欢迎回来" : "添加管理账户" }}</h1>
      <p>
        {{
          session.configured
            ? "登录以查看邮件。"
            : "设置管理账户，然后添加你的邮箱。"
        }}
      </p>
      <label
        >管理账号<input
          v-model="credentials.username"
          autocomplete="username"
          maxlength="64"
          required /></label
      ><label
        >{{ session.configured ? "登录密码" : "设置管理密码"
        }}<input
          v-model="credentials.password"
          type="password"
          :autocomplete="
            session.configured ? 'current-password' : 'new-password'
          "
          :minlength="session.configured ? 1 : 12"
          maxlength="256"
          required /></label
      ><small v-if="!session.configured" class="muted"
        >至少12个字符。邮箱授权在创建账户后配置。</small
      ><button class="primary full" :disabled="working">
        {{ working ? "请稍候…" : session.configured ? "登录" : "创建并进入" }}
      </button>
    </form>
    <footer class="auth-footer">
      邮屿<span>Mail Harbor · MIT License</span>
    </footer>
  </div>
  <div v-else class="app-shell">
    <button
      v-if="navOpen"
      class="nav-overlay"
      aria-label="收起导航"
      @click="navOpen = false"
    ></button>
    <aside class="sidebar" :class="{ open: navOpen }">
      <a href="/" class="brand" @click.prevent="navigate('inbox')"
        ><span class="brand-mark"
          ><PhEnvelopeSimple :size="25" weight="duotone" /></span
        ><b>邮屿</b></a
      >
      <button class="compose primary" @click="editAccount()">
        <PhPlus :size="18" />添加账户
      </button>
      <nav aria-label="邮件导航">
        <button
          :class="{ active: page === 'inbox' && filter === 'all' }"
          @click="navigate('inbox')"
        >
          <PhTray :size="20" /><span>全部收件箱</span
          ><small v-if="totalUnread">{{ totalUnread }}</small></button
        ><button
          :class="{ active: page === 'inbox' && filter === 'unread' }"
          @click="navigate('inbox', 'unread')"
        >
          <PhEnvelopeSimple :size="20" /><span>未读邮件</span></button
        ><button
          :class="{ active: page === 'inbox' && filter === 'starred' }"
          @click="navigate('inbox', 'starred')"
        >
          <PhStar :size="20" /><span>星标邮件</span>
        </button>
      </nav>
      <div class="nav-label">
        我的邮箱<span>{{ state.accounts.length }}</span>
      </div>
      <nav aria-label="邮箱账户">
        <button
          v-for="acc in state.accounts"
          :key="acc.id"
          :class="{ active: page === 'inbox' && filter === acc.id }"
          @click="navigate('inbox', acc.id)"
        >
          <i
            class="account-dot"
            :style="{ background: provider(acc.provider).color }"
          ></i
          ><span>{{ acc.name }}</span
          ><small v-if="unread(acc.id)">{{ unread(acc.id) }}</small>
        </button>
        <p v-if="!state.accounts.length" class="nav-empty">还没有添加账户</p>
      </nav>
      <div class="nav-label settings-label">管理设置</div>
      <nav aria-label="管理设置">
        <button
          v-for="item in pages"
          :key="item.id"
          :class="{ active: page === item.id }"
          @click="
            navigate(item.id);
            if (item.id === 'security') security.username = session.username;
          "
        >
          <component :is="item.icon" :size="19" /><span>{{ item.name }}</span>
        </button>
      </nav>
      <div class="sidebar-bottom">
        <span class="avatar">{{
          session.username.slice(0, 1).toUpperCase()
        }}</span
        ><span>{{ session.username }}<small>管理员</small></span
        ><button
          class="icon-button"
          aria-label="退出登录"
          title="退出登录"
          @click="logout"
        >
          <PhSignOut :size="19" />
        </button>
      </div>
    </aside>
    <div class="main-shell">
      <header class="topbar">
        <div class="topbar-title">
          <button
            class="icon-button menu-toggle"
            aria-label="打开导航"
            @click="navOpen = true"
          >
            <PhList :size="23" /></button
          ><span>{{ pageTitle }}</span>
        </div>
        <div class="topbar-actions">
          <button
            class="icon-button"
            aria-label="切换主题"
            @click="
              theme = theme === 'light' ? 'dark' : 'light';
              applyTheme();
            "
          >
            <component :is="theme === 'light' ? PhMoon : PhSun" :size="19" />
          </button>
        </div>
      </header>
      <main
        v-if="page === 'inbox'"
        class="inbox-layout"
        :class="{ 'show-reader': !!selected }"
      >
        <section class="message-list" aria-label="邮件列表">
          <div class="list-heading">
            <div>
              <h1>{{ title }}</h1>
              <p>
                {{ visible.length }} 封邮件<span v-if="totalUnread">
                  · {{ totalUnread }} 封未读</span
                >
              </p>
            </div>
            <button
              class="icon-button"
              aria-label="刷新邮件索引"
              @click="task(reload)"
            >
              <PhArrowClockwise :size="19" />
            </button>
          </div>
          <label class="search-field"
            ><PhMagnifyingGlass :size="18" /><input
              v-model="query"
              type="search"
              aria-label="搜索邮件"
              placeholder="搜索发件人、主题…"
          /></label>
          <div class="list-caption">
            <span>{{ query ? "搜索结果" : "最近来信" }}</span
            ><span>按时间排序 <PhArrowDown :size="12" /></span>
          </div>
          <div class="message-scroll">
            <button
              v-for="m in visible"
              :key="m.id"
              class="message-item"
              :class="{ selected: selected === m.id, unread: !m.read }"
              @click="openMessage(m)"
            >
              <div class="message-sender">
                <i class="unread-dot" :class="{ visible: !m.read }"></i
                ><strong>{{ m.from || m.sender || "未知发件人" }}</strong
                ><time>{{ date(m.date) }}</time>
              </div>
              <h2>{{ m.subject || "（无主题）" }}</h2>
              <p>{{ m.preview || m.sender }}</p>
              <div class="message-meta">
                <span
                  ><i
                    class="account-dot"
                    :style="{
                      background: provider(account(m.accountId)?.provider || '')
                        .color,
                    }"
                  ></i
                  >{{ account(m.accountId)?.name }}</span
                ><PhStar
                  v-if="m.starred"
                  :size="14"
                  weight="fill"
                /><PhPaperclip v-if="m.attachments" :size="14" />
              </div>
            </button>
            <div v-if="!visible.length" class="list-empty">
              <PhTray :size="32" weight="thin" />
              <h3>
                {{
                  query
                    ? "没有匹配的邮件"
                    : state.accounts.length
                      ? "没有邮件"
                      : "没有邮件"
                }}
              </h3>
              <p>
                {{
                  query
                    ? "换一个关键词试试。"
                    : state.accounts.length
                      ? "完成邮箱授权并同步后，来信会显示在这里。"
                      : "接入第一个邮箱，把来信收在一起。"
                }}
              </p>
              <button
                v-if="!state.accounts.length"
                class="text-button"
                @click="editAccount()"
              >
                添加账户 <PhCaretRight :size="14" />
              </button>
            </div>
          </div>
          <div class="list-footer">
            <span><i class="live-dot"></i>索引自动更新</span
            ><small>已读与星标仅保存在本站</small>
          </div>
        </section>
        <section class="reader" aria-label="邮件详情">
          <template v-if="current"
            ><div class="reader-toolbar">
              <button
                class="icon-button reader-back"
                aria-label="返回邮件列表"
                @click="back"
              >
                <PhArrowLeft :size="20" /></button
              ><span class="mailbox-label">{{
                account(current.accountId)?.name
              }}</span>
              <div>
                <button
                  class="icon-button"
                  :class="{ starred: current.starred }"
                  :aria-label="current.starred ? '取消星标' : '添加星标'"
                  @click="flag(current, 'starred')"
                >
                  <PhStar
                    :size="20"
                    :weight="current.starred ? 'fill' : 'regular'"
                  /></button
                ><button
                  class="icon-button"
                  :aria-label="current.read ? '标记未读' : '标记已读'"
                  @click="flag(current, 'read')"
                >
                  <PhEnvelopeSimple :size="20" /></button
                ><button
                  class="icon-button"
                  aria-label="重新加载正文"
                  @click="openMessage(current)"
                >
                  <PhArrowClockwise :size="19" />
                </button>
              </div>
            </div>
            <article class="mail-content">
              <h1>{{ current.subject || "（无主题）" }}</h1>
              <div class="sender-block">
                <span class="sender-avatar">{{
                  (current.from || current.sender || "?")
                    .slice(0, 1)
                    .toUpperCase()
                }}</span>
                <div>
                  <b>{{ current.from || current.sender }}</b
                  ><small>{{ current.sender }}</small
                  ><small
                    >收件邮箱 {{ account(current.accountId)?.email }}</small
                  >
                </div>
                <time>{{ date(current.date, true) }}</time>
              </div>
              <p v-if="loadingDetail" class="body-loading">
                正在从原邮箱读取正文…
              </p>
              <div v-else-if="detailError" class="error-box">
                <PhWarningCircle :size="23" />
                <p>{{ detailError }}</p>
                <button @click="openMessage(current)">重新加载</button>
              </div>
              <template v-else-if="detail"
                ><div class="mail-text">
                  {{ detail.text || "这封邮件没有可显示的正文。" }}
                </div>
                <section v-if="detail.attachments.length" class="attachments">
                  <h3>
                    <PhPaperclip :size="17" />附件 ·
                    {{ detail.attachments.length }}
                  </h3>
                  <a
                    v-for="att in detail.attachments"
                    :key="att.index"
                    :href="
                      '/api/attachment?id=' +
                      encodeURIComponent(current.id) +
                      '&part=' +
                      att.index
                    "
                    download
                    ><PhDownloadSimple :size="19" /><span
                      >{{ att.name }}<small>{{ bytes(att.size) }}</small></span
                    ></a
                  >
                </section>
                <p class="privacy-note">
                  <PhShieldCheck
                    :size="15"
                  />以纯文本显示，未加载邮件中的远程图片或脚本。
                </p></template
              >
            </article></template
          >
          <div v-else class="reader-empty">
            <PhEnvelopeSimple :size="48" weight="thin" />
            <h2>未选择邮件</h2>
          </div>
        </section>
      </main>
      <main v-else class="settings-content">
        <div class="page-heading">
          <h1>{{ pageTitle }}</h1>
          <p>
            {{
              page === "accounts"
                ? "连接你常用的邮箱。新邮件由服务器持续检查，网页关闭后也能收到通知。"
                : page === "channels"
                  ? "把重要来信送到你常用的地方。"
                  : page === "rules"
                    ? "决定哪些邮件需要提醒，以及推送多少内容。"
                    : page === "backup"
                      ? "把配置和同步进度一起带走，在新部署中继续使用。"
                      : page === "security"
                        ? "管理这个私人邮件空间的登录账户。"
                        : "查看同步和通知的最近运行情况。"
            }}
          </p>
        </div>
        <template v-if="page === 'accounts'"
          ><div class="section-actions">
            <span>{{ state.accounts.length }} / 20 个邮箱</span
            ><button class="primary" @click="editAccount()">
              <PhPlus :size="17" />添加账户
            </button>
          </div>
          <div v-if="!state.accounts.length" class="settings-card empty-card">
            <PhEnvelopeSimple :size="36" weight="thin" />
            <h2>添加邮箱账户</h2>
            <p>
              支持 QQ、163、Gmail 和 Outlook。接入后先建立索引，再开始通知。
            </p>
            <button @click="editAccount()">选择邮箱提供商</button>
          </div>
          <section
            v-for="acc in state.accounts"
            :key="acc.id"
            class="settings-card account-card"
          >
            <div class="account-card-heading">
              <span
                class="provider-tile"
                :style="{ color: provider(acc.provider).color }"
                >{{ provider(acc.provider).label }}</span
              >
              <div>
                <h2>{{ acc.name }}</h2>
                <p>{{ acc.email }}</p>
              </div>
              <span
                class="status-pill"
                :class="{
                  error: acc.lastError && !state.busy.includes(acc.id),
                }"
                ><i></i
                >{{
                  !acc.enabled
                    ? "已暂停"
                    : state.busy.includes(acc.id)
                      ? "同步中"
                      : !acc.authorized
                        ? "待授权"
                        : acc.lastError
                          ? "需要处理"
                          : acc.initialized
                            ? "已连接"
                            : "待首次同步"
                }}</span
              >
            </div>
            <p v-if="acc.lastError" class="inline-error">{{ acc.lastError }}</p>
            <div class="account-bottom">
              <small>最近检查：{{ date(acc.lastSync, true) }}</small>
              <div>
                <button
                  v-if="acc.provider === 'outlook'"
                  @click="authorize(acc)"
                  :disabled="working"
                >
                  {{ acc.authorized ? "重新授权" : "连接微软账户" }}</button
                ><button
                  :disabled="
                    working ||
                    !acc.enabled ||
                    !acc.authorized ||
                    state.busy.includes(acc.id)
                  "
                  @click="sync(acc)"
                >
                  <PhArrowClockwise :size="15" />同步</button
                ><button :disabled="working" @click="editAccount(acc)">
                  编辑</button
                ><button
                  class="danger text-button"
                  :disabled="working"
                  @click="removeAccount(acc)"
                >
                  断开
                </button>
              </div>
            </div>
            <div v-if="device?.accountId === acc.id" class="binding-box">
              <p>在微软页面输入下方代码，并登录此邮箱。</p>
              <code>{{ device.code }}</code
              ><a
                class="button primary"
                :href="device.url"
                target="_blank"
                rel="noopener noreferrer"
                >打开微软授权页面</a
              ><small>等待授权完成…请保持此页面打开。</small>
            </div>
          </section>
          <p class="footnote">
            首轮索引：IMAP 最近30封，Outlook
            最近7天。默认每分钟检查新邮件；不下载整库附件，不推送接入前的历史邮件。
          </p></template
        >
        <template v-if="page === 'channels'"
          ><section class="settings-card">
            <div class="card-heading">
              <span class="channel-icon"><PhTelegramLogo :size="23" /></span>
              <div>
                <h2>Telegram 机器人</h2>
                <p>
                  使用长轮询，无需公网回调地址。一个机器人只供一个部署使用。
                </p>
              </div>
            </div>
            <label class="check-label"
              ><input
                v-model="channelForm.telegramEnabled"
                type="checkbox"
              />开启 Telegram 机器人</label
            ><label
              >Bot Token<input
                v-model="channelForm.token"
                type="password"
                autocomplete="new-password"
                :placeholder="
                  state.channels.hasToken
                    ? 'Token 已保存，留空保留'
                    : '从 BotFather 获取机器人 Token'
                "
            /></label>
            <p class="field-help">
              在 Telegram 的
              <a
                href="https://t.me/BotFather"
                target="_blank"
                rel="noopener noreferrer"
                >BotFather</a
              >
              创建专用机器人。保存后不会回显 Token，同时创建机器人菜单。
            </p>
            <button class="primary" :disabled="working" @click="saveChannels">
              保存设置
            </button>
            <div class="subsection">
              <h3>连接与管理员绑定</h3>
              <p class="field-help">
                {{
                  state.channels.botName
                    ? "已连接 @" + state.channels.botName
                    : "先填写 Token 并保存，再生成绑定码。"
                }}
                用自己的 Telegram 账户私聊机器人，发送生成的完整指令。
              </p>
              <div v-if="state.channels.chatId" class="bound-row">
                <span><PhCheck :size="17" />管理员已绑定</span
                ><button class="danger" :disabled="working" @click="unbind">
                  解除绑定
                </button>
              </div>
              <button
                v-else
                :disabled="
                  working ||
                  !state.channels.telegramEnabled ||
                  !state.channels.hasToken
                "
                @click="makeBinding"
              >
                生成绑定码
              </button>
              <div v-if="binding" class="binding-box">
                <code>{{ binding }}</code
                ><small
                  >5分钟内有效，仅可使用一次。重新生成会使旧码失效。</small
                >
              </div>
            </div>
            <div class="subsection">
              <h3>机器人指令</h3>
              <dl class="commands">
                <dt>/help</dt>
                <dd>查看使用说明</dd>
                <dt>/status</dt>
                <dd>查看邮箱连接数量</dd>
              </dl>
              <p class="field-help">
                绑定成功后，按“推送规则”发送新邮件。默认不向未绑定用户或群聊提供邮件信息。
              </p>
            </div>
            <button
              v-if="state.channels.hasToken"
              class="danger text-button"
              :disabled="working"
              @click="
                channelForm.clearToken = true;
                saveChannels();
              "
            >
              删除 Token 并关闭机器人
            </button>
          </section>
          <section class="settings-card">
            <div class="card-heading">
              <span class="channel-icon"><PhLink :size="23" /></span>
              <div>
                <h2>Webhook 回调</h2>
                <p>向你指定的服务发送统一 JSON 通知。</p>
              </div>
            </div>
            <label class="check-label"
              ><input
                v-model="channelForm.webhookEnabled"
                type="checkbox"
              />开启 Webhook</label
            ><label
              >回调地址<input
                v-model="channelForm.webhookUrl"
                type="url"
                placeholder="https://example.com/hooks/mail" /></label
            ><label
              >签名密钥 <small>可选</small
              ><input
                v-model="channelForm.webhookSecret"
                type="password"
                autocomplete="new-password"
                :placeholder="
                  state.channels.hasWebhookSecret
                    ? '签名密钥已保存，留空保留'
                    : '用于 HMAC-SHA256 请求签名'
                "
            /></label>
            <p class="field-help">
              固定发送 POST JSON。带有事件类型、投递
              ID、邮箱名称和规则允许的内容；测试使用当前表单，不会保存配置。
            </p>
            <label v-if="state.channels.hasWebhookSecret" class="check-label"
              ><input
                v-model="channelForm.clearWebhookSecret"
                type="checkbox"
              />移除已保存的签名密钥</label
            >
            <div class="button-row">
              <button class="primary" :disabled="working" @click="saveChannels">
                保存设置</button
              ><button
                :disabled="working || !channelForm.webhookUrl"
                @click="testWebhook"
              >
                测试当前地址
              </button>
            </div>
          </section></template
        >
        <template v-if="page === 'rules'"
          ><div class="section-actions">
            <span>新邮件匹配规则后推送，多条规则可同时生效。</span
            ><button @click="addRule"><PhPlus :size="17" />添加规则</button>
          </div>
          <div v-if="!rulesForm.length" class="settings-card empty-card">
            <PhBell :size="34" weight="thin" />
            <h2>尚未添加规则</h2>
            <p>添加一条规则，选择邮箱、通知渠道和内容范围。</p>
            <button @click="addRule">创建第一条规则</button>
          </div>
          <section
            v-for="(rule, index) in rulesForm"
            :key="index"
            class="settings-card"
          >
            <div class="rule-heading">
              <label class="check-label"
                ><input
                  v-model="rule.enabled"
                  type="checkbox"
                />启用这条规则</label
              ><button
                class="text-button danger"
                @click="rulesForm.splice(index, 1)"
              >
                删除
              </button>
            </div>
            <label>规则名称<input v-model="rule.name" maxlength="80" /></label>
            <div class="form-grid">
              <label
                >适用邮箱<select v-model="rule.accountId">
                  <option value="">全部邮箱</option>
                  <option
                    v-for="acc in state.accounts"
                    :key="acc.id"
                    :value="acc.id"
                  >
                    {{ acc.name }}
                  </option>
                </select></label
              ><label
                >推送内容<select v-model="rule.mode">
                  <option value="notice">仅提醒有新邮件</option>
                  <option value="summary">发件人、标题与摘要</option>
                  <option value="body">发件人、标题与正文</option>
                </select></label
              ><label
                >发件人包含 <small>可选</small
                ><input
                  v-model="rule.sender"
                  placeholder="例如 @example.com"
                  maxlength="200" /></label
              ><label
                >标题 / 可用摘要包含 <small>可选</small
                ><input
                  v-model="rule.keyword"
                  placeholder="留空匹配全部"
                  maxlength="200"
              /></label>
            </div>
            <div class="channel-options">
              <span>通知到</span
              ><label class="check-label"
                ><input
                  v-model="rule.telegram"
                  type="checkbox"
                />Telegram</label
              ><label class="check-label"
                ><input v-model="rule.webhook" type="checkbox" />Webhook</label
              >
            </div>
          </section>
          <div class="settings-card compact-card">
            <div class="button-row">
              <button class="primary" :disabled="working" @click="saveRules">
                保存推送规则</button
              ><small class="muted"
                >正文过长时按通道上限截断，附件请在收件箱下载。</small
              >
            </div>
          </div></template
        >
        <template v-if="page === 'backup'"
          ><section class="settings-card">
            <h2>加密备份</h2>
            <p>
              包含管理账户、邮箱授权、通知设置、规则、邮件索引、同步进度和待发通知。在其他部署导入后可以继续使用。
            </p>
            <label
              >备份密码<input
                v-model="backupPassword"
                type="password"
                autocomplete="new-password"
                minlength="12"
                placeholder="至少12个字符，用于加密或解密备份包"
            /></label>
            <p class="field-help">
              备份密码无法找回。邮件正文和附件保存在原邮箱，不包含在备份中；恢复后仍需原邮箱授权有效。
            </p>
            <button
              class="primary"
              :disabled="working || backupPassword.length < 12"
              @click="downloadBackup"
            >
              <PhDownloadSimple :size="18" />下载加密备份
            </button>
            <div class="subsection">
              <h3>恢复备份</h3>
              <p class="field-help">
                选择 .mhbackup
                文件并填写该备份的密码。恢复前会再次确认，不会修改原邮箱。
              </p>
              <input
                ref="backupInput"
                class="hidden-file"
                type="file"
                accept=".mhbackup"
                @change="
                  backupFile =
                    ($event.target as HTMLInputElement).files?.[0] || null
                "
              />
              <div class="file-picker">
                <span
                  ><PhArchive :size="23" /><span
                    >{{ backupFile?.name || "尚未选择备份包"
                    }}<small>{{
                      backupFile
                        ? bytes(backupFile.size)
                        : "仅支持邮屿加密备份，最大20MB"
                    }}</small></span
                  ></span
                ><button :disabled="working" @click="backupInput?.click()">
                  选择备份包
                </button>
              </div>
              <button
                :disabled="working || !backupFile || backupPassword.length < 12"
                @click="restore"
              >
                <PhUploadSimple :size="18" />{{
                  working ? "正在处理…" : "导入并恢复"
                }}
              </button>
            </div>
          </section></template
        >
        <template v-if="page === 'events'"
          ><div class="metrics">
            <div>
              <small>已发送</small><strong>{{ state.jobs.sent }}</strong>
            </div>
            <div>
              <small>等待投递</small><strong>{{ state.jobs.pending }}</strong>
            </div>
            <div>
              <small>需要处理</small><strong>{{ state.jobs.failed }}</strong>
            </div>
          </div>
          <section class="settings-card">
            <div class="section-actions">
              <h2>最近运行记录</h2>
              <button
                v-if="state.jobs.failed"
                :disabled="working"
                @click="
                  task(async () => {
                    await api('jobs/retry', {});
                    await reload();
                    notice('失败通知已重新加入队列');
                  })
                "
              >
                重试失败通知
              </button>
            </div>
            <p v-if="!state.events.length" class="muted">还没有运行记录。</p>
            <div
              v-for="(event, index) in [...state.events].reverse()"
              :key="index"
              class="event-row"
            >
              <span
                class="event-dot"
                :class="{ error: event.kind === 'error' }"
              ></span
              ><span>{{ event.text }}</span
              ><time>{{ date(event.time, true) }}</time>
            </div>
            <p class="field-help">
              保留最近150条运行记录，不记录授权码、Token 或正文。
            </p>
          </section></template
        >
        <form
          v-if="page === 'security'"
          class="settings-card"
          @submit.prevent="changePassword"
        >
          <h2>修改管理账户</h2>
          <p>修改成功后，所有设备的旧登录立即失效。</p>
          <label
            >当前密码<input
              v-model="security.current"
              type="password"
              autocomplete="current-password"
              required /></label
          ><label
            >管理账号<input
              v-model="security.username"
              autocomplete="username"
              maxlength="64"
              required /></label
          ><label
            >新密码<input
              v-model="security.password"
              type="password"
              autocomplete="new-password"
              minlength="12"
              maxlength="256"
              required /></label
          ><button class="primary" :disabled="working">保存并重新登录</button>
        </form>
        <footer class="settings-footer">
          邮屿 · Mail Harbor {{ session.version }}<span>MIT License</span>
        </footer>
      </main>
    </div>
  </div>
  <dialog
    ref="accountDialog"
    class="account-dialog"
    @click="
      ($event) => {
        if ($event.target === accountDialog && !working) accountDialog?.close();
      }
    "
  >
    <form @submit.prevent="saveAccount">
      <div class="dialog-heading">
        <div>
          <h2>{{ accountForm.id ? "编辑邮箱" : "添加账户" }}</h2>
          <p>连接原邮箱，邮件仍留在原来的地方。</p>
        </div>
        <button
          type="button"
          class="icon-button"
          aria-label="关闭邮箱配置"
          :disabled="working"
          @click="accountDialog?.close()"
        >
          <PhX :size="20" />
        </button>
      </div>
      <div class="provider-options">
        <button
          v-for="p in providers"
          :key="p.id"
          type="button"
          :disabled="!!accountForm.id"
          :class="{ chosen: accountForm.provider === p.id }"
          @click="accountForm.provider = p.id"
        >
          <span :style="{ color: p.color }">{{ p.label }}</span
          >{{ p.name }}
        </button>
      </div>
      <div class="provider-help">{{ provider(accountForm.provider).help }}</div>
      <div class="form-grid">
        <label
          >显示名称<input
            v-model="accountForm.name"
            maxlength="60"
            placeholder="例如 工作邮箱"
            required /></label
        ><label
          >邮箱地址<input
            v-model="accountForm.email"
            type="email"
            :readonly="!!accountForm.id"
            placeholder="name@example.com"
            required
        /></label>
      </div>
      <label v-if="accountForm.provider === 'outlook'"
        >应用 Client ID<input
          v-model="accountForm.clientId"
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          required /></label
      ><label v-else
        >{{ accountForm.provider === "gmail" ? "应用专用密码" : "客户端授权码"
        }}<input
          v-model="accountForm.password"
          type="password"
          autocomplete="new-password"
          :required="!accountForm.id"
          :placeholder="
            accountForm.id ? '已保存，留空保留' : '请勿填写邮箱普通登录密码'
          " /></label
      ><label class="check-label"
        ><input
          v-model="accountForm.enabled"
          type="checkbox"
        />启用自动收信</label
      >
      <div class="dialog-footer">
        <button
          v-if="accountForm.provider !== 'outlook'"
          type="button"
          :disabled="working"
          @click="testAccount"
        >
          测试当前配置</button
        ><button class="primary" :disabled="working">
          {{ working ? "正在处理…" : "保存邮箱" }}
        </button>
      </div>
    </form>
  </dialog>
  <div v-if="toast" role="status" class="toast" :class="{ error: toastError }">
    <component
      :is="toastError ? PhWarningCircle : PhCheck"
      :size="19"
    /><span>{{ toast }}</span
    ><button aria-label="关闭提示" @click="toast = ''">
      <PhX :size="16" />
    </button>
  </div>
</template>
