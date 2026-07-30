import { PublicClientApplication, type AccountInfo } from '@azure/msal-browser'
import { analyze, LEVEL_META, SEV_META, domainOf, type Analysis, type MailInput } from './analyzer'

// ─── Config ───────────────────────────────────────────────────────────────────
// ใช้ App registration เดียวกับแอดอิน Helpdesk → ผู้ใช้ไม่ต้อง consent ใหม่
const CLIENT_ID = '0bab07cf-65e6-487c-89af-c917fc1a5a13'
const TENANT_ID = 'd569b991-89fc-4a62-9df5-eb361abcef40'
const SHAREPOINT_URL = 'https://rpaexpert.sharepoint.com/sites/iTServicesCo.Ltd'
const SP_SCOPE = 'https://rpaexpert.sharepoint.com/.default'
// ขอสิทธิ์เท่าที่ต้องใช้จริง: อ่าน header + ดึงไฟล์ .eml เป็นหลักฐาน
const GRAPH_SCOPES = ['https://graph.microsoft.com/Mail.Read']

const REPORT_LIST = 'HD_PhishingReports'
// โดเมนขององค์กร (ใช้ตรวจโดเมนเลียนแบบ / การปลอมเป็นคนใน)
const INTERNAL_DOMAINS = ['itservices.co.th', 'rpaexpert.com', 'rpaexpert.onmicrosoft.com']

const BASE = window.location.origin.includes('localhost')
  ? window.location.origin + '/'
  : 'https://darmmunginsa.github.io/itservices-phishguard/'

// ─── MSAL ─────────────────────────────────────────────────────────────────────
const msalInstance = new PublicClientApplication({
  auth: {
    clientId: CLIENT_ID,
    authority: `https://login.microsoftonline.com/${TENANT_ID}`,
    redirectUri: BASE,
    navigateToLoginRequestUrl: false,
  },
  // localStorage = แชร์ token กับ auth dialog (same origin) → มือถือ login ผ่าน dialog ได้
  cache: { cacheLocation: 'localStorage', storeAuthStateInCookie: false },
})

const AUTH_DIALOG_URL = `${BASE}auth.html`

function isMobilePlatform(): boolean {
  const p = Office.context?.diagnostics?.platform
  return p === Office.PlatformType.iOS || p === Office.PlatformType.Android
}

// Outlook มือถือใช้ popup ไม่ได้ → auth ผ่าน Office Dialog API
function openAuthDialog(): Promise<void> {
  return new Promise((resolve, reject) => {
    Office.context.ui.displayDialogAsync(AUTH_DIALOG_URL, { height: 60, width: 30, promptBeforeOpen: false }, res => {
      if (res.status !== Office.AsyncResultStatus.Succeeded) { reject(new Error('เปิดหน้าเข้าสู่ระบบไม่ได้')); return }
      const dlg = res.value
      dlg.addEventHandler(Office.EventType.DialogMessageReceived, arg => {
        dlg.close()
        const raw = (arg as { message?: string }).message
        if (!raw) { reject(new Error('auth message error')); return }
        try { const m = JSON.parse(raw); m.ok ? resolve() : reject(new Error(m.error || 'auth failed')) }
        catch { reject(new Error('auth message error')) }
      })
      dlg.addEventHandler(Office.EventType.DialogEventReceived, () => reject(new Error('ปิดหน้าเข้าสู่ระบบก่อนเสร็จ')))
    })
  })
}

async function getToken(): Promise<string> {
  const accounts = msalInstance.getAllAccounts()
  if (!accounts.length) throw new Error('Not signed in')
  const request = { scopes: [SP_SCOPE], account: accounts[0] }
  try { return (await msalInstance.acquireTokenSilent(request)).accessToken }
  catch {
    if (isMobilePlatform()) {
      await openAuthDialog()
      const acc = msalInstance.getAllAccounts()[0]
      if (!acc) throw new Error('เข้าสู่ระบบไม่สำเร็จ')
      return (await msalInstance.acquireTokenSilent({ scopes: [SP_SCOPE], account: acc })).accessToken
    }
    return (await msalInstance.acquireTokenPopup(request)).accessToken
  }
}

async function getGraphToken(): Promise<string> {
  const accounts = msalInstance.getAllAccounts()
  if (!accounts.length) throw new Error('Not signed in')
  const request = { scopes: GRAPH_SCOPES, account: accounts[0] }
  try { return (await msalInstance.acquireTokenSilent(request)).accessToken }
  catch {
    if (isMobilePlatform()) {
      await openAuthDialog()
      const acc = msalInstance.getAllAccounts()[0]
      if (!acc) throw new Error('เข้าสู่ระบบไม่สำเร็จ')
      return (await msalInstance.acquireTokenSilent({ scopes: GRAPH_SCOPES, account: acc })).accessToken
    }
    return (await msalInstance.acquireTokenPopup(request)).accessToken
  }
}

// ─── State ────────────────────────────────────────────────────────────────────
interface State {
  account: AccountInfo | null
  mail: MailInput | null
  analysis: Analysis | null
  loading: boolean
  reporting: boolean
  reported: boolean
  /** URL template ของ Kasm เช่น https://kasm.../#/cast/xxx?go=1&url={url} */
  kasmTemplate: string
  showHeaders: boolean
  headersLoaded: boolean
}
const state: State = {
  account: null, mail: null, analysis: null,
  loading: true, reporting: false, reported: false,
  kasmTemplate: '', showHeaders: false, headersLoaded: false,
}

// ─── UI helpers ───────────────────────────────────────────────────────────────
const esc = (s: string): string =>
  (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')

function showToast(msg: string, type: 'success' | 'error' | 'info' = 'success'): void {
  const box = document.getElementById('toast-container')
  if (!box) return
  const color = type === 'error' ? 'bg-red-600' : type === 'info' ? 'bg-slate-700' : 'bg-emerald-600'
  const el = document.createElement('div')
  el.className = `toast ${color} text-white text-xs px-3 py-2 rounded-lg shadow-lg pointer-events-auto max-w-[90%]`
  el.textContent = msg
  box.appendChild(el)
  setTimeout(() => el.remove(), 4000)
}

// ─── SharePoint ───────────────────────────────────────────────────────────────
async function spCreate(listTitle: string, body: Record<string, unknown>): Promise<number> {
  const token = await getToken()
  const url = `${SHAREPOINT_URL}/_api/web/lists/getbytitle('${encodeURIComponent(listTitle)}')/items`
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json;odata=nometadata',
      'Content-Type': 'application/json;odata=nometadata',
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`SharePoint ${res.status}: ${await res.text()}`)
  return ((await res.json()) as { Id: number }).Id
}

/** รายชื่อคนในองค์กร — ใช้ตรวจว่ามีการปลอมเป็นพนักงานเราไหม */
async function fetchInternalPeople(): Promise<{ name: string; email: string }[]> {
  try {
    const token = await getToken()
    const url = `${SHAREPOINT_URL}/_api/web/lists/getbytitle('HD_AgentProfiles')/items?$select=Title,EmailText&$top=500`
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json;odata=nometadata' } })
    if (!res.ok) return []
    const data = await res.json() as { value: { Title: string; EmailText?: string }[] }
    return data.value.filter(p => p.EmailText).map(p => ({ name: p.Title, email: p.EmailText! }))
  } catch { return [] }
}

/** URL template ของ Kasm (HD_Options: Category='KasmConfig', Title=template) */
async function fetchKasmTemplate(): Promise<string> {
  try {
    const token = await getToken()
    const url = `${SHAREPOINT_URL}/_api/web/lists/getbytitle('HD_Options')/items?$select=Title&$filter=Category eq 'KasmConfig'&$top=1`
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json;odata=nometadata' } })
    if (!res.ok) return ''
    const data = await res.json() as { value: { Title?: string }[] }
    return (data.value[0]?.Title ?? '').trim()
  } catch { return '' }
}

// ─── Mail reading ─────────────────────────────────────────────────────────────
const getBodyAsync = (type: Office.CoercionType): Promise<string> =>
  new Promise(resolve => {
    Office.context.mailbox.item?.body.getAsync(type, r =>
      resolve(r.status === Office.AsyncResultStatus.Succeeded ? (r.value ?? '') : ''))
  })

/** อ่าน header ต้นฉบับผ่าน Graph — ใช้ตรวจ SPF/DKIM/DMARC (ไม่ได้ก็ข้าม ไม่ error) */
async function fetchHeaders(): Promise<Record<string, string>> {
  try {
    const item = Office.context.mailbox.item
    if (!item?.itemId) return {}
    const restId = Office.context.mailbox.convertToRestId(item.itemId, Office.MailboxEnums.RestVersion.v2_0)
    const token = await getGraphToken()
    const res = await fetch(
      `https://graph.microsoft.com/v1.0/me/messages/${restId}?$select=internetMessageHeaders`,
      { headers: { Authorization: `Bearer ${token}` } })
    if (!res.ok) return {}
    const data = await res.json() as { internetMessageHeaders?: { name: string; value: string }[] }
    const out: Record<string, string> = {}
    // header ชื่อซ้ำได้ (เช่น Received) → ต่อกันด้วย newline ไม่ให้ทับกัน
    for (const h of data.internetMessageHeaders ?? []) {
      out[h.name] = out[h.name] ? `${out[h.name]}\n${h.value}` : h.value
    }
    return out
  } catch { return {} }
}

/** แปลงค่า header ผู้รับ เช่น  "IT Support" <a@b.com>, c@d.com  → รายชื่อ */
function parseAddressList(raw: string): { name: string; email: string }[] {
  if (!raw) return []
  return raw.split(',').map(part => {
    const s = part.trim()
    const m = s.match(/^(.*?)\s*<([^>]+)>$/)
    if (m) return { name: m[1].replace(/^"|"$/g, '').trim(), email: m[2].trim() }
    return { name: '', email: s.replace(/[<>]/g, '').trim() }
  }).filter(a => a.email.includes('@'))
}

async function readMail(): Promise<MailInput> {
  const item = Office.context.mailbox.item
  const [html, text] = await Promise.all([
    getBodyAsync(Office.CoercionType.Html),
    getBodyAsync(Office.CoercionType.Text),
  ])
  return {
    fromName: item?.from?.displayName ?? '',
    fromEmail: item?.from?.emailAddress ?? '',
    // Office.js โหมดอ่านไม่มี item.replyTo → อ่านจาก header 'Reply-To' หลัง login (แม่นกว่า)
    replyTo: [],
    subject: item?.subject ?? '',
    bodyHtml: html,
    bodyText: text,
    attachments: (item?.attachments ?? []).map(a => ({
      name: a.name, size: a.size ?? 0, isInline: !!a.isInline,
    })),
    headers: {},
    internalDomains: INTERNAL_DOMAINS,
    internalPeople: [],
  }
}

/** วิเคราะห์ใหม่ทั้งหมด (เรียกตอนเปิด และตอนสลับอีเมล) */
async function runAnalysis(): Promise<void> {
  state.loading = true
  state.reported = false
  state.headersLoaded = false
  render()

  const mail = await readMail()
  // วิเคราะห์รอบแรกทันทีด้วยข้อมูลที่ไม่ต้อง login — ผู้ใช้เห็นผลเร็ว
  state.mail = mail
  state.analysis = analyze(mail)
  state.loading = false
  render()

  // ถ้า login แล้ว → เติมข้อมูลที่ต้องใช้สิทธิ์ (header + รายชื่อพนักงาน) แล้ววิเคราะห์ซ้ำ
  if (state.account) {
    const [headers, people] = await Promise.all([fetchHeaders(), fetchInternalPeople()])
    const replyToHeader = Object.entries(headers).find(([k]) => k.toLowerCase() === 'reply-to')?.[1] ?? ''
    state.mail = { ...mail, headers, internalPeople: people, replyTo: parseAddressList(replyToHeader) }
    state.analysis = analyze(state.mail)
    state.headersLoaded = Object.keys(headers).length > 0
    render()
  }
}

// ─── Report ───────────────────────────────────────────────────────────────────
function reportText(): string {
  const m = state.mail, a = state.analysis
  if (!m || !a) return ''
  const lines = [
    `ผู้ส่ง: ${m.fromName} <${m.fromEmail}>`,
    `หัวข้อ: ${m.subject}`,
    m.replyTo.length ? `Reply-To: ${m.replyTo.map(r => r.email).join(', ')}` : '',
    `คะแนนความเสี่ยง: ${a.score} (${LEVEL_META[a.level].label})`,
    '',
    'สิ่งที่ตรวจพบ:',
    ...a.findings.map(f => `- [${SEV_META[f.severity].label}] (${f.category}) ${f.title} — ${f.detail.replace(/\n/g, ' ')}`),
    '',
    a.links.length ? 'ลิงก์ในอีเมล:' : '',
    ...a.links.map(l => `- ${l.href}${l.flags.length ? `  ⚠ ${l.flags.join(' / ')}` : ''}`),
  ]
  return lines.filter(l => l !== '').join('\n')
}

/** แนบอีเมลต้นฉบับ (.eml) เป็นหลักฐาน — ทำแบบ best-effort ไม่ให้ล้มทั้งการรายงาน */
async function attachEml(itemId: number): Promise<boolean> {
  try {
    const item = Office.context.mailbox.item
    if (!item?.itemId) return false
    const restId = Office.context.mailbox.convertToRestId(item.itemId, Office.MailboxEnums.RestVersion.v2_0)
    const token = await getGraphToken()
    const res = await fetch(`https://graph.microsoft.com/v1.0/me/messages/${restId}/$value`,
      { headers: { Authorization: `Bearer ${token}` } })
    if (!res.ok) return false
    const mime = await res.arrayBuffer()
    // ชื่อไฟล์ต้องปลอดภัยกับ SharePoint (ตัดอักขระต้องห้าม, ห้ามขึ้นต้นด้วย _)
    const safe = (item.subject || 'phishing')
      .replace(/[\\/:*?"<>|#%&{}~]/g, '_').replace(/^_+/, '').slice(0, 80).trim() || 'phishing'
    const spToken = await getToken()
    const url = `${SHAREPOINT_URL}/_api/web/lists/getbytitle('${REPORT_LIST}')/items(${itemId})/AttachmentFiles/add(FileName='${encodeURIComponent(safe + '.eml')}')`
    const up = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${spToken}`, Accept: 'application/json;odata=nometadata' },
      body: mime,
    })
    return up.ok
  } catch { return false }
}

async function submitReport(): Promise<void> {
  if (!state.mail || !state.analysis || state.reporting) return
  state.reporting = true; render()
  try {
    const m = state.mail, a = state.analysis
    const id = await spCreate(REPORT_LIST, {
      Title: (m.subject || '(ไม่มีหัวข้อ)').slice(0, 255),
      SenderName: m.fromName.slice(0, 255),
      SenderEmail: m.fromEmail.slice(0, 255),
      SenderDomain: domainOf(m.fromEmail),
      RiskScore: a.score,
      RiskLevel: a.level,
      Findings: reportText(),
      LinkCount: a.links.length,
      SuspiciousLinks: a.links.filter(l => l.flags.length).map(l => l.href).join('\n').slice(0, 4000),
      ReportedBy: state.account?.name ?? '',
      ReportedEmail: state.account?.username ?? '',
      Status: 'New',
    })
    const withEml = await attachEml(id)
    state.reported = true
    showToast(withEml ? 'ส่งรายงานพร้อมอีเมลต้นฉบับแล้ว' : 'ส่งรายงานแล้ว (แนบ .eml ไม่ได้)')
  } catch (e) {
    showToast(`ส่งรายงานไม่สำเร็จ: ${e instanceof Error ? e.message : String(e)}`, 'error')
  } finally {
    state.reporting = false; render()
  }
}

// ─── Actions ──────────────────────────────────────────────────────────────────
function openInKasm(href: string): void {
  if (!state.kasmTemplate) {
    showToast('ยังไม่ได้ตั้งค่า Kasm — เพิ่มใน HD_Options (Category=KasmConfig)', 'info')
    return
  }
  const target = state.kasmTemplate.includes('{url}')
  ? state.kasmTemplate.replace('{url}', encodeURIComponent(href))
    : state.kasmTemplate + encodeURIComponent(href)
  window.open(target, '_blank', 'noopener,noreferrer')
}

async function copyReport(): Promise<void> {
  try {
    await navigator.clipboard.writeText(reportText())
    showToast('คัดลอกผลวิเคราะห์แล้ว')
  } catch { showToast('คัดลอกไม่ได้', 'error') }
}

async function login(): Promise<void> {
  try {
    if (isMobilePlatform()) {
      await openAuthDialog()
      state.account = msalInstance.getAllAccounts()[0] ?? null
      if (!state.account) throw new Error('เข้าสู่ระบบไม่สำเร็จ')
    } else {
      state.account = (await msalInstance.loginPopup({ scopes: [SP_SCOPE] })).account
    }
    state.kasmTemplate = await fetchKasmTemplate()
    await runAnalysis()
  } catch (e) {
    showToast(`เข้าสู่ระบบไม่สำเร็จ: ${e instanceof Error ? e.message : String(e)}`, 'error')
    render()
  }
}

// ─── Render ───────────────────────────────────────────────────────────────────
function render(): void {
  const app = document.getElementById('app')
  if (!app) return
  const { account, mail, analysis, loading } = state

  if (loading && !analysis) {
    app.innerHTML = `<div class="p-6 text-center text-slate-500 text-sm">
      <div class="w-8 h-8 border-[3px] border-slate-200 border-t-blue-600 rounded-full animate-spin mx-auto mb-3"></div>
      กำลังตรวจอีเมล…</div>`
    return
  }
  if (!analysis || !mail) { app.innerHTML = `<div class="p-6 text-sm text-slate-500">เปิดอีเมลเพื่อเริ่มตรวจ</div>`; return }

  const lv = LEVEL_META[analysis.level]
  const suspiciousLinks = analysis.links.filter(l => l.flags.length)
  const safeLinks = analysis.links.filter(l => !l.flags.length)

  app.innerHTML = `
    <div class="p-3 space-y-3">

      <!-- ผลสรุป -->
      <div class="rounded-xl border-2 ${lv.cls} p-3">
        <div class="flex items-center gap-2">
          <span class="text-2xl leading-none">${lv.icon}</span>
          <div class="min-w-0 flex-1">
            <div class="font-bold text-sm">${esc(lv.label)}</div>
            <div class="text-xs opacity-80">คะแนนความเสี่ยง ${analysis.score} · พบสัญญาณ ${analysis.findings.filter(f => f.severity !== 'info').length} ข้อ</div>
          </div>
        </div>
      </div>

      <!-- ผู้ส่ง -->
      <div class="bg-white rounded-xl border border-slate-200 p-3 text-xs space-y-1">
        <div class="flex gap-2"><span class="text-slate-400 w-14 flex-shrink-0">ผู้ส่ง</span>
          <span class="font-medium text-slate-800 break-url">${esc(mail.fromName || '—')}</span></div>
        <div class="flex gap-2"><span class="text-slate-400 w-14 flex-shrink-0">อีเมล</span>
          <span class="text-slate-600 break-url">${esc(mail.fromEmail || '—')}</span></div>
        ${mail.replyTo.length ? `<div class="flex gap-2"><span class="text-slate-400 w-14 flex-shrink-0">Reply-To</span>
          <span class="text-slate-600 break-url">${esc(mail.replyTo.map(r => r.email).join(', '))}</span></div>` : ''}
        <div class="flex gap-2"><span class="text-slate-400 w-14 flex-shrink-0">หัวข้อ</span>
          <span class="text-slate-600">${esc(mail.subject || '—')}</span></div>
      </div>

      ${!account ? `
        <div class="bg-blue-50 border border-blue-200 rounded-xl p-3 text-xs text-blue-800">
          <p class="font-medium mb-1">เข้าสู่ระบบเพื่อตรวจให้ครบ</p>
          <p class="mb-2 opacity-80">จะได้ตรวจ SPF/DKIM/DMARC, ตรวจการปลอมเป็นพนักงาน และรายงานเข้า Helpdesk ได้</p>
          <button id="btn-login" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-1.5 rounded-lg">เข้าสู่ระบบ</button>
        </div>` : ''}

      <!-- สิ่งที่ตรวจพบ -->
      <div class="space-y-2">
        ${analysis.findings.length === 0
          ? `<p class="text-xs text-slate-400 text-center py-3">ไม่พบสัญญาณผิดปกติจากการตรวจอัตโนมัติ</p>`
          : analysis.findings.map(f => {
            const s = SEV_META[f.severity]
            return `<div class="bg-white rounded-xl border border-slate-200 p-2.5">
              <div class="flex items-start gap-2">
                <span class="text-[9px] font-bold px-1.5 py-0.5 rounded-full ${s.cls} flex-shrink-0 mt-0.5">${s.label}</span>
                <div class="min-w-0 flex-1">
                  <div class="text-xs font-semibold text-slate-800">${esc(f.title)}</div>
                  <div class="text-[11px] text-slate-500 whitespace-pre-line break-url">${esc(f.detail)}</div>
                  <div class="text-[9px] text-slate-400 mt-0.5">${esc(f.category)}</div>
                </div>
              </div>
            </div>`
          }).join('')}
      </div>

      <!-- ลิงก์ -->
      ${analysis.links.length ? `
      <div class="bg-white rounded-xl border border-slate-200 p-3">
        <div class="text-xs font-semibold text-slate-700 mb-2">ลิงก์ในอีเมล (${analysis.links.length})</div>
        <div class="space-y-2">
          ${[...suspiciousLinks, ...safeLinks].map((l, i) => `
            <div class="rounded-lg border ${l.flags.length ? 'border-red-200 bg-red-50/50' : 'border-slate-100'} p-2">
              <div class="text-[11px] font-medium ${l.flags.length ? 'text-red-700' : 'text-slate-700'} break-url">${esc(l.host || l.href)}</div>
              ${l.text && l.text !== l.href ? `<div class="text-[10px] text-slate-500 break-url">ข้อความที่แสดง: “${esc(l.text.slice(0, 80))}”</div>` : ''}
              <div class="text-[10px] text-slate-400 break-url mt-0.5">${esc(l.href.slice(0, 160))}</div>
              ${l.flags.map(f => `<div class="text-[10px] text-red-600 mt-0.5">⚠ ${esc(f)}</div>`).join('')}
              <button data-kasm="${i}" class="mt-1.5 text-[10px] font-semibold px-2 py-1 rounded-md bg-slate-800 hover:bg-slate-900 text-white">
                🛡 เปิดใน Kasm (แซนด์บ็อกซ์)
              </button>
            </div>`).join('')}
        </div>
        <p class="text-[10px] text-slate-400 mt-2">อย่าคลิกลิงก์จากอีเมลที่ไม่มั่นใจโดยตรง — เปิดผ่าน Kasm เพื่อแยกออกจากเครื่องคุณ</p>
      </div>` : ''}

      <!-- ปุ่มจัดการ -->
      <div class="space-y-2 pb-4">
        <button id="btn-report" ${!account || state.reported ? 'disabled' : ''}
          class="w-full ${state.reported ? 'bg-emerald-600' : 'bg-red-600 hover:bg-red-700'} disabled:opacity-50 text-white text-sm font-semibold py-2 rounded-lg">
          ${state.reported ? '✓ รายงานแล้ว' : state.reporting ? 'กำลังส่ง…' : '🚩 รายงานอีเมลนี้ให้ IT'}
        </button>
        <div class="flex gap-2">
          <button id="btn-copy" class="flex-1 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 text-xs font-medium py-1.5 rounded-lg">คัดลอกผลตรวจ</button>
          <button id="btn-headers" class="flex-1 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 text-xs font-medium py-1.5 rounded-lg">
            ${state.showHeaders ? 'ซ่อน header' : 'ดู header'}
          </button>
        </div>
        ${state.showHeaders ? `
          <pre class="bg-slate-900 text-slate-100 text-[9px] p-2 rounded-lg overflow-x-auto whitespace-pre-wrap break-url max-h-64 overflow-y-auto">${
            esc(Object.entries(mail.headers).map(([k, v]) => `${k}: ${v}`).join('\n') || (account ? 'อ่าน header ไม่ได้ (ตรวจสิทธิ์ Mail.Read)' : 'ต้องเข้าสู่ระบบก่อน'))
          }</pre>` : ''}
        <p class="text-[10px] text-slate-400 text-center">วิเคราะห์ในเครื่องทั้งหมด — ไม่มีการส่งเนื้อหาอีเมลออกไปที่บริการภายนอก</p>
      </div>
    </div>`

  // ─── bind events ───
  document.getElementById('btn-login')?.addEventListener('click', login)
  document.getElementById('btn-report')?.addEventListener('click', submitReport)
  document.getElementById('btn-copy')?.addEventListener('click', copyReport)
  document.getElementById('btn-headers')?.addEventListener('click', () => { state.showHeaders = !state.showHeaders; render() })
  const ordered = [...suspiciousLinks, ...safeLinks]
  document.querySelectorAll('[data-kasm]').forEach(btn => {
    btn.addEventListener('click', () => {
      const i = Number((btn as HTMLElement).dataset.kasm)
      const l = ordered[i]
      if (l) openInKasm(l.href)
    })
  })
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
Office.onReady(async () => {
  await msalInstance.initialize()
  try { await msalInstance.handleRedirectPromise() } catch { /* ignore */ }
  state.account = msalInstance.getAllAccounts()[0] ?? null
  if (state.account) state.kasmTemplate = await fetchKasmTemplate()

  await runAnalysis()

  // สลับอีเมลใน Outlook → ตรวจใบใหม่อัตโนมัติ (ไม่ต้องปิด-เปิด task pane)
  try {
    Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => { runAnalysis() })
  } catch { /* บางแพลตฟอร์มไม่รองรับ */ }
})
