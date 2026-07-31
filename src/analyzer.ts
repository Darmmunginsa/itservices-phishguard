// ─── PhishGuard analyzer ────────────────────────────────────────────────────
// วิเคราะห์อีเมลหาสัญญาณ phishing ด้วย heuristic ทั้งหมด "ในเครื่อง"
// ไม่มีการส่งเนื้อหาอีเมล/URL/ไฟล์ออกไปที่บริการภายนอกเลย (ข้อมูลลูกค้าไม่รั่ว)
// ทุกฟังก์ชันเป็น pure function — ทดสอบง่ายและไม่มีผลข้างเคียง

export type Severity = 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  severity: Severity
  category: 'ผู้ส่ง' | 'การยืนยันตัวตน' | 'ลิงก์' | 'ไฟล์แนบ' | 'เนื้อหา'
  title: string
  detail: string
}

export interface LinkInfo {
  href: string
  text: string
  host: string
  /** เหตุผลที่ลิงก์นี้น่าสงสัย (ว่าง = ไม่พบสัญญาณ) */
  flags: string[]
}

export interface MailInput {
  fromName: string
  fromEmail: string
  replyTo: { name: string; email: string }[]
  subject: string
  bodyHtml: string
  bodyText: string
  attachments: { name: string; size: number; isInline: boolean }[]
  /** header จาก Graph (ชื่อ header → ค่า) — ใช้ตรวจ SPF/DKIM/DMARC ; ว่างได้ */
  headers: Record<string, string>
  /** โดเมนขององค์กรเรา */
  internalDomains: string[]
  /** ชื่อ-อีเมลคนในองค์กร (จาก HD_AgentProfiles) — ใช้ตรวจการปลอมเป็นคนใน */
  internalPeople: { name: string; email: string }[]
}

export interface Analysis {
  score: number
  level: 'safe' | 'suspicious' | 'danger'
  findings: Finding[]
  links: LinkInfo[]
}

const WEIGHT: Record<Severity, number> = { high: 30, medium: 12, low: 5, info: 0 }

// ─── helpers ───────────────────────────────────────────────────────────────
export const domainOf = (email: string): string => (email.split('@')[1] ?? '').trim().toLowerCase()
const lc = (s: string) => (s ?? '').toLowerCase()

/** ตัด subdomain ให้เหลือโดเมนหลัก (รองรับ .co.th / .ac.th ที่มี 3 ส่วน) */
export function rootDomain(host: string): string {
  const p = lc(host).replace(/\.$/, '').split('.')
  if (p.length <= 2) return p.join('.')
  const twoLevelTlds = ['co', 'or', 'ac', 'go', 'in', 'net', 'com']
  if (p.length >= 3 && twoLevelTlds.includes(p[p.length - 2]) && p[p.length - 1].length === 2) {
    return p.slice(-3).join('.')
  }
  return p.slice(-2).join('.')
}

/** ระยะแก้ไข (Levenshtein) — ใช้จับโดเมนเลียนแบบ เช่น itservlces.co.th */
export function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length
  if (!m) return n
  if (!n) return m
  let prev = Array.from({ length: n + 1 }, (_, i) => i)
  for (let i = 1; i <= m; i++) {
    const cur = [i]
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      )
    }
    prev = cur
  }
  return prev[n]
}

const FREE_MAIL = new Set([
  'gmail.com', 'googlemail.com', 'hotmail.com', 'outlook.com', 'live.com', 'msn.com',
  'yahoo.com', 'yahoo.co.th', 'protonmail.com', 'proton.me', 'aol.com', 'icloud.com',
  'mail.com', 'gmx.com', 'yandex.com', 'zoho.com', 'qq.com', '163.com',
])

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly',
  'rebrand.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in', 'bl.ink', 's.id', 'v.gd',
])

// TLD ที่ถูกใช้ทำ phishing บ่อยผิดปกติ
const RISKY_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'click', 'link', 'work', 'fit', 'gq', 'cf', 'tk', 'ml',
  'country', 'kim', 'science', 'party', 'review', 'loan', 'date', 'racing', 'rest',
])

// นามสกุลไฟล์ที่รันโค้ดได้ทันที — อันตรายที่สุด
const DANGEROUS_EXT = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh',
  'ps1', 'psm1', 'msi', 'msp', 'hta', 'cpl', 'jar', 'lnk', 'reg', 'inf', 'scf', 'chm',
  'iso', 'img', 'vhd', 'apk', 'dll', 'appx',
])
// Office ที่ฝังมาโครได้
const MACRO_EXT = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'xlam', 'ppam', 'sldm'])
// ไฟล์บีบอัด — ใช้ห่อ payload เพื่อเลี่ยงการสแกน
const ARCHIVE_EXT = new Set(['zip', '7z', 'rar', 'gz', 'tar', 'cab', 'ace', 'arj'])
// HTML แนบมา = หน้า login ปลอมแบบออฟไลน์
const HTML_EXT = new Set(['htm', 'html', 'shtml', 'svg', 'xhtml'])

const extOf = (name: string): string => {
  const i = name.lastIndexOf('.')
  return i > 0 ? lc(name.slice(i + 1)) : ''
}

// คำที่บ่งชี้การกดดัน/หลอกล่อ (ไทย + อังกฤษ)
const URGENCY_WORDS = [
  'ด่วน', 'ด่วนที่สุด', 'ภายใน 24 ชั่วโมง', 'ทันที', 'ระงับ', 'ระงับบัญชี', 'ถูกระงับ',
  'หมดอายุ', 'จะถูกลบ', 'ยืนยันตัวตน', 'ยืนยันบัญชี', 'ตรวจสอบบัญชี', 'อัปเดตข้อมูล',
  'urgent', 'immediately', 'within 24 hours', 'act now', 'final notice', 'last warning',
  'account suspended', 'account locked', 'will be deleted', 'verify your account',
  'confirm your identity', 'unusual activity', 'security alert', 'expire', 'expiring',
  'failure to comply', 'avoid suspension', 'reactivate',
]
const CREDENTIAL_WORDS = [
  'รหัสผ่าน', 'พาสเวิร์ด', 'ใส่รหัส', 'เข้าสู่ระบบเพื่อยืนยัน', 'otp', 'รหัส otp',
  'password', 'passcode', 'sign in to verify', 'log in to confirm', 'enter your credentials',
  'update your password', 'reset your password', 'mfa code', 'authentication code',
]
const BEC_WORDS = [
  'เปลี่ยนเลขบัญชี', 'บัญชีใหม่', 'โอนเงิน', 'ชำระเงินด่วน', 'เปลี่ยนธนาคาร', 'แจ้งบัญชีใหม่',
  'change of bank', 'new bank account', 'updated bank details', 'wire transfer',
  'remittance', 'payment instruction', 'invoice attached', 'kindly process payment',
  'beneficiary account',
]

const hitWords = (text: string, words: string[]): string[] => {
  const t = lc(text)
  return words.filter(w => t.includes(lc(w)))
}

// ─── raw internet headers ──────────────────────────────────────────────────
/**
 * แปลง header ดิบ (จาก item.getAllInternetHeadersAsync) เป็น map
 * รองรับ folded line ตาม RFC 5322 — บรรทัดที่ขึ้นต้นด้วย space/tab เป็นส่วนต่อของบรรทัดก่อน
 * (ถ้าไม่รวมบรรทัดต่อ จะอ่าน Authentication-Results ยาว ๆ ได้ไม่ครบ → ตรวจ SPF/DKIM พลาด)
 * header ชื่อซ้ำได้ (เช่น Received) → ต่อด้วย newline ไม่ให้ทับกัน
 */
export function parseRawHeaders(raw: string): Record<string, string> {
  const out: Record<string, string> = {}
  if (!raw) return out
  let cur = ''
  const flush = () => {
    const i = cur.indexOf(':')
    if (i > 0) {
      const k = cur.slice(0, i).trim()
      const v = cur.slice(i + 1).trim()
      if (k) out[k] = out[k] ? `${out[k]}\n${v}` : v
    }
    cur = ''
  }
  for (const line of raw.replace(/\r\n/g, '\n').split('\n')) {
    if (/^[ \t]/.test(line)) { if (cur) cur += ' ' + line.trim(); continue }
    flush()
    cur = line
  }
  flush()
  return out
}

// ─── link extraction ───────────────────────────────────────────────────────
/** ดึงลิงก์ทั้งหมดจาก HTML พร้อมข้อความที่ผู้ใช้เห็น */
export function extractLinks(html: string): { href: string; text: string }[] {
  const out: { href: string; text: string }[] = []
  if (!html) return out
  // ใช้ DOMParser — ปลอดภัยกว่า regex และไม่รัน script ในเอกสารที่ parse
  try {
    const doc = new DOMParser().parseFromString(html, 'text/html')
    doc.querySelectorAll('a[href]').forEach(a => {
      const href = (a.getAttribute('href') ?? '').trim()
      if (/^(https?:)?\/\//i.test(href) || /^https?:/i.test(href)) {
        out.push({ href, text: (a.textContent ?? '').trim() })
      }
    })
  } catch { /* parse ไม่ได้ → คืนที่หาได้ */ }
  return out
}

const hostOf = (url: string): string => {
  try { return lc(new URL(url).hostname) } catch { return '' }
}

/** ข้อความที่แสดงมีชื่อโดเมนอยู่ข้างในไหม (ใช้เทียบว่าตรงกับ href จริงหรือไม่) */
function domainInText(text: string): string {
  const m = text.match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i)
  return m ? lc(m[1]) : ''
}

// ─── main ──────────────────────────────────────────────────────────────────
export function analyze(m: MailInput): Analysis {
  const findings: Finding[] = []
  const add = (severity: Severity, category: Finding['category'], title: string, detail: string) =>
    findings.push({ severity, category, title, detail })

  const fromDomain = domainOf(m.fromEmail)
  const fromRoot = rootDomain(fromDomain)
  const internalRoots = m.internalDomains.map(d => rootDomain(d))
  const isInternalSender = internalRoots.includes(fromRoot)
  const body = `${m.subject}\n${m.bodyText || m.bodyHtml}`

  // ── 1) ผู้ส่ง ──
  if (!m.fromEmail) {
    add('medium', 'ผู้ส่ง', 'ไม่พบอีเมลผู้ส่ง', 'อ่านที่อยู่ผู้ส่งไม่ได้ — ตรวจด้วยตาอีกครั้ง')
  }

  // ชื่อที่แสดงเป็นอีเมล แต่ไม่ตรงกับอีเมลจริง = ตั้งใจอำพราง
  const nameAsEmail = m.fromName.match(/[\w.+-]+@[\w.-]+\.\w+/)
  if (nameAsEmail && lc(nameAsEmail[0]) !== lc(m.fromEmail)) {
    add('high', 'ผู้ส่ง', 'ชื่อผู้ส่งแสดงอีเมลคนละอันกับผู้ส่งจริง',
      `แสดงว่า "${nameAsEmail[0]}" แต่ส่งจริงจาก "${m.fromEmail}"`)
  }

  // โดเมนเลียนแบบองค์กรเรา (ต่างกันไม่เกิน 2 ตัวอักษร แต่ไม่ใช่โดเมนเรา)
  if (fromRoot && !isInternalSender) {
    for (const d of internalRoots) {
      const dist = editDistance(fromRoot, d)
      if (dist > 0 && dist <= 2) {
        add('high', 'ผู้ส่ง', 'โดเมนผู้ส่งคล้ายโดเมนองค์กรมาก',
          `"${fromRoot}" ต่างจาก "${d}" เพียง ${dist} ตัวอักษร — น่าจะเป็นโดเมนเลียนแบบ`)
        break
      }
    }
  }

  // punycode (โดเมนใช้อักษรหน้าตาเหมือนภาษาอังกฤษ)
  if (fromDomain.includes('xn--')) {
    add('high', 'ผู้ส่ง', 'โดเมนผู้ส่งเป็น punycode',
      `"${fromDomain}" ใช้อักขระที่หน้าตาเหมือนตัวอักษรอังกฤษ (homoglyph) เพื่อลวงตา`)
  }

  // ปลอมเป็นคนในองค์กร: ชื่อตรงกับพนักงาน แต่อีเมลไม่ใช่ของเรา
  if (!isInternalSender && m.fromName.trim()) {
    const fn = lc(m.fromName).replace(/\s+/g, ' ').trim()
    const impersonated = m.internalPeople.find(p => {
      const pn = lc(p.name).replace(/\s+/g, ' ').trim()
      return pn.length > 4 && (fn === pn || fn.includes(pn)) && lc(p.email) !== lc(m.fromEmail)
    })
    if (impersonated) {
      add('high', 'ผู้ส่ง', 'ปลอมเป็นคนในองค์กร',
        `ใช้ชื่อ "${m.fromName}" (ตรงกับ ${impersonated.email}) แต่ส่งจากโดเมนภายนอก "${fromDomain}"`)
    }
  }

  // ฟรีเมลแต่อ้างชื่อบริษัท
  if (FREE_MAIL.has(fromRoot)) {
    const claimsCompany = /บริษัท|จำกัด|co\.?,?\s?ltd|company|corp|support|admin|it\s|helpdesk|billing|account/i.test(m.fromName)
    add(claimsCompany ? 'medium' : 'low', 'ผู้ส่ง', 'ส่งจากอีเมลฟรี',
      `"${fromRoot}" เป็นผู้ให้บริการอีเมลฟรี${claimsCompany ? ' แต่ชื่อผู้ส่งอ้างเป็นองค์กร/ฝ่ายงาน' : ''}`)
  }

  // Reply-To ไปโดเมนอื่น = ตอบกลับแล้วไปเข้ามือคนร้าย
  for (const rt of m.replyTo) {
    const rtRoot = rootDomain(domainOf(rt.email))
    if (rtRoot && fromRoot && rtRoot !== fromRoot) {
      add('high', 'ผู้ส่ง', 'Reply-To ชี้ไปโดเมนอื่น',
        `ตอบกลับจะไปที่ "${rt.email}" (${rtRoot}) ไม่ใช่ผู้ส่ง "${m.fromEmail}" (${fromRoot})`)
      break
    }
  }

  // ── 2) การยืนยันตัวตนของเมล (จาก header) ──
  const H = Object.fromEntries(Object.entries(m.headers).map(([k, v]) => [lc(k), v]))
  const authResults = lc(H['authentication-results'] ?? '')
  if (authResults) {
    const spf = authResults.match(/spf=(\w+)/)?.[1]
    const dkim = authResults.match(/dkim=(\w+)/)?.[1]
    const dmarc = authResults.match(/dmarc=(\w+)/)?.[1]
    const bad = ['fail', 'softfail', 'permerror', 'temperror', 'none']
    if (spf && bad.includes(spf)) {
      add(spf === 'fail' ? 'high' : 'medium', 'การยืนยันตัวตน', `SPF = ${spf}`,
        'เซิร์ฟเวอร์ที่ส่งไม่ได้รับอนุญาตให้ส่งแทนโดเมนนี้ (อาจปลอมผู้ส่ง)')
    }
    if (dkim && bad.includes(dkim)) {
      add(dkim === 'fail' ? 'high' : 'medium', 'การยืนยันตัวตน', `DKIM = ${dkim}`,
        'ลายเซ็นดิจิทัลของอีเมลไม่ถูกต้องหรือไม่มี — เนื้อหาอาจถูกแก้ระหว่างทาง')
    }
    if (dmarc && bad.includes(dmarc)) {
      add(dmarc === 'fail' ? 'high' : 'medium', 'การยืนยันตัวตน', `DMARC = ${dmarc}`,
        'ไม่ผ่านนโยบายป้องกันการปลอมโดเมนของผู้ส่ง')
    }
    if (spf === 'pass' && dkim === 'pass' && dmarc === 'pass') {
      add('info', 'การยืนยันตัวตน', 'SPF / DKIM / DMARC ผ่านทั้งหมด',
        'ผู้ส่งยืนยันตัวตนถูกต้อง — แต่ยัง "ไม่ได้" รับประกันว่าเนื้อหาปลอดภัย (บัญชีจริงอาจถูกยึด)')
    }
  } else {
    add('low', 'การยืนยันตัวตน', 'อ่าน header ยืนยันตัวตนไม่ได้',
      'ไม่พบ Authentication-Results — ข้ามการตรวจ SPF/DKIM/DMARC')
  }

  // Return-Path คนละโดเมนกับ From
  const returnPath = H['return-path'] ?? ''
  const rpDomain = rootDomain(domainOf(returnPath.replace(/[<>]/g, '')))
  if (rpDomain && fromRoot && rpDomain !== fromRoot) {
    add('medium', 'การยืนยันตัวตน', 'Return-Path ไม่ตรงกับผู้ส่ง',
      `ซองจดหมายจริงมาจาก "${rpDomain}" แต่แสดงผู้ส่งเป็น "${fromRoot}"`)
  }

  // ── 3) ลิงก์ ──
  const raw = extractLinks(m.bodyHtml)
  const seen = new Set<string>()
  const links: LinkInfo[] = []
  for (const l of raw) {
    const host = hostOf(l.href)
    const key = `${host}|${l.href}`
    if (seen.has(key)) continue
    seen.add(key)
    const flags: string[] = []

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) flags.push('ปลายทางเป็น IP ตรง ๆ ไม่ใช่ชื่อโดเมน')
    if (host.includes('xn--')) flags.push('โดเมนเป็น punycode (อักขระลวงตา)')
    if (SHORTENERS.has(rootDomain(host))) flags.push('เป็นลิงก์ย่อ — ซ่อนปลายทางจริง')
    if (RISKY_TLDS.has(host.split('.').pop() ?? '')) flags.push(`นามสกุลโดเมน ".${host.split('.').pop()}" ถูกใช้ทำ phishing บ่อย`)
    if (/^http:\/\//i.test(l.href)) flags.push('ไม่ได้เข้ารหัส (http)')
    // userinfo ลวงตา: https://paypal.com@evil.com/
    try {
      const u = new URL(l.href)
      if (u.username || u.password) flags.push('มี "@" ใน URL — ส่วนหน้าเป็นของหลอก ปลายทางจริงคือ ' + host)
    } catch { /* ignore */ }

    // ข้อความที่แสดงบอกโดเมนหนึ่ง แต่ลิงก์ไปอีกโดเมน
    const shown = domainInText(l.text)
    if (shown && host && rootDomain(shown) !== rootDomain(host)) {
      flags.push(`ข้อความแสดง "${shown}" แต่ลิงก์ไป "${host}"`)
    }

    links.push({ href: l.href, text: l.text, host, flags })
  }

  const badLinks = links.filter(l => l.flags.length > 0)
  if (badLinks.length) {
    const worst = badLinks.find(l =>
      l.flags.some(f => f.includes('ข้อความแสดง') || f.includes('IP ตรง') || f.includes('punycode') || f.includes('"@"')))
    add(worst ? 'high' : 'medium', 'ลิงก์', `พบลิงก์น่าสงสัย ${badLinks.length} รายการ`,
      badLinks.slice(0, 3).map(l => `• ${l.host}: ${l.flags[0]}`).join('\n'))
  }

  // ── 4) ไฟล์แนบ ── (ตัดรูปในลายเซ็นออก)
  const atts = m.attachments.filter(a => !a.isInline)
  for (const a of atts) {
    const ext = extOf(a.name)
    // นามสกุลซ้อน: invoice.pdf.exe
    const parts = a.name.split('.')
    if (parts.length > 2) {
      const prev = lc(parts[parts.length - 2])
      if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt', 'ppt'].includes(prev)) {
        add('high', 'ไฟล์แนบ', 'ไฟล์แนบใช้นามสกุลซ้อนเพื่อลวงตา',
          `"${a.name}" ดูเหมือน .${prev} แต่ไฟล์จริงเป็น .${ext}`)
      }
    }
    if (DANGEROUS_EXT.has(ext)) {
      add('high', 'ไฟล์แนบ', `ไฟล์แนบอันตราย (.${ext})`,
        `"${a.name}" เป็นไฟล์ที่รันโค้ดได้ทันที — ห้ามเปิดถ้าไม่มั่นใจ 100%`)
    } else if (MACRO_EXT.has(ext)) {
      add('high', 'ไฟล์แนบ', `เอกสารฝังมาโคร (.${ext})`,
        `"${a.name}" อาจรันมาโครเมื่อเปิด — ห้ามกด "Enable Content"`)
    } else if (HTML_EXT.has(ext)) {
      add('high', 'ไฟล์แนบ', `ไฟล์แนบเป็นหน้าเว็บ (.${ext})`,
        `"${a.name}" มักเป็นหน้า login ปลอมที่เปิดจากเครื่องเพื่อเลี่ยงการสแกน URL`)
    } else if (ARCHIVE_EXT.has(ext)) {
      add('medium', 'ไฟล์แนบ', `ไฟล์บีบอัด (.${ext})`,
        `"${a.name}" อาจห่อไฟล์อันตรายไว้ข้างใน (โดยเฉพาะถ้าใส่รหัสผ่าน) — ตรวจก่อนแตกไฟล์`)
    }
  }
  // มีรหัสผ่านของไฟล์บอกในเนื้อเมล = ตั้งใจเลี่ยงระบบสแกน
  if (atts.length && /รหัสผ่านไฟล์|รหัสเปิดไฟล์|password (?:is|:)|passcode (?:is|:)/i.test(body)) {
    add('high', 'ไฟล์แนบ', 'บอกรหัสผ่านของไฟล์แนบไว้ในเนื้อเมล',
      'เป็นวิธีมาตรฐานในการเลี่ยงระบบสแกนไวรัส — ระวังอย่างสูง')
  }

  // ── 5) เนื้อหา ──
  const urgency = hitWords(body, URGENCY_WORDS)
  if (urgency.length >= 2) {
    add('medium', 'เนื้อหา', 'ใช้ถ้อยคำกดดันให้รีบทำ',
      `พบคำ: ${urgency.slice(0, 5).join(', ')}`)
  } else if (urgency.length === 1) {
    add('low', 'เนื้อหา', 'มีถ้อยคำเร่งรัด', `พบคำ: ${urgency[0]}`)
  }
  const creds = hitWords(body, CREDENTIAL_WORDS)
  if (creds.length) {
    add('high', 'เนื้อหา', 'ขอข้อมูลเข้าสู่ระบบ',
      `พบคำ: ${creds.slice(0, 5).join(', ')} — องค์กรจะไม่ขอรหัสผ่าน/OTP ทางอีเมล`)
  }
  const bec = hitWords(body, BEC_WORDS)
  if (bec.length) {
    add(bec.length >= 2 ? 'high' : 'medium', 'เนื้อหา', 'เกี่ยวกับการโอนเงิน/เปลี่ยนบัญชี',
      `พบคำ: ${bec.slice(0, 5).join(', ')} — ยืนยันทางโทรศัพท์กับผู้ติดต่อตัวจริงก่อนทุกครั้ง`)
  }

  // อ้างเป็นคนในองค์กรพร้อมขอเงิน/รหัส = อันตรายสูงสุด
  if (!isInternalSender && (creds.length || bec.length) &&
      /it\s?support|helpdesk|ฝ่ายไอที|แผนกไอที|ผู้ดูแลระบบ|admin|ceo|managing director|กรรมการ/i.test(m.fromName)) {
    add('high', 'เนื้อหา', 'อ้างเป็นผู้มีอำนาจ/ฝ่ายไอที และขอข้อมูลสำคัญ',
      `ผู้ส่งภายนอก "${m.fromName}" <${m.fromEmail}> อ้างตำแหน่งเพื่อสร้างความน่าเชื่อถือ`)
  }

  // ── สรุปคะแนน ──
  const score = findings.reduce((s, f) => s + WEIGHT[f.severity], 0)
  const hasHigh = findings.some(f => f.severity === 'high')
  const level: Analysis['level'] =
    score >= 40 || (hasHigh && score >= 30) ? 'danger'
    : score >= 12 || hasHigh ? 'suspicious'
    : 'safe'

  // เรียงความรุนแรงมากไปน้อย เพื่อให้เห็นเรื่องสำคัญก่อน
  const order: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 }
  findings.sort((a, b) => order[a.severity] - order[b.severity])

  return { score, level, findings, links }
}

export const LEVEL_META: Record<Analysis['level'], { label: string; cls: string; icon: string }> = {
  safe:       { label: 'ไม่พบสัญญาณผิดปกติ', cls: 'bg-emerald-50 border-emerald-300 text-emerald-800', icon: '✅' },
  suspicious: { label: 'น่าสงสัย — ตรวจก่อนคลิก',  cls: 'bg-amber-50 border-amber-300 text-amber-800',    icon: '⚠️' },
  danger:     { label: 'เสี่ยงสูง — อย่าคลิก',      cls: 'bg-red-50 border-red-300 text-red-800',         icon: '🛑' },
}

export const SEV_META: Record<Severity, { label: string; cls: string }> = {
  high:   { label: 'สูง',   cls: 'bg-red-100 text-red-700' },
  medium: { label: 'กลาง',  cls: 'bg-amber-100 text-amber-700' },
  low:    { label: 'ต่ำ',   cls: 'bg-slate-100 text-slate-600' },
  info:   { label: 'ข้อมูล', cls: 'bg-blue-100 text-blue-700' },
}
