import { PublicClientApplication } from '@azure/msal-browser'

// หน้านี้เปิดใน Office Dialog (สำหรับ Outlook มือถือ) — ทำ MSAL redirect แล้วส่งผลกลับหน้าหลัก
const CLIENT_ID = '0bab07cf-65e6-487c-89af-c917fc1a5a13'
const TENANT_ID = 'd569b991-89fc-4a62-9df5-eb361abcef40'
const SP_SCOPE = 'https://rpaexpert.sharepoint.com/.default'

const AUTH_REDIRECT = window.location.origin.includes('localhost')
  ? `${window.location.origin}/auth.html`
  : 'https://darmmunginsa.github.io/itservices-phishguard/auth.html'

const msalInstance = new PublicClientApplication({
  auth: {
    clientId: CLIENT_ID,
    authority: `https://login.microsoftonline.com/${TENANT_ID}`,
    redirectUri: AUTH_REDIRECT,
    navigateToLoginRequestUrl: false,
  },
  // ต้องตรงกับหน้าหลัก เพื่อให้ token cache ใช้ร่วมกันได้ (same origin)
  cache: { cacheLocation: 'localStorage', storeAuthStateInCookie: false },
})

function tell(ok: boolean, error?: string) {
  // ส่งผลกลับหน้าหลักผ่าน Office Dialog API
  try { Office.context.ui.messageParent(JSON.stringify({ ok, error })) }
  catch { /* ถ้าไม่ได้เปิดใน dialog ก็เงียบไว้ */ }
}

async function run() {
  await msalInstance.initialize()
  try {
    const resp = await msalInstance.handleRedirectPromise()
    if (resp?.account) { msalInstance.setActiveAccount(resp.account); tell(true); return }
    if (msalInstance.getAllAccounts().length > 0) { tell(true); return }
    // ยังไม่มีบัญชี → เริ่ม login (หน้าจะ redirect ไป AAD แล้วกลับมาที่ auth.html)
    await msalInstance.loginRedirect({ scopes: [SP_SCOPE], redirectUri: AUTH_REDIRECT })
  } catch (e) {
    tell(false, e instanceof Error ? e.message : String(e))
  }
}

// office.js โหลดใน auth.html แล้ว — รอ Office พร้อมก่อนค่อยส่งผลกลับ
Office.onReady(() => { run() })
