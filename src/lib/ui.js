// Small DOM helpers shared by the interactive tools.

export function $(root, selector) {
  return root.querySelector(selector)
}

export function setStatus(el, message, kind = 'info') {
  if (!el) return
  el.textContent = message
  el.dataset.kind = kind
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    let ok = false
    try {
      ok = document.execCommand('copy')
    } catch {
      ok = false
    }
    ta.remove()
    return ok
  }
}

/** Wires every `.ist-copy[data-copy-target]` button inside root to copy the target's text. */
export function wireCopyButtons(root) {
  root.querySelectorAll('.ist-copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const target = root.querySelector(btn.dataset.copyTarget)
      if (!target) return
      const ok = await copyText(target.textContent ?? '')
      const label = btn.textContent
      btn.textContent = ok ? 'Copied' : 'Copy failed'
      setTimeout(() => (btn.textContent = label), 1500)
    })
  })
}

export function show(el, visible) {
  el?.classList.toggle('ist-hidden', !visible)
}

/** Best-effort mapping of the current browser to an Appendix B `source` value. */
export function detectSource(ua = navigator.userAgent, touchPoints = navigator.maxTouchPoints || 0) {
  const isIOS = /iPhone|iPad|iPod/i.test(ua) || (/Macintosh/i.test(ua) && touchPoints > 1)
  if (/Android/i.test(ua)) {
    if (/EdgA\//.test(ua)) return 'Android_Edge'
    if (/Firefox\//.test(ua)) return 'Android_Firefox'
    if (/SamsungBrowser\//.test(ua)) return 'Android_Samsung'
    if (/HuaweiBrowser\//.test(ua)) return 'Android_Huawei'
    if (/MiuiBrowser\/|XiaoMi\//i.test(ua)) return 'Android_Xiaomi'
    return 'Android_Chrome'
  }
  if (isIOS) {
    if (/EdgiOS\//.test(ua)) return 'iOS_Edge'
    if (/FxiOS\//.test(ua)) return 'iOS_Firefox'
    if (/CriOS\//.test(ua)) return 'iOS_Chrome'
    return 'iOS_Safari'
  }
  return 'PC_Browser'
}

/** Remembers non-secret form values per tool in localStorage (best effort). */
export function persist(key, inputs) {
  let saved = {}
  try {
    saved = JSON.parse(localStorage.getItem(key) || '{}')
  } catch {
    saved = {}
  }
  for (const input of inputs) {
    if (!input?.name) continue
    if (saved[input.name] !== undefined) {
      if (input.type === 'checkbox') input.checked = saved[input.name]
      else input.value = saved[input.name]
    }
    input.addEventListener('change', () => {
      saved[input.name] = input.type === 'checkbox' ? input.checked : input.value
      try {
        localStorage.setItem(key, JSON.stringify(saved))
      } catch {
        /* storage unavailable */
      }
    })
  }
}
