export function copyText(text: string): Promise<boolean> {
  return new Promise((resolve) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard
        .writeText(text)
        .then(() => resolve(true))
        .catch(() => {
          // Fallback to legacy execCommand if clipboard API fails / document not focused
          try {
            const el = document.createElement('textarea')
            el.value = text
            el.setAttribute('readonly', '')
            el.style.position = 'fixed'
            el.style.left = '-9999px'
            document.body.appendChild(el)
            el.select()
            const successful = document.execCommand('copy')
            document.body.removeChild(el)
            resolve(successful)
          } catch {
            resolve(false)
          }
        })
    } else {
      resolve(false)
    }
  })
}
