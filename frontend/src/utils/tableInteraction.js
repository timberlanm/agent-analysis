const INTERACTIVE_SELECTOR = [
  'button',
  'a',
  'input',
  'textarea',
  'select',
  '[role="button"]',
  '[contenteditable="true"]',
].join(',')

export function shouldIgnoreRowClick(event, selectionText) {
  const target = event?.target
  if (target?.closest?.(INTERACTIVE_SELECTOR)) return true

  let selected = selectionText
  if (selected === undefined && typeof window !== 'undefined') {
    selected = window.getSelection?.()?.toString() || ''
  }
  return String(selected || '').trim().length > 0
}

