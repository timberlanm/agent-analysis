const MB = 1024 * 1024

const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'])
const LOG_EXTENSIONS = new Set(['.json', '.txt', '.log', '.csv', '.out'])
const COMPRESSED_LOG_EXTENSIONS = new Set(['.gz', '.bz2', '.xz'])
const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar'])
const PACKET_EXTENSIONS = new Set(['.pcap', '.pcapng'])

const startsWith = (bytes, header) => (
  header.every((value, index) => bytes[index] === value)
)

function extensionOf(name) {
  const lower = String(name || '').toLowerCase()
  const index = lower.lastIndexOf('.')
  return index >= 0 ? lower.slice(index) : ''
}

function isLogFilename(name) {
  let lower = String(name || '').split(/[\\/]/).pop().toLowerCase()
  const compressedExt = extensionOf(lower)
  if (COMPRESSED_LOG_EXTENSIONS.has(compressedExt)) {
    lower = lower.slice(0, -compressedExt.length)
  }
  if (LOG_EXTENSIONS.has(extensionOf(lower))) return true
  if (/\.(?:log|out|txt|json|csv)(?:\.\d+|\.\d{4}[-_.]\d{1,2}[-_.]\d{1,2})?$/.test(lower)) {
    return true
  }
  return ['access_log', 'error_log', 'messages', 'syslog', 'catalina', 'stdout', 'stderr'].includes(lower)
}

async function readHead(file) {
  const buffer = await file.slice(0, 64 * 1024).arrayBuffer()
  return new Uint8Array(buffer)
}

function exceeds(file, maxMb) {
  return Number(file.size || 0) > maxMb * MB
    ? `${file.name} 大小超过限制（最大 ${maxMb} MB）`
    : ''
}

/**
 * 校验新建告警页面选择的单个文件。返回空字符串表示通过。
 * 后端仍会执行同等校验，前端预检用于保证整批文件通过后才发起上传。
 */
export async function validateIncidentFile(file, { screenshot = false } = {}) {
  const name = String(file?.name || 'attachment')
  const ext = extensionOf(name)
  const bytes = await readHead(file)

  if (screenshot && !IMAGE_EXTENSIONS.has(ext)) {
    return `${name} 不是支持的图片格式`
  }

  if (IMAGE_EXTENSIONS.has(ext)) {
    return exceeds(file, 10)
  }

  if (screenshot) return `${name} 不是支持的图片格式`

  if (PACKET_EXTENSIONS.has(ext)) {
    const pcapHeaders = [
      [0xd4, 0xc3, 0xb2, 0xa1],
      [0xa1, 0xb2, 0xc3, 0xd4],
      [0x4d, 0x3c, 0xb2, 0xa1],
      [0xa1, 0xb2, 0x3c, 0x4d],
    ]
    const valid = ext === '.pcap'
      ? pcapHeaders.some(header => startsWith(bytes, header))
      : startsWith(bytes, [0x0a, 0x0d, 0x0d, 0x0a])
    if (!valid) return `${name} 文件头校验失败，请上传有效的流量包`
    return exceeds(file, 500)
  }

  if (COMPRESSED_LOG_EXTENSIONS.has(ext)) {
    if (!isLogFilename(name)) {
      return `${name} 不是日志归档；GZ/BZ2/XZ 仅支持日志文件`
    }
    const headers = {
      '.gz': [[0x1f, 0x8b]],
      '.bz2': [[0x42, 0x5a, 0x68]],
      '.xz': [[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]],
    }
    if (!headers[ext].some(header => startsWith(bytes, header))) {
      return `${name} 压缩文件头校验失败`
    }
    return exceeds(file, 500)
  }

  if (ARCHIVE_EXTENSIONS.has(ext)) {
    const headers = ext === '.zip'
      ? [[0x50, 0x4b, 0x03, 0x04], [0x50, 0x4b, 0x05, 0x06], [0x50, 0x4b, 0x07, 0x08]]
      : [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00], [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]]
    if (!headers.some(header => startsWith(bytes, header))) {
      return `${name} 压缩文件头校验失败`
    }
    return exceeds(file, 500)
  }

  if (isLogFilename(name) || (!ext && !bytes.includes(0))) {
    if (bytes.includes(0)) return `${name} 不是可识别的文本日志`
    return exceeds(file, 200)
  }

  return `${name} 格式不受支持；可上传图片、PCAP/PCAPNG、日志及 ZIP/RAR 压缩包`
}

export async function validateIncidentFiles(files) {
  for (const item of files) {
    const error = await validateIncidentFile(item.file, { screenshot: item.screenshot })
    if (error) return error
  }
  return ''
}
