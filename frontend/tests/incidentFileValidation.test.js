import test from 'node:test'
import assert from 'node:assert/strict'
import { validateIncidentFile, validateIncidentFiles } from '../src/utils/incidentFileValidation.js'

function namedBlob(bytes, name, type = '') {
  const blob = new Blob([Uint8Array.from(bytes)], { type })
  Object.defineProperty(blob, 'name', { value: name })
  return blob
}

test('generic ZIP and RAR archives are accepted', async () => {
  const zip = namedBlob([0x50, 0x4b, 0x03, 0x04, 0x00], 'evidence.zip')
  const rar = namedBlob([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00], 'bundle.rar')
  assert.equal(await validateIncidentFile(zip), '')
  assert.equal(await validateIncidentFile(rar), '')
})

test('fake archive and non-log gzip are rejected', async () => {
  const fakeRar = namedBlob([0x00, 0x01], 'evidence.rar')
  const genericGzip = namedBlob([0x1f, 0x8b], 'evidence.gz')
  assert.match(await validateIncidentFile(fakeRar), /文件头校验失败/)
  assert.match(await validateIncidentFile(genericGzip), /不是日志归档/)
})

test('the complete batch is inspected before upload', async () => {
  const valid = namedBlob([0x50, 0x4b, 0x03, 0x04], 'valid.zip')
  const invalid = namedBlob([0x00], 'invalid.exe')
  assert.match(
    await validateIncidentFiles([
      { file: valid, screenshot: false },
      { file: invalid, screenshot: false },
    ]),
    /格式不受支持/,
  )
})
