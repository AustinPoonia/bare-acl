/**
 * `bare-acl`'s round trip, held to the standard `custody.test.js` sets.
 *
 * A check that only ever passes is not evidence, so every case below breaks the
 * boundary a different way and asserts the check reports it — by name, not as a
 * bare `false`.
 *
 * `icacls` does the breaking, and that choice is the point. Mutating the ACL with
 * the OS's own tool rather than with this addon means a negative case cannot pass
 * because of a bug shared between the writing and the reading, which is the failure
 * a self-consistent round trip is otherwise wide open to.
 *
 * The case/`main` shape and the `trash` list follow `custody.test.js`: `bare-tap`
 * counts *cases* rather than assertions, so one `t.pass` per case keeps the sweep's
 * totals meaningful, and a case that throws is reported with its message rather
 * than aborting the file.
 */
const t = require('bare-tap')
const assert = require('bare-assert')
const fs = require('bare-fs')
const path = require('bare-path')
const os = require('bare-os')
const { spawnSync } = require('bare-subprocess')

const acl = require('./index')

/** @type {[string, () => Promise<void> | void][]} */
const cases = []
const test = (/** @type {string} */ n, /** @type {any} */ f) => cases.push([n, f])

const WIN32 = os.platform() === 'win32'

/** @type {string[]} */
const trash = []

function scratch (name) {
  const dir = path.join(os.tmpdir(), `bare-acl-${Date.now()}-${cases.length}-${trash.length}`)
  fs.mkdirSync(dir, { recursive: true })
  trash.push(dir)
  return name === undefined ? dir : path.join(dir, name)
}

function icacls (...args) {
  const r = spawnSync('icacls', args, { encoding: 'utf8' })
  return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}` }
}

// Printed rather than silently skipped, for the reason `custody.test.js` gives: a
// host that could not measure and did not say so is indistinguishable from one that
// measured and passed.
//
// ## Why the marker carries a name, and why it is not plain `# NOT MEASURED:`
//
// Because that exact string is already load-bearing for a *different* finding.
// `all-repos.sh` counts `^# MEASURED:` and `^# NOT MEASURED:` across every log and
// decides one thing with them: whether this run proved `ROADMAP.md` §4's **FAT
// volume** finding. Its own output says so -- "built the volume they assert about",
// "this host can build a FAT volume". Emitting the bare marker from here would have
// been counted as FAT skips, and a Linux CI run would have reported ten unmeasured
// FAT cases when four of them are FAT and six are ACLs.
//
// So this names its finding. The bracket falls before the colon, so it does not match
// the script's anchored pattern and the FAT accounting stays exactly as narrow and as
// correct as it was.
function unmeasured (why) {
  console.log(`# NOT MEASURED [win32-acl]: ${why}`)
}

test('this platform is named rather than silently skipped', () => {
  const why = acl.unavailable()
  if (WIN32) {
    assert.strictEqual(why, null, `win32 should be able to answer, got: ${why}`)
  } else {
    assert.ok(why !== null, 'a non-win32 platform must say why it cannot answer')
    unmeasured(`bare-acl is win32 only and this is ${os.platform()}`)
  }
})

test('a file that was never restricted is not restricted', () => {
  if (!WIN32) return unmeasured(`win32 only; this is ${os.platform()}`)

  const file = scratch('fresh.txt')
  fs.writeFileSync(file, 'secret')

  // The negative case first, because a check that cannot say no is worthless. A
  // fresh file inherits its parent's ACEs, so this is the ordinary state of a file
  // on NTFS and it must not read as protected.
  const { restricted, why } = acl.isRestricted(file)
  assert.strictEqual(restricted, false, 'a fresh inheriting file read as restricted')
  assert.ok(why !== null && why.length > 0, 'a refusal must name its reason')
})

test('restrict then read back is exactly what was written', () => {
  if (!WIN32) return unmeasured(`win32 only; this is ${os.platform()}`)

  const file = scratch('key.json')
  fs.writeFileSync(file, 'secret')

  acl.restrict(file, false)

  const { restricted, why } = acl.isRestricted(file)
  assert.strictEqual(restricted, true, `restrict wrote a DACL isRestricted rejects: ${why}`)
})

test('an extra ACE is noticed, and the count is the reason given', () => {
  if (!WIN32) return unmeasured(`win32 only; this is ${os.platform()}`)

  const file = scratch('key.json')
  fs.writeFileSync(file, 'secret')
  acl.restrict(file, false)
  assert.strictEqual(acl.isRestricted(file).restricted, true, 'precondition: it starts restricted')

  // Grant Everyone read with the OS's own tool. The file is now readable by anyone
  // and nothing about restrict's own ACE changed — precisely the case a check that
  // only looked for its own ACE would miss.
  const granted = icacls(file, '/grant', '*S-1-1-0:(R)')
  assert.strictEqual(granted.code, 0, `icacls /grant failed: ${granted.out}`)

  const { restricted, why } = acl.isRestricted(file)
  assert.strictEqual(restricted, false, 'a DACL with Everyone added still read as restricted')
  assert.ok(/2 ACEs/.test(String(why)), `the reason should name the ACE count, got: ${why}`)
})

test('an unprotected DACL is refused even when it holds one ACE', () => {
  if (!WIN32) return unmeasured(`win32 only; this is ${os.platform()}`)

  const file = scratch('key.json')
  fs.writeFileSync(file, 'secret')
  acl.restrict(file, false)

  // Re-enable inheritance without adding an ACE of our own. Whether the parent
  // actually contributes ACEs is not the point: the DACL stops being protected, and
  // an unprotected DACL is one the parent can widen later without touching the file.
  const inherited = icacls(file, '/inheritance:e')
  assert.strictEqual(inherited.code, 0, `icacls /inheritance:e failed: ${inherited.out}`)

  const { restricted, why } = acl.isRestricted(file)
  assert.strictEqual(restricted, false, 'an unprotected DACL read as restricted')
  assert.ok(why !== null, 'a refusal must name its reason')
})

test('a directory carries inherit flags, a file does not, and both are compared', () => {
  if (!WIN32) return unmeasured(`win32 only; this is ${os.platform()}`)

  const dir = scratch()
  acl.restrict(dir, true)

  assert.strictEqual(acl.isRestricted(dir, true).restricted, true,
    'a restricted directory was rejected when asked about as a directory')

  // The same directory, asked about as though it were a file. The ACE is otherwise
  // identical, so this passes only if the flags are genuinely compared rather than
  // read and discarded.
  const asFile = acl.isRestricted(dir, false)
  assert.strictEqual(asFile.restricted, false, 'inherit flags were not compared')
  assert.ok(/flags/.test(String(asFile.why)), `the reason should name the flags, got: ${asFile.why}`)
})

test('restrict on a path that does not exist throws rather than reporting success', () => {
  if (!WIN32) return unmeasured(`win32 only; this is ${os.platform()}`)

  const missing = path.join(scratch(), 'nope', 'still-nope.json')

  // try/catch and not `assert.throws`, which `bare-assert` does not implement —
  // found by this case failing on it rather than by reading the module. Writing it
  // out also lets the message be asserted, which matters here: the point is that the
  // failure arrives as a named win32 error and not as a silent success.
  let threw = null
  try { acl.restrict(missing, false) } catch (err) { threw = err }

  assert.ok(threw !== null, 'a missing path did not throw')
  assert.ok(/win32 error/.test(String(threw && threw.message)),
    `the throw should name the win32 error, got: ${threw && threw.message}`)
})

async function main () {
  t.plan(cases.length)
  try {
    for (const [name, fn] of cases) {
      try { await fn(); t.pass(name) } catch (err) { t.fail(`${name} — ${err instanceof Error ? err.message : err}`) }
    }
  } finally {
    for (const dir of trash) {
      // The DACLs written above deny deletion to nobody, but a protected directory
      // with inherit flags is still worth un-protecting before removal so a failure
      // here cannot leave the temp tree undeletable by hand later.
      try { icacls(dir, '/reset', '/T', '/C', '/Q') } catch { /* best effort */ }
      try { fs.rmSync(dir, { recursive: true, force: true }) } catch { /* best effort */ }
    }
  }
}

main()
