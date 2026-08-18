// `restrict` and `isRestricted` for win32, shaped to slot into `lib/custody.js`.
//
// The policy lives here rather than in C because it is the part worth reading: what
// counts as restricted is a comparison between what was written and what came back,
// and that argument should be legible without a compiler.
const binding = require('./binding')

const os = require('bare-os')

const WIN32 = os.platform() === 'win32'

// Directories carry inherit flags so entries created inside them later are covered;
// files carry none. The caller says which, because guessing from the filesystem
// would mean a stat race between the check and the write.
const FILE_FLAGS = 0
const DIR_FLAGS = 0x1 | 0x2 // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE

function unavailable () {
  if (!WIN32) return 'bare-acl is win32 only; this platform has POSIX modes and `custody.js` uses them'
  if (typeof binding.restrict !== 'function') {
    return 'bare-acl loaded without its win32 entry points, which means the addon was built for another platform'
  }
  return null
}

/**
 * Write an explicit, protected DACL granting only this process's user.
 *
 * @param {string} path
 * @param {boolean} directory  true to carry inherit flags to future children
 */
function restrict (path, directory = false) {
  const why = unavailable()
  if (why !== null) throw new Error(`cannot restrict ${path}: ${why}`)
  binding.restrict(path, directory)
}

/**
 * Read the DACL back and say whether it is exactly what `restrict` writes.
 *
 * Returns `restricted: null` rather than false when the answer cannot be had, so a
 * caller cannot read "we could not look" as "it is open" -- the same discipline
 * `custody.isRestricted` uses, where a boundary is two nulls and there is no
 * boolean to misread.
 *
 * @param {string} path
 * @param {boolean} directory
 * @returns {{ restricted: boolean | null, why: string | null, acl: object | null }}
 */
function isRestricted (path, directory = false) {
  const why = unavailable()
  if (why !== null) return { restricted: null, why, acl: null }

  const acl = binding.inspect(path)
  const wantFlags = directory ? DIR_FLAGS : FILE_FLAGS

  // Every clause is a way the boundary is not what it looks like, and each is
  // reported by name rather than collapsed into one false.
  if (!acl.present) return { restricted: false, why: 'the DACL is absent, which grants everyone everything', acl }
  if (!acl.protected) return { restricted: false, why: 'the DACL is not protected, so it still inherits ACEs from the parent', acl }
  if (acl.aces !== 1) return { restricted: false, why: `the DACL holds ${acl.aces} ACEs and a restricted one holds exactly 1`, acl }
  if (!acl.matches) return { restricted: false, why: 'the single ACE is not for this process user', acl }
  if (acl.mask !== binding.expectedMask()) return { restricted: false, why: `the ACE mask is 0x${acl.mask.toString(16)}, not the 0x${binding.expectedMask().toString(16)} restrict writes`, acl }
  if (acl.flags !== wantFlags) return { restricted: false, why: `the ACE flags are 0x${acl.flags.toString(16)}, not the 0x${wantFlags.toString(16)} a ${directory ? 'directory' : 'file'} should carry`, acl }

  return { restricted: true, why: null, acl }
}

module.exports = { restrict, isRestricted, unavailable, FILE_FLAGS, DIR_FLAGS }
