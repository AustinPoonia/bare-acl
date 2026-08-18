# bare-acl

Write a Win32 DACL and read it back. A round trip, never effective rights.

`ROADMAP.md` §4 item 1. `lib/custody.js` measures a filesystem permission boundary
by round trip rather than by reading a mode and judging it, because a mode can be a
property of the mount and lie — macOS FAT returns success for `chmod` and stores
nothing, and Linux `vfat` refuses it outright with `EPERM`. On win32 there is no
mode to round-trip at all, which `custody.js#unavailable` says in the open:

> the boundary on this platform is an ACL and nothing in this runtime writes one,
> so there is no answer to give and a comfortable one would be false

This is the thing that writes one.

## The two verbs

- **`restrict(path, directory)`** writes an explicit, **protected** DACL carrying
  exactly one ACE, for the current process user's SID.
- **`isRestricted(path, directory)`** reads the DACL back and answers whether it is
  exactly what `restrict` writes — reporting *which* clause failed rather than a
  bare `false`.

A directory's ACE carries `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE` so entries
created inside it later are covered; a file's carries no flags. The caller says
which, because inferring it from the filesystem would put a stat race between the
check and the write.

## Why never `effectiveRights`

Computing who could actually reach a file means reasoning across inheritance,
nested group membership, deny ACEs, and privilege overrides such as
`SeBackupPrivilege` and `SeTakeOwnershipPrivilege`. An implementation that gets any
of that subtly wrong answers "private" about something that is not, and false
assurance on a key-custody path is worse than the honest absence of a check — which
is what shipped before this existed. So the only question asked here is *is what I
read back exactly what I wrote*, which is answerable without a model of Windows
access evaluation.

`PROTECTED_DACL_SECURITY_INFORMATION` is load-bearing for the same reason: without
it the DACL keeps inheriting from the parent, so a file can hold one ACE and still
be readable by everyone. Removing that flag turns three cases in `test.js` red.

## Measured

Built with clang-cl 22.1.8 targeting `aarch64-pc-windows-msvc` and run on Windows
11 Pro ARM64 (build 26200) against real NTFS: **7 cases, 7 ok, exit 0**. Four of
them are adversarial and break the boundary using `icacls`, the OS's own tool, so a
negative case cannot pass because of a bug shared between the writing and the
reading — the failure a self-consistent round trip is otherwise wide open to.

`prebuilds/win32-x64` is **not** built here: this addon has only ever been compiled
and executed on ARM64. The x64 binary is produced and exercised by CI, because
shipping a native binary that has never been run anywhere is the failure this
project keeps refusing.
