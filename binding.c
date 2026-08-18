// `bare-acl` -- write a Win32 DACL and read it back, and nothing else.
//
// `ROADMAP.md` §4 item 1. `lib/custody.js` measures a filesystem permission
// boundary by round trip rather than by reading a mode and judging it, because a
// mode can be a property of the mount and lie (macOS FAT returns success for
// `chmod` and stores nothing; Linux `vfat` refuses it outright). On win32 there is
// no mode to round-trip at all -- `custody.js#unavailable` says so in the open:
// "the boundary on this platform is an ACL and nothing in this runtime writes
// one, so there is no answer to give and a comfortable one would be false". This
// is the thing that writes one.
//
// ## A round trip, and emphatically never `effectiveRights`
//
// `restrict` writes an explicit, protected DACL carrying exactly one ACE for the
// current user's SID. `inspect` reads the DACL back and reports its structure.
// The verdict is composed in JS from that structure.
//
// What this deliberately does not do is compute who could actually reach the
// file. `GetEffectiveRightsFromAcl` and friends have to reason across inheritance,
// nested group membership, deny ACEs and privilege overrides such as
// SeBackupPrivilege and SeTakeOwnershipPrivilege -- and an implementation that
// gets any of that subtly wrong answers "private" about something that is not.
// False assurance on a key-custody path is worse than the honest absence of a
// check, which is what ships today. So the only question asked here is "is what I
// read back exactly what I wrote", which is answerable without a model of Windows
// access evaluation.
//
// ## Why PROTECTED_DACL_SECURITY_INFORMATION
//
// Without it the DACL keeps inheriting ACEs from the parent directory, so a file
// can be "restricted" and still carry an inherited Everyone entry. Protecting the
// DACL severs inheritance, which is the only way a single-ACE DACL means what it
// appears to mean. `inspect` therefore also reports SE_DACL_PROTECTED, and JS
// treats an unprotected DACL as not restricted however few ACEs it holds.
//
// ## Directories carry inherit flags and files do not
//
// A directory holding keys must pass the restriction to entries created inside it
// later, so its ACE gets CONTAINER_INHERIT_ACE|OBJECT_INHERIT_ACE. A file's ACE
// gets no flags. The two cases are told apart by the caller rather than guessed
// here, and `inspect` returns the flags it found so the comparison is exact in
// both cases instead of approximately right in one.

#include <assert.h>
#include <bare.h>
#include <js.h>
#include <stdlib.h>

#ifdef _WIN32

#include <windows.h>

#include <aclapi.h>
#include <sddl.h>

#define BARE_ACL_MASK (FILE_ALL_ACCESS)

// The current process user's SID, copied onto the heap. Caller frees.
//
// The token's own buffer is not kept: `GetTokenInformation` hands back a
// TOKEN_USER whose `Sid` points inside that allocation, so holding the SID means
// holding the whole thing or copying it out. Copying is smaller and removes a
// lifetime question from every call site.
static PSID
bare_acl_current_sid(void) {
  HANDLE token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;

  DWORD len = 0;
  GetTokenInformation(token, TokenUser, NULL, 0, &len);
  if (len == 0) {
    CloseHandle(token);
    return NULL;
  }

  TOKEN_USER *user = (TOKEN_USER *) malloc(len);
  if (user == NULL) {
    CloseHandle(token);
    return NULL;
  }

  if (!GetTokenInformation(token, TokenUser, user, len, &len)) {
    free(user);
    CloseHandle(token);
    return NULL;
  }

  DWORD sid_len = GetLengthSid(user->User.Sid);
  PSID sid = (PSID) malloc(sid_len);
  if (sid != NULL && !CopySid(sid_len, sid, user->User.Sid)) {
    free(sid);
    sid = NULL;
  }

  free(user);
  CloseHandle(token);

  return sid;
}

// UTF-8 from JS to UTF-16 for the W APIs. Heap allocated; caller frees.
//
// The wide form is not a nicety: the A variants are code-page dependent, so a
// path holding anything outside the active code page would be silently rewritten
// on the way to the kernel and a key could be protected at a path that is not the
// one asked about.
static WCHAR *
bare_acl_widen(const char *utf8) {
  int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
  if (len <= 0) return NULL;

  WCHAR *wide = (WCHAR *) malloc((size_t) len * sizeof(WCHAR));
  if (wide == NULL) return NULL;

  if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, len) <= 0) {
    free(wide);
    return NULL;
  }

  return wide;
}

static js_value_t *
bare_acl_throw_win32(js_env_t *env, const char *what, DWORD code) {
  char message[512];
  snprintf(message, sizeof(message), "%s failed: win32 error %lu", what, (unsigned long) code);
  js_throw_error(env, NULL, message);
  return NULL;
}

// restrict(path, inherit) -> undefined, throws on failure.
static js_value_t *
bare_acl_restrict(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 2;
  js_value_t *argv[2];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);
  assert(argc == 2);

  char path[MAX_PATH * 4];
  err = js_get_value_string_utf8(env, argv[0], (utf8_t *) path, sizeof(path), NULL);
  assert(err == 0);

  bool inherit;
  err = js_get_value_bool(env, argv[1], &inherit);
  assert(err == 0);

  WCHAR *wide = bare_acl_widen(path);
  if (wide == NULL) return bare_acl_throw_win32(env, "widening the path", GetLastError());

  PSID sid = bare_acl_current_sid();
  if (sid == NULL) {
    free(wide);
    return bare_acl_throw_win32(env, "reading the process token", GetLastError());
  }

  // sizeof(ACCESS_ALLOWED_ACE) already includes four bytes of SidStart, so the
  // SID's first DWORD would be counted twice without subtracting it. Getting this
  // wrong overruns by four bytes, which InitializeAcl will not catch.
  DWORD size = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(sid);

  PACL dacl = (PACL) malloc(size);
  if (dacl == NULL) {
    free(sid);
    free(wide);
    js_throw_error(env, NULL, "out of memory building the DACL");
    return NULL;
  }

  DWORD flags = inherit ? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) : 0;

  if (!InitializeAcl(dacl, size, ACL_REVISION) ||
      !AddAccessAllowedAceEx(dacl, ACL_REVISION, flags, BARE_ACL_MASK, sid)) {
    DWORD code = GetLastError();
    free(dacl);
    free(sid);
    free(wide);
    return bare_acl_throw_win32(env, "building the DACL", code);
  }

  DWORD code = SetNamedSecurityInfoW(
    wide,
    SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
    NULL,
    NULL,
    dacl,
    NULL
  );

  free(dacl);
  free(sid);
  free(wide);

  if (code != ERROR_SUCCESS) return bare_acl_throw_win32(env, "setting the DACL", code);

  return NULL;
}

// inspect(path) -> { aces, protected, present, matches, mask, flags }
//
// Reports structure and decides nothing. `matches` is whether the single ACE, if
// there is exactly one, allows this process's user; the caller compares `mask` and
// `flags` against what it asked for.
static js_value_t *
bare_acl_inspect(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);
  assert(argc == 1);

  char path[MAX_PATH * 4];
  err = js_get_value_string_utf8(env, argv[0], (utf8_t *) path, sizeof(path), NULL);
  assert(err == 0);

  WCHAR *wide = bare_acl_widen(path);
  if (wide == NULL) return bare_acl_throw_win32(env, "widening the path", GetLastError());

  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;

  DWORD code = GetNamedSecurityInfoW(
    wide, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd
  );

  free(wide);

  if (code != ERROR_SUCCESS) return bare_acl_throw_win32(env, "reading the DACL", code);

  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  bool got_control = GetSecurityDescriptorControl(sd, &control, &revision);

  uint32_t aces = 0;
  uint32_t mask = 0;
  uint32_t ace_flags = 0;
  bool matches = false;

  // A NULL DACL is not an empty one: it grants everyone everything. Reported as
  // present=false so JS cannot mistake "no ACEs found" for a closed boundary.
  if (dacl != NULL) {
    ACL_SIZE_INFORMATION size_info;
    if (GetAclInformation(dacl, &size_info, sizeof(size_info), AclSizeInformation)) {
      aces = (uint32_t) size_info.AceCount;
    }

    if (aces == 1) {
      ACCESS_ALLOWED_ACE *ace = NULL;
      if (GetAce(dacl, 0, (void **) &ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
        mask = (uint32_t) ace->Mask;
        ace_flags = (uint32_t) ace->Header.AceFlags;

        PSID sid = bare_acl_current_sid();
        if (sid != NULL) {
          matches = EqualSid((PSID) &ace->SidStart, sid) ? true : false;
          free(sid);
        }
      }
    }
  }

  bool is_protected = got_control && (control & SE_DACL_PROTECTED) != 0;
  bool present = dacl != NULL && got_control && (control & SE_DACL_PRESENT) != 0;

  if (sd != NULL) LocalFree(sd);

  js_value_t *result;
  err = js_create_object(env, &result);
  assert(err == 0);

#define SET_U32(name, value) \
  { \
    js_value_t *val; \
    err = js_create_uint32(env, value, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, result, name, val); \
    assert(err == 0); \
  }

#define SET_BOOL(name, value) \
  { \
    js_value_t *val; \
    err = js_get_boolean(env, value, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, result, name, val); \
    assert(err == 0); \
  }

  SET_U32("aces", aces)
  SET_U32("mask", mask)
  SET_U32("flags", ace_flags)
  SET_BOOL("protected", is_protected)
  SET_BOOL("present", present)
  SET_BOOL("matches", matches)

#undef SET_U32
#undef SET_BOOL

  return result;
}

static js_value_t *
bare_acl_expected_mask(js_env_t *env, js_callback_info_t *info) {
  js_value_t *val;
  int err = js_create_uint32(env, (uint32_t) BARE_ACL_MASK, &val);
  assert(err == 0);
  return val;
}

#endif

static js_value_t *
bare_acl_exports(js_env_t *env, js_value_t *exports) {
  int err;

#define V(name, fn) \
  { \
    js_value_t *val; \
    err = js_create_function(env, name, -1, fn, NULL, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, exports, name, val); \
    assert(err == 0); \
  }

#ifdef _WIN32
  V("restrict", bare_acl_restrict)
  V("inspect", bare_acl_inspect)
  V("expectedMask", bare_acl_expected_mask)
#endif

#undef V

  // On every other platform this module exports nothing, and index.js turns that
  // into a named refusal. A stub that pretended to work would be the exact
  // failure mode custody.js is written to avoid.

  return exports;
}

BARE_MODULE(bare_acl, bare_acl_exports)
