cmake_minimum_required(VERSION 3.25)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)

project(bare_acl C)

add_bare_module(bare_acl)

target_sources(
  ${bare_acl}
  PRIVATE
    binding.c
)

# advapi32 carries Get/SetNamedSecurityInfoW, the ACL builders and the token
# calls. Linked only on win32 because the binding compiles to an empty module
# everywhere else -- see binding.c's closing comment on why it exports nothing
# rather than a stub that pretends.
if(WIN32)
  target_link_libraries(
    ${bare_acl}
    PRIVATE
      advapi32
  )
endif()
