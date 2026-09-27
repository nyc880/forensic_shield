# ============================================================================
# CMakeLists.txt — build script for the CVLT native locked-memory layer
# File #5 (was: 5_Cmake.txt)
# Location: app/src/main/cpp/CMakeLists.txt
#
# Step-8 hardening (report item 1). The original file compiled native-lib.cpp
# with bare NDK defaults. This version turns on the full hardening set:
#
#   Compile:
#     -Wall -Wextra -Werror        warnings are errors; nothing ships dirty
#     -fstack-protector-strong     canaries on every function that takes an
#                                  address of a local (arena bookkeeping does)
#     -fvisibility=hidden          only JNI entry points are exported; the
#                                  arena internals are not reachable via dlsym
#     -ffunction-sections/-fdata-sections + --gc-sections
#                                  dead code/data is stripped from the .so
#     -O2 -D_FORTIFY_SOURCE=2      libc hardening (memcpy/strcpy bounds
#                                  checks), gated to optimized builds because
#                                  _FORTIFY_SOURCE requires optimization
#   Link:
#     -Wl,-z,relro -Wl,-z,now      full RELRO: the GOT becomes read-only
#                                  after load (blocks GOT-overwrite exploits)
#     -Wl,-z,noexecstack           non-executable stack
#     -Wl,--gc-sections            strip unreachable sections
#     -Wl,--exclude-libs,ALL       static-lib symbols never leak into the
#                                  dynamic symbol table
# ============================================================================

cmake_minimum_required(VERSION 3.18.1)

project("cvltsec_native" CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(
        cvltsec_native
        SHARED
        native-lib.cpp
)

target_compile_options(
        cvltsec_native
        PRIVATE
        -Wall
        -Wextra
        -Werror
        -fstack-protector-strong
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections
        # _FORTIFY_SOURCE needs an optimization level >= -O1; only apply it
        # (and force -O2) in optimized configurations. Debug builds keep -O0
        # so stepping through the arena logic stays possible.
        $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:-O2;-D_FORTIFY_SOURCE=2>
)

target_link_options(
        cvltsec_native
        PRIVATE
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL
        # 16 KB page alignment (Android 15+ / Google Play requirement)
        -Wl,-z,max-page-size=16384
        -Wl,-z,common-page-size=16384
)

find_library(
        log-lib
        log
)

target_link_libraries(
        cvltsec_native
        ${log-lib}
)
