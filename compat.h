/*
 * compat.h - portability layer for vanitygen-plusplus.
 *
 * This header is the single place where platform-specific naming
 * differences (POSIX vs. Win32) are reconciled, plus declarations of
 * thin helpers that hide platform-specific implementations behind a
 * common API.
 *
 * Source files should include this header instead of sprinkling
 * `#ifdef _WIN32` blocks throughout. To add a new platform shim:
 *   1. Add the declaration here.
 *   2. Provide both POSIX and Win32 implementations in compat.c.
 *
 * Note: this header is intentionally narrow. Windows-only glue that is
 * shared with other source files (getopt, gettimeofday, count_processors,
 * ...) lives in winglue.h. compat.h covers the symbols needed by source
 * files that previously assumed a POSIX environment.
 */

#ifndef __VG_COMPAT_H__
#define __VG_COMPAT_H__

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
/* MSVC has SSIZE_T in <BaseTsd.h>; <windows.h> pulls it in too. */
#include <BaseTsd.h>
#if !defined(_SSIZE_T_DEFINED) && !defined(ssize_t)
typedef SSIZE_T ssize_t;
#define _SSIZE_T_DEFINED
#endif

/* MSVC names case-insensitive compare differently. The macros below
 * let cross-platform code use the POSIX names unchanged. */
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#else
/* POSIX: strcasecmp / strncasecmp live in <strings.h>. */
#include <strings.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * vg_random_bytes - fill `buf` with `len` cryptographically secure bytes.
 *
 * Implementation:
 *   - POSIX:   reads /dev/urandom in a loop until `len` bytes are obtained.
 *   - Windows: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
 *
 * Returns 0 on success, -1 on failure (errno / Win32 last error is left
 * set when possible). Does not partially fill on failure.
 */
int vg_random_bytes(void *buf, size_t len);

/*
 * vg_monotonic_ns - return a monotonically increasing nanosecond
 * counter suitable for measuring elapsed time.
 *
 * Implementation:
 *   - POSIX:   clock_gettime(CLOCK_MONOTONIC, ...).
 *   - Windows: QueryPerformanceCounter() scaled to nanoseconds.
 *
 * The absolute value is meaningless; only differences between two
 * calls are. The counter does not wrap within any practical runtime
 * (uint64 nanoseconds covers > 500 years).
 */
uint64_t vg_monotonic_ns(void);

/*
 * vg_dirname - copy the directory component of `path` into `out`.
 *
 * Behaves like POSIX dirname() but is non-destructive (does not modify
 * `path`) and writes into a caller-provided buffer. If `path` has no
 * directory component, "." is written. The output is always null-
 * terminated as long as `out_size > 0`. On Windows both '\' and '/'
 * are treated as separators.
 */
void vg_dirname(const char *path, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* __VG_COMPAT_H__ */
