/*
 * compat.c - implementations of the portability shims declared in compat.h.
 *
 * Each function carries both a POSIX and a Win32 implementation, gated by
 * `_WIN32`. Keeping the two side-by-side (rather than splitting into
 * compat_posix.c / compat_win32.c) makes it obvious at a glance that the
 * two paths produce equivalent behaviour, and only adds one file to the
 * build instead of conditional sources.
 */

#include "compat.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>      /* BCryptGenRandom; link with bcrypt.lib */
#  ifndef STATUS_SUCCESS
#    define STATUS_SUCCESS ((NTSTATUS)0)
#  endif
#else
#  include <errno.h>
#  include <fcntl.h>       /* open, O_RDONLY */
#  include <unistd.h>      /* read, close */
#  include <libgen.h>      /* dirname */
#  include <time.h>        /* clock_gettime, CLOCK_MONOTONIC */
#endif

/* -------------------------------------------------------------------------
 * vg_random_bytes
 * -------------------------------------------------------------------------
 * Both backends fill the buffer fully or fail without writing partial
 * results visible to the caller's logic (we do not advertise partial
 * progress on the return value).
 */
int
vg_random_bytes(void *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return 0;

#ifdef _WIN32
    /* BCRYPT_USE_SYSTEM_PREFERRED_RNG lets us call without first opening
     * an algorithm provider handle - simpler and still cryptographically
     * strong (CNG default RNG). */
    NTSTATUS status = BCryptGenRandom(NULL,
                                      (PUCHAR)buf,
                                      (ULONG)len,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == STATUS_SUCCESS) ? 0 : -1;
#else
    /* /dev/urandom is the canonical OS-provided CSPRNG on Linux, macOS
     * and the BSDs. We loop because read() may return fewer bytes than
     * requested (rare for /dev/urandom but documented behaviour). */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;       /* interrupted by signal, retry */
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        got += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

/* -------------------------------------------------------------------------
 * vg_monotonic_ns
 * -------------------------------------------------------------------------
 * The absolute value of the returned counter is meaningless; callers
 * compute differences between two samples to measure elapsed time.
 */
uint64_t
vg_monotonic_ns(void)
{
#ifdef _WIN32
    /* QueryPerformanceCounter is monotonic and high-resolution on all
     * supported Windows versions. Frequency is fixed at boot, so we
     * cache it on first use. */
    static LARGE_INTEGER freq = { 0 };
    LARGE_INTEGER counter;

    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);

    /* Split the multiplication to avoid overflow at large counter
     * values: (counter / freq) gives whole seconds, (counter % freq)
     * the sub-second remainder which we then scale to nanoseconds. */
    uint64_t whole = (uint64_t)counter.QuadPart / (uint64_t)freq.QuadPart;
    uint64_t rem   = (uint64_t)counter.QuadPart % (uint64_t)freq.QuadPart;
    return whole * 1000000000ULL +
           (rem * 1000000000ULL) / (uint64_t)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/* -------------------------------------------------------------------------
 * vg_dirname
 * -------------------------------------------------------------------------
 * Wraps the platform-native "directory of this path" computation.
 * The Windows version is implemented from scratch because MSVC has no
 * dirname(). The POSIX version copies the input first because POSIX
 * dirname() is allowed to modify its argument.
 */
void
vg_dirname(const char *path, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
        return;

    if (path == NULL || *path == '\0') {
        /* Mirror POSIX dirname("") => "." */
        snprintf(out, out_size, ".");
        return;
    }

#ifdef _WIN32
    /* Walk the string and remember the last separator. Windows accepts
     * both '\\' and '/' in paths, so handle both. */
    const char *last_sep = NULL;
    for (const char *p = path; *p; ++p) {
        if (*p == '\\' || *p == '/')
            last_sep = p;
    }

    if (last_sep == NULL) {
        /* No directory component, e.g. "foo.exe" */
        snprintf(out, out_size, ".");
        return;
    }

    /* Special case: path is just "/" or "\" -> dirname is the same. */
    if (last_sep == path) {
        snprintf(out, out_size, "%c", *last_sep);
        return;
    }

    size_t n = (size_t)(last_sep - path);
    if (n >= out_size)
        n = out_size - 1;
    memcpy(out, path, n);
    out[n] = '\0';
#else
    /* POSIX dirname() may modify its input and may return a pointer to
     * static storage, so we copy in and copy out. */
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    const char *d = dirname(tmp);
    snprintf(out, out_size, "%s", d ? d : ".");
#endif
}
