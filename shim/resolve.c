/* A name's lookup with a time limit, for socket.goose's connect, on every
   platform: net_resolve_within runs the platform shim's net_resolve on a
   thread of its own and waits for it up to the limit. A caller past its
   limit stops waiting, and the thread finishes the lookup alone and frees
   it, since no system resolver can be stopped midway. Every lookup, waited
   for or not, holds one of RESOLVE_THREADS, so lookups that hang can't pile
   up threads: one past them fails at once with EAGAIN, as a lookup that
   failed for now does.

   Returns what net_resolve does, or -ETIMEDOUT past the limit. The name
   and the addresses are copied, so no thread keeps a pointer into Goose
   memory after the call returns. */
#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#endif

#pragma pack(push, 1)
typedef struct { uint8_t *data; int64_t len; } net_bytes;
#pragma pack(pop)

int32_t net_resolve(net_bytes host, net_bytes out);

#define RESOLVE_THREADS 32
#define RESOLVE_ADDRESSES 8

typedef struct {
    char name[256];
    int64_t len;
    uint8_t out[16 * RESOLVE_ADDRESSES];
    int32_t result;
#ifdef _WIN32
    HANDLE done;
    volatile LONG refs;
#else
    int pipe[2];   /* the thread writes a byte to pipe[1] once result is set */
    atomic_int refs;
#endif
} resolve_job;

#ifdef _WIN32

static volatile LONG running;

static int claim(void) {
    if (InterlockedIncrement(&running) <= RESOLVE_THREADS) return 1;
    InterlockedDecrement(&running);
    return 0;
}

static void unclaim(void) { InterlockedDecrement(&running); }

/* The caller's and the thread's hold on job: the last to let go frees it. */
static void let_go(resolve_job *job) {
    if (InterlockedDecrement(&job->refs) != 0) return;
    CloseHandle(job->done);
    free(job);
}

static DWORD WINAPI resolve_thread(LPVOID arg) {
    resolve_job *job = arg;
    job->result = net_resolve((net_bytes){ (uint8_t *)job->name, job->len },
                              (net_bytes){ job->out, (int64_t)sizeof job->out });
    SetEvent(job->done);
    let_go(job);
    unclaim();
    return 0;
}

static int start(resolve_job *job) {
    job->done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!job->done) return 0;
    HANDLE t = CreateThread(NULL, 256 * 1024, resolve_thread, job, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!t) {
        CloseHandle(job->done);
        return 0;
    }
    CloseHandle(t);
    return 1;
}

static int wait_done(resolve_job *job, int32_t ms) {
    return WaitForSingleObject(job->done, (DWORD)ms) == WAIT_OBJECT_0;
}

#else

static atomic_int running;

static int claim(void) {
    if (atomic_fetch_add(&running, 1) < RESOLVE_THREADS) return 1;
    atomic_fetch_sub(&running, 1);
    return 0;
}

static void unclaim(void) { atomic_fetch_sub(&running, 1); }

static void let_go(resolve_job *job) {
    if (atomic_fetch_sub(&job->refs, 1) != 1) return;
    close(job->pipe[0]);
    close(job->pipe[1]);
    free(job);
}

static void *resolve_thread(void *arg) {
    resolve_job *job = arg;
    job->result = net_resolve((net_bytes){ (uint8_t *)job->name, job->len },
                              (net_bytes){ job->out, (int64_t)sizeof job->out });
    char one = 1;
    while (write(job->pipe[1], &one, 1) < 0 && errno == EINTR) {}
    let_go(job);
    unclaim();
    return NULL;
}

static int start(resolve_job *job) {
    if (pipe(job->pipe) != 0) return 0;
    fcntl(job->pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(job->pipe[1], F_SETFD, FD_CLOEXEC);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 256 * 1024);
    pthread_t t;
    int ok = pthread_create(&t, &attr, resolve_thread, job) == 0;
    pthread_attr_destroy(&attr);
    if (!ok) {
        close(job->pipe[0]);
        close(job->pipe[1]);
    }
    return ok;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int wait_done(resolve_job *job, int32_t ms) {
    int64_t until = now_ms() + ms;
    for (;;) {
        struct pollfd p = { .fd = job->pipe[0], .events = POLLIN };
        int64_t left = until - now_ms();
        int r = poll(&p, 1, left > 0 ? (int)left : 0);
        if (r > 0) return 1;
        if (r == 0 || errno != EINTR) return 0;
    }
}

#endif

int32_t net_resolve_within(net_bytes host, net_bytes out, int32_t ms) {
    if (ms < 0) return net_resolve(host, out);
    if (ms == 0) return -110;
    if (host.len <= 0 || host.len >= 256) return -22;
    if (!claim()) return -11;
    resolve_job *job = calloc(1, sizeof *job);
    if (!job) {
        unclaim();
        return -11;
    }
    memcpy(job->name, host.data, (size_t)host.len);
    job->len = host.len;
    job->refs = 2;
    if (!start(job)) {
        free(job);
        unclaim();
        return -11;
    }
    int32_t r = -110;
    if (wait_done(job, ms)) {
        r = job->result;
        if (r > 0) {
            int64_t n = (int64_t)r * 16 <= out.len ? (int64_t)r * 16 : out.len / 16 * 16;
            memcpy(out.data, job->out, (size_t)n);
            r = (int32_t)(n / 16);
        }
    }
    let_go(job);
    return r;
}
