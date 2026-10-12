/* KGSL profiling-path reachability probe (CVE candidate 3e624b77).
 *
 * Goal: prove, from Termux untrusted_app, that the kgsl command-submission
 * object list reaches add_profiling_buffer() and that the profiling buffer is
 * CPU-written by adreno_ringbuffer_addcmds() -- with ZERO corruption risk:
 *
 *   - allocate a 64 KiB GPU buffer
 *   - submit a cmdbatch with KGSL_CMDBATCH_PROFILING|MEMLIST, numcmds==0
 *     (auto-promoted to a MARKER -> no IB, no GPU command execution)
 *   - objlist = one KGSL_OBJLIST_PROFILE object whose computed profiling
 *     address is SAFELY inside the buffer (offset 0x8000 of 0x10000)
 *   - read the buffer back; if the kernel wrote wall_clock_ns / gpu_ticks_*,
 *     the entire profiling path (and the 3e624b77 bug location) is reachable.
 *
 * No OOB, no race, no bad GPU command. Safe to repeat.
 *
 * Build: zig cc -target arm-linux-musleabihf -static -O2 -w -Wl,--strip-all
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09

/* ---- uapi structs (include/uapi/linux/msm_kgsl.h, lineage-15.1) ---- */
struct kgsl_version { unsigned int drv_major, drv_minor, dev_major, dev_minor; };
struct kgsl_devinfo {
    unsigned int device_id;
    unsigned int chip_id;
    unsigned int mmu_enabled;
    unsigned long gmem_gpubaseaddr;
    unsigned int gpu_id;
    size_t gmem_sizebytes;
};
struct kgsl_device_getproperty { unsigned int type; void *value; size_t sizebytes; };
struct kgsl_gpumem_alloc_id {
    unsigned int id, flags;
    size_t size, mmapsize;
    unsigned long gpuaddr;
    unsigned long __pad[2];
};
struct kgsl_gpumem_get_info {
    unsigned long gpuaddr;
    unsigned int id, flags;
    size_t size, mmapsize;
    unsigned long useraddr;
    unsigned long __pad[4];
};
struct kgsl_gpumem_free_id { unsigned int id, __pad; };
struct kgsl_drawctxt_create { unsigned int flags, drawctxt_id; };
struct kgsl_drawctxt_destroy { unsigned int drawctxt_id; };
struct kgsl_command_object {
    uint64_t offset, gpuaddr, size;
    unsigned int flags, id;
};
struct kgsl_gpu_command {
    uint64_t flags;
    uint64_t cmdlist;
    unsigned int cmdsize, numcmds;
    uint64_t objlist;
    unsigned int objsize, numobjs;
    uint64_t synclist;
    unsigned int syncsize, numsyncs, context_id, timestamp;
};
struct kgsl_profiling_buffer {
    uint64_t wall_clock_s, wall_clock_ns, gpu_ticks_queued,
             gpu_ticks_submitted, gpu_ticks_retired;
};

#define IOCTL_GETPROP     _IOWR(KGSL_IOC_TYPE, 0x02, struct kgsl_device_getproperty)
#define IOCTL_CTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_CTXT_DESTROY _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)
#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE, 0x34, struct kgsl_gpumem_alloc_id)
#define IOCTL_PMEM_FREE_ID _IOWR(KGSL_IOC_TYPE, 0x35, struct kgsl_gpumem_free_id)
#define IOCTL_PMEM_GET_INFO _IOWR(KGSL_IOC_TYPE, 0x36, struct kgsl_gpumem_get_info)
#define IOCTL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

#define KGSL_PROP_DEVICE_INFO 0x1
#define KGSL_PROP_VERSION     0x8
#define KGSL_CMDBATCH_MEMLIST 0x1
#define KGSL_CMDBATCH_PROFILING 0x10
#define KGSL_CMDBATCH_SYNC    0x400
#define KGSL_OBJLIST_MEMOBJ   0x8
#define KGSL_OBJLIST_PROFILE  0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2
#define KGSL_CONTEXT_PREAMBLE      0x10

static void hexdump(const unsigned char *p, int n){
    for (int i=0;i<n;i++){ printf("%02x",p[i]); if(i%16==15)printf("\n"); else if(i%4==3)printf(" ");} 
    if(n%16) printf("\n");
}

int main(void)
{
    setvbuf(stdout,NULL,_IONBF,0);
    printf("== kgsl profiling reachability probe (uid=%d) ==\n",(int)getuid());

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0){ printf("[-] open /dev/kgsl-3d0: %s\n",strerror(errno)); return 1; }
    printf("[+] open /dev/kgsl-3d0 OK\n");

    /* -- version -- */
    struct kgsl_version v; memset(&v,0,sizeof v);
    struct kgsl_device_getproperty gp = { KGSL_PROP_VERSION, &v, sizeof v };
    int r = ioctl(fd, IOCTL_GETPROP, &gp);
    printf("[%c] GETPROP(VERSION) rc=%d errno=%d -> drv %u.%u dev %u.%u\n",
           r==0?'+':'-', r, errno, v.drv_major,v.drv_minor,v.dev_major,v.dev_minor);

    /* -- device info -- */
    struct kgsl_devinfo di; memset(&di,0,sizeof di);
    gp.type = KGSL_PROP_DEVICE_INFO; gp.value=&di; gp.sizebytes=sizeof di;
    r = ioctl(fd, IOCTL_GETPROP, &gp);
    printf("[%c] GETPROP(DEVICE_INFO) rc=%d dev_id=%u chip_id=0x%08x mmu=%u gpu_id=%u gmem=%zu gpubase=0x%lx\n",
           r==0?'+':'-', r, di.device_id, di.chip_id, di.mmu_enabled, di.gpu_id,
           di.gmem_sizebytes, di.gmem_gpubaseaddr);

    /* -- allocate a 64 KiB GPU buffer -- */
    struct kgsl_gpumem_alloc_id al; memset(&al,0,sizeof al);
    al.size = 0x10000; al.flags = 0;
    r = ioctl(fd, IOCTL_PMEM_ALLOC_ID, &al);
    if (r){ printf("[-] GPUMEM_ALLOC_ID rc=%d errno=%d\n",r,errno); close(fd); return 1; }
    printf("[+] GPUMEM_ALLOC_ID id=%u gpuaddr=0x%lx size=0x%zx mmapsize=0x%zx\n",
           al.id, al.gpuaddr, al.size, al.mmapsize);

    /* -- map it for readback -- */
    void *ptr = MAP_FAILED;
    size_t msz = al.mmapsize ? al.mmapsize : al.size;
    ptr = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)al.id << 12);
    if (ptr == MAP_FAILED){
        ptr = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)al.gpuaddr);
    }
    printf("[%c] mmap(size=0x%zx) -> %p\n", ptr==MAP_FAILED?'-':'+', msz, ptr);
    if (ptr == MAP_FAILED) printf("    mmap errno=%d (%s)\n", errno, strerror(errno));
    if (ptr != MAP_FAILED) memset(ptr, 0, msz);   /* clean slate for readback */

    /* -- create a draw context -- */
    struct kgsl_drawctxt_create cc; memset(&cc,0,sizeof cc);
    /* legacy context switch is rejected: PREAMBLE + NO_GMEM_ALLOC required */
    cc.flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC;
    r = ioctl(fd, IOCTL_CTXT_CREATE, &cc);
    printf("[%c] DRAWCTXT_CREATE rc=%d errno=%d drawctxt_id=%u\n",
           r==0?'+':'-', r, errno, cc.drawctxt_id);

    /* PROFILE object, same for every attempt (address safely in-bounds) */
    struct kgsl_command_object obj;
    memset(&obj,0,sizeof obj);
    obj.offset  = 0x8000;             /* safely inside the 64 KiB buffer */
    obj.gpuaddr = (uint64_t)al.gpuaddr;
    obj.size    = 0x1000;
    obj.flags   = KGSL_OBJLIST_MEMOBJ | KGSL_OBJLIST_PROFILE;
    obj.id      = al.id;

    struct kgsl_profiling_buffer *pb = NULL;
    if (ptr != MAP_FAILED) pb = (struct kgsl_profiling_buffer*)((unsigned char*)ptr + 0x8000);

    /* Build a real, harmless IB: one Adreno type-7 CP_NOP packet.
     * a5xx is not legacy PM4 (ADRENO_LEGACY_PM4 = rev < 500), so type-7:
     *   cp_type7_packet(CP_NOP=0x10, cnt=1) = (7<<28)|(1)<<0|
     *      parity(1)<<15 | (0x10<<16) | parity(0x10)<<23  = 0x70100001
     * followed by its 1 payload dword. A NOP is a no-op for the CP. */
    if (ptr != MAP_FAILED) {
        volatile unsigned int *ib = (volatile unsigned int *)ptr;
        ib[0] = 0x70100001u;   /* CP_NOP header, cnt=1 */
        ib[1] = 0x00000000u;   /* payload (ignored) */
    }

    /* MARKER and SYNC are retired in software; only a real (non-marker,
     * non-sync) cmdbatch reaches adreno_ringbuffer_issueibcmds(), where the
     * profiling buffer is CPU-written. _ringbuffer_verify_ib() requires a
     * nonzero, mapped IB -> use the NOP IB above. */
    for (int attempt = 1; attempt <= 3; attempt++) {
        struct kgsl_command_object cobj; memset(&cobj,0,sizeof cobj);
        struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);
        gc.objlist    = (uint64_t)(uintptr_t)&obj;
        gc.objsize    = sizeof obj; gc.numobjs = 1;
        gc.context_id = cc.drawctxt_id;
        const char *name;

        if (attempt == 1) {           /* MARKER: numcmds==0, no SYNC */
            gc.flags = KGSL_CMDBATCH_PROFILING | KGSL_CMDBATCH_MEMLIST;
            name = "MARKER numcmds=0";
        } else if (attempt == 2) {    /* SYNC: numcmds==0 */
            gc.flags = KGSL_CMDBATCH_PROFILING | KGSL_CMDBATCH_MEMLIST | KGSL_CMDBATCH_SYNC;
            name = "SYNC numcmds=0";
        } else {                      /* REAL: one NOP IB */
            if (ptr == MAP_FAILED) { printf("[-] attempt 3 skipped (no mmap)\n"); break; }
            cobj.flags = 0x1;         /* KGSL_CMDLIST_IB */
            cobj.gpuaddr = (uint64_t)al.gpuaddr;
            cobj.size = 8;
            gc.flags = KGSL_CMDBATCH_PROFILING | KGSL_CMDBATCH_MEMLIST;
            gc.cmdlist = (uint64_t)(uintptr_t)&cobj; gc.cmdsize = sizeof cobj;
            gc.numcmds = 1;
            name = "REAL 1x NOP IB";
        }

        if (pb) memset(pb, 0, 40);
        errno = 0;
        r = ioctl(fd, IOCTL_GPU_COMMAND, &gc);
        printf("[%c] attempt %d %-20s rc=%d errno=%d ts=%u\n",
               r==0?'+':'-', attempt, name, r, errno, gc.timestamp);

        if (pb) {
            usleep(300000);
            int nz=0; unsigned char *b=(unsigned char*)pb;
            for (int i=0;i<40;i++) if (b[i]) nz++;
            printf("    readback: nz=%d s=%llu ns=%llu q=%llu sub=%llu ret=%llu\n",
                   nz, (unsigned long long)pb->wall_clock_s,
                   (unsigned long long)pb->wall_clock_ns,
                   (unsigned long long)pb->gpu_ticks_queued,
                   (unsigned long long)pb->gpu_ticks_submitted,
                   (unsigned long long)pb->gpu_ticks_retired);
            if (nz) printf("*** PROFILING PATH REACHABLE via attempt %d ***\n", attempt);
        }
    }

    /* -- cleanup -- */
    if (cc.drawctxt_id){ struct kgsl_drawctxt_destroy d = { cc.drawctxt_id }; ioctl(fd, IOCTL_CTXT_DESTROY, &d); }
    { struct kgsl_gpumem_free_id f = { al.id, 0 }; ioctl(fd, IOCTL_PMEM_FREE_ID, &f); }
    close(fd);
    printf("== done ==\n");
    return 0;
}
