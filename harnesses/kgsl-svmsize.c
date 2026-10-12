/* kgsl-svmsize.c — is the first SVM GPU write gated by a prior (priming) cmd batch?
 * For each case: optional priming marker batch, then ONE IB containing
 *   CP_MEM_WRITE(SVMaddr, val) ; CP_MEM_WRITE(marker, markval)
 * If mark lands but val doesn't -> mapped but GPU-cache stale.
 * If mark doesn't land     -> SVM write faulted (not mapped).
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
/* build one IB with [SVM write, marker write] and submit it */
static int submit_pair(uint64_t saddr,uint32_t sval,uint32_t mval){
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
    return ioctl(fd,IOCTL_GPU_COMMAND,&gc);
}
static void prime(void){ /* benign batch to a non-SVM marker; separate submit */
    mark[0]=0;
    uint32_t *p=cmd; memset(cmd,0,0x40);
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,mgpu); *p++=0x0F00D000u;
    struct kgsl_command_object cob; memset(&cob,0,sizeof cob);
    cob.gpuaddr=cgpu; cob.size=(uint64_t)(p-cmd)*4; cob.flags=KGSL_CMDLIST_IB;
    struct kgsl_command_object mo; memset(&mo,0,sizeof mo);
    mo.gpuaddr=cgpu; mo.size=0x10000; mo.flags=KGSL_OBJLIST_MEMOBJ; mo.id=cid;
    struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);
    gc.flags=KGSL_CMDBATCH_MEMLIST; gc.context_id=ctx;
    gc.cmdlist=(uint64_t)(uintptr_t)&cob; gc.cmdsize=sizeof cob; gc.numcmds=1;
    gc.objlist=(uint64_t)(uintptr_t)&mo; gc.objsize=sizeof mo; gc.numobjs=1;
    ioctl(fd,IOCTL_GPU_COMMAND,&gc);
}
static void one(const char *tag,uint64_t size,int prewrite,int doprime,uint32_t val){
    struct kgsl_gpuobj_alloc sa; memset(&sa,0,sizeof sa);
    sa.size=size; sa.flags=USE_CPU_MAP; sa.va_len=size;
    if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&sa)<0){ printf("%-16s alloc fail: %s\n",tag,strerror(errno)); return; }
    void *v=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)sa.id<<12);
    if(v==MAP_FAILED){ printf("%-16s mmap fail: %s\n",tag,strerror(errno)); return; }
    struct kgsl_gpuobj_info si; memset(&si,0,sizeof si); si.id=sa.id; ioctl(fd,IOCTL_GPUOBJ_INFO,&si);
    if(prewrite) ((uint32_t*)v)[0]=0x11111111u;
    if(doprime){ prime(); usleep(60000); }
    mark[0]=0;
    int rc=submit_pair(si.gpuaddr,val,0x0F00D000u);
    usleep(200000);
    printf("%-16s gpuaddr=0x%llx pre=%d prime=%d rc=%d -> p0=0x%08x want=0x%08x mark=0x%08x  %s\n",
        tag,(unsigned long long)si.gpuaddr,prewrite,doprime,rc,
        ((volatile uint32_t*)v)[0],val,mark[0],
        (((volatile uint32_t*)v)[0]==val)?"VAL_LAND":
        ((mark[0]==0x0F00D000u)?"MAP_OK_CACHE_STALE":"SVM_FAULT"));
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGALRM,on_alarm); alarm(60);
    printf("== kgsl SVM priming test (uid=%d) ==\n",(int)getuid());
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

    one("1p_noprime",  0x1000,1,0,0x51510001u);
    one("1p_prime",    0x1000,1,1,0x51510002u);
    one("2p_noprime",  0x2000,1,0,0x51510003u);
    one("2p_prime",    0x2000,1,1,0x51510004u);
    one("1p_noprime_nw",0x1000,0,0,0x51510005u);
    one("1p_prime_nw",  0x1000,0,1,0x51510006u);

    { struct kgsl_drawctxt_destroy x={ctx}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n"); return 0;
}
