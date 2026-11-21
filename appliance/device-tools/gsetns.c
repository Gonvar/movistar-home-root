/* gsetns: run a command inside another process's mount namespace.
 *
 * usage: gsetns <pid|/proc/PID/ns/mnt> cmd [args...]
 *
 * Why: on this box the root-worker lineage (agent -> worker -> /cmd sh)
 * lives in a different mount namespace than init (PID 1).  Any mount we
 * make in our own namespace is invisible to init-spawned services.
 * setns(2) into init's mnt namespace, then exec the tool (e.g. mount).
 *
 * Build (static arm32):
 *   zig cc -target arm-linux-musleabi -O2 -static -o build/gsetns gsetns.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char path[256];
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid|nsfile> cmd [args...]\n", argv[0]);
        return 2;
    }
    if (argv[1][0] == '/')
        snprintf(path, sizeof(path), "%s", argv[1]);
    else
        snprintf(path, sizeof(path), "/proc/%s/ns/mnt", argv[1]);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "gsetns: open %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (setns(fd, CLONE_NEWNS) != 0) {
        fprintf(stderr, "gsetns: setns: %s\n", strerror(errno));
        return 1;
    }
    close(fd);

    execvp(argv[2], &argv[2]);
    fprintf(stderr, "gsetns: exec %s: %s\n", argv[2], strerror(errno));
    return 1;
}
