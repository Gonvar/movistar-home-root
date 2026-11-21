/* adbd-pause: block forever, do nothing, ~0% CPU.
 * Used via bind-mount over /system/bin/adbd (init mount namespace only)
 * so init's crash-respawn loop for the vendor-crippled adbd goes quiet.
 * The mount dies on reboot; re-apply from the boot chain if wanted.
 * build: zig cc -target arm-linux-musleabihf -static -O2 -w -Wl,--strip-all
 */
#include <unistd.h>
int main(int argc, char **argv) { (void)argc; (void)argv; for (;;) pause(); }
