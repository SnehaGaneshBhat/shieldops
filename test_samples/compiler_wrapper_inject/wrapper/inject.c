#include <stdio.h>
/* SIMULATED COMPILER COMPROMISE - DEMONSTRATION ONLY.
   Stands in for code a compromised compiler could add.
   Written by the BuildGuard team. Not real malware. */
__attribute__((constructor))
void __bg_hidden_telemetry(void) {
    FILE *f = fopen("/tmp/bg_demo.txt", "w");
    if (f) {
        fputs("BG-SIMULATED-TELEMETRY", f);
        fclose(f);
    }
}
