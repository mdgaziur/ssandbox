#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    int megabytes = 0;
    printf("Starting Memory Limit Test...\n");
    fflush(stdout); // Force output to the memfd immediately before we get killed

    while (1) {
        // Allocate 1 Megabyte
        char *chunk = (char *)malloc(1024 * 1024);

        if (chunk == NULL) {
            // If the kernel returns NULL instead of killing us
            printf("malloc failed at %d MB\n", megabytes);
            return 1;
        }

        // CRITICAL: We must write to the memory to trigger physical allocation!
        memset(chunk, 'A', 1024 * 1024);

        megabytes++;
        printf("Successfully allocated and touched %d MB\n", megabytes);
        fflush(stdout);
    }

    return 0;
}