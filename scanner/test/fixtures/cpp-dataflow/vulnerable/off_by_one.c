/* Fixture: off-by-one loop bound (CWE-193). */
#include <string.h>

void copy_bytes(const char *src, char *dst, int len) {
    /* BUG: <= len iterates one past end of a [len]-sized buffer */
    for (int i = 0; i <= len; i++) {
        dst[i] = src[i];   /* off-by-one */
    }
}
