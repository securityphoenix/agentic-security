/* Fixture: double-free (CWE-415). */
#include <stdlib.h>

void cleanup(char *buf, int error) {
    free(buf);
    if (error) {
        /* BUG: buf is freed again on the error path */
        free(buf);  /* double-free */
    }
}
