/* Fixture: use-after-free (CWE-416).
   The scanner should fire on the line that dereferences p after free(). */
#include <stdlib.h>
#include <string.h>

void process_data(int len) {
    char *p = malloc(len);
    if (!p) return;
    memset(p, 0, len);
    free(p);
    /* BUG: p is accessed after being freed */
    p[0] = 'x';    /* use-after-free */
}
