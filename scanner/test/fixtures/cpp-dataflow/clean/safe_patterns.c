/* Clean fixture: none of these should produce cpp-dataflow findings. */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Safe: pointer set to NULL after free — no UAF, no double-free. */
void safe_free(char *buf, int len) {
    (void)len;
    free(buf);
    buf = NULL;
    /* buf not used after this point */
}

/* Safe: NULL check before deref. */
typedef struct { int x; } Node;
Node *safe_alloc(void) {
    Node *n = malloc(sizeof(Node));
    if (!n) return NULL;  /* null check present */
    n->x = 0;
    return n;
}

/* Safe: < (not <=) loop bound. */
void safe_loop(const char *src, char *dst, int len) {
    for (int i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

/* Safe: bounds-checked allocation. */
#define MAX_ITEMS 1024
void safe_alloc_bounded(size_t count) {
    if (count > MAX_ITEMS) return;  /* bound check present */
    int *buf = malloc(count * sizeof(int));
    if (!buf) return;
    free(buf);
}
