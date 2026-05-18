/* Fixture: missing NULL check after malloc (CWE-476). */
#include <stdlib.h>
#include <string.h>

typedef struct { int x; } Node;

Node *make_node(void) {
    Node *n = malloc(sizeof(Node));
    /* BUG: n is dereferenced without checking for NULL */
    n->x = 42;   /* missing null check */
    return n;
}
