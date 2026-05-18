/* Fixture: allocation size overflow (CWE-190). */
#include <stdlib.h>
#include <stdint.h>

/* recv() is a known taint source (network input). */
ssize_t recv(int s, void *buf, size_t len, int flags);

void read_packet(int sock) {
    size_t count;
    recv(sock, &count, sizeof(count), 0);
    count = count; /* assign from tainted source */
    /* BUG: count comes from network, no bounds check before multiplication */
    uint32_t *buf = malloc(count * sizeof(uint32_t));  /* alloc-size-overflow */
    if (!buf) return;
    free(buf);
}
