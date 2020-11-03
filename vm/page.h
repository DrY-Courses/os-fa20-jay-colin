#ifndef VM_PAGE_H
#define VM_PAGE_H
//page.h

#include <hash.h>
#include <stdbool.h>

struct spt_entry {
    size_t page_read_bytes;
    size_t page_zero_bytes;
    int offset;
    struct file *fPtr;
    struct hash_elem hash_elem;
    int key;
    uint8_t *upage;
    uint8_t *kpage;
    bool writable;
    bool inSwap;
    int swapIndex;
};


unsigned page_hash(const struct hash_elem *p, void *aux);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
void grow_stack(void *fault_addr);
void free_SPTE();
void destroy(struct hash_elem *p, void *aux);

#endif