//page.c

#include "frame.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

unsigned page_hash (const struct hash_elem *p, void *aux){

    const struct spt_entry *ptr = hash_entry(p, struct spt_entry, hash_elem);
    return hash_bytes(&(ptr->key), sizeof(ptr->key));
}

bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux){
    
    const struct spt_entry *a = hash_entry(a_, struct spt_entry, hash_elem);
    const struct spt_entry *b = hash_entry(b_, struct spt_entry, hash_elem);

    return a->key < b->key;
}

void grow_stack(void *fault_addr)
{
    struct ft_entry *frame = frame_get(true);

    struct spt_entry *sptPtr = (struct spt_entry *)malloc(sizeof(struct spt_entry));
    sptPtr->fPtr = NULL;
    sptPtr->page_read_bytes = 0;
    sptPtr->page_zero_bytes = PGSIZE;
    sptPtr->kpage = frame->page_addr;
    sptPtr->upage = pg_round_down(fault_addr);
    sptPtr->writable = true;
    sptPtr->key = pg_round_down(fault_addr);
    hash_insert(&(thread_current()->pageTable), &(sptPtr->hash_elem));

    lock_acquire(&frame_lock);
    frame->isAllocated = true;
    frame->page = sptPtr;
    frame->ownerTid = thread_current()->tid;

    if (!install_page(sptPtr->upage, sptPtr->kpage, sptPtr->writable)) {
        palloc_free_page(sptPtr->kpage);
        return;
    }

    lock_release(&frame_lock);
}

void free_SPTE()
{
    struct hash *h = &(thread_current()->pageTable);
    if(h != NULL)
        hash_destroy(h, destroy);
}

void destroy(struct hash_elem *p_, void *aux)
{
    struct spt_entry *p = hash_entry(p_, struct spt_entry, hash_elem);
    free(p);
}