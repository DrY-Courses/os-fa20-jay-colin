#ifndef VM_FRAME_H
#define VM_FRAME_H

//frame.h

#include <stdbool.h>
#include "threads/synch.h"
#include "vm/page.h"

struct list frame_table;
static struct list_elem *current;
struct lock frame_lock;

struct ft_entry{
    void *page_addr;
    struct spt_entry *page;
    struct list_elem list_entry;
    bool isAllocated;
    int ownerTid;
    struct thread *owner;
};

void frame_init();
struct ft_entry* frame_get(bool zeroes);
void unallocate_FTE(int tid);

#endif