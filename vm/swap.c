//swap.c

#include "vm/swap.h"

struct block *swap_block;
struct bitmap *swap_slots;
struct lock swap_lock;
const int SECTORS = PGSIZE /  BLOCK_SECTOR_SIZE;

static bool initAlready = false;

void swap_init()
{
    if(!initAlready)
    {
        initAlready = true;
        lock_init(&swap_lock);
        swap_block = block_get_role(BLOCK_SWAP);
        swap_slots = bitmap_create(block_size(swap_block) / SECTORS);
        bitmap_set_all(swap_slots, true);
    }
    
}

void swap_in(int index, void *page)
{
    lock_acquire(&swap_lock);

    for(int i = 0; i < SECTORS; i++)
    {
        block_read(swap_block, index * SECTORS + i, page + (BLOCK_SECTOR_SIZE * i));
    }
    
    bitmap_set(swap_slots, index, true);

    lock_release(&swap_lock);
}

int swap_out(void *page)
{
    swap_init();

    lock_acquire(&swap_lock);

    int index = bitmap_scan(swap_slots, 0, 1, true);

    for(int i = 0; i < SECTORS; i++)
    {
        block_write(swap_block, index * SECTORS + i, page + (BLOCK_SECTOR_SIZE * i));
    }

    bitmap_set(swap_slots, index, false);

    lock_release(&swap_lock);

    return index;
}
