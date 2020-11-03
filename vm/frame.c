//frame.c

#include "vm/frame.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/swap.h"
#include <hash.h>

void frame_init()
{
    void *base_addr;
    struct ft_entry *fPtr;
    
    list_init(&frame_table);
    lock_init(&frame_lock);

    lock_acquire(&frame_lock);

    while(base_addr = palloc_get_page(PAL_USER))
    {
        fPtr = (struct ft_entry *)malloc(sizeof(struct ft_entry));
        fPtr->page_addr = base_addr;
        fPtr->page = NULL;
        fPtr->isAllocated = false;

        //printf("base address: 0x%x\n", base_addr);
        list_push_back(&frame_table, &(fPtr->list_entry));
    }

    lock_release(&frame_lock);

    current = list_head(&frame_table);
}

struct ft_entry * frame_get(bool zeroes)
{   
    lock_acquire(&frame_lock);

    struct ft_entry *entryPtr = list_entry(current, struct ft_entry, list_entry);
    struct thread *curThread = thread_current();
    
    int x = 0;

    while(x < list_size(&frame_table) && entryPtr->isAllocated)
    {
        current = list_next(current);

        if(current == list_end(&frame_table))
            current = list_begin(&frame_table);
        entryPtr = list_entry(current, struct ft_entry, list_entry);

        x++;
    }

    if(x >= list_size(&frame_table))
    {
        int i  = 0;
    
        while(i < list_size(&frame_table) && pagedir_is_accessed(curThread->pagedir,  entryPtr->page))
        {
            pagedir_set_accessed(curThread->pagedir, entryPtr->page, false);
            current = list_next(current);

            if(current == list_end(&frame_table))
                current = list_begin(&frame_table);
            entryPtr = list_entry(current, struct ft_entry, list_entry);

            i++;
        }
        
        
        if(i >= list_size(&frame_table))
        {
            int j = 0;

            while(j < list_size(&frame_table) && pagedir_is_dirty(curThread->pagedir,  entryPtr->page))
            {
                current = list_next(current);

                if(current == list_end(&frame_table))
                    current = list_begin(&frame_table);
                entryPtr = list_entry(current, struct ft_entry, list_entry);

                j++;
            }
        }

        if(entryPtr->page->writable)
        {
            entryPtr->page->inSwap = true;
            int index = swap_out(entryPtr->page_addr);
            entryPtr->page->swapIndex = index;
        }
        pagedir_clear_page(thread_current()->pagedir, entryPtr->page->upage);       
        
    }

    entryPtr->isAllocated = true;
    
    current = list_next(current);
    if(current == list_end(&frame_table))
        current = list_begin(&frame_table);
        
    if(zeroes)
         memset(entryPtr->page_addr, 0, PGSIZE);

    lock_release(&frame_lock);
    
    return entryPtr;

}

void unallocate_FTE(int tid)
{
    lock_acquire(&frame_lock);

    int i  = 0;
    struct ft_entry *entryPtr = list_entry(current, struct ft_entry, list_entry);
    
    while(i < list_size(&frame_table))
    {
        if(tid == entryPtr->ownerTid)
        {
            pagedir_clear_page(thread_current()->pagedir, entryPtr->page->upage);
            entryPtr->isAllocated = false;
            entryPtr->page = NULL;
        }

        current = list_next(current);

        if(current == list_end(&frame_table))
            current = list_begin(&frame_table);

        entryPtr = list_entry(current, struct ft_entry, list_entry);

        i++;
    }

    lock_release(&frame_lock);
}
