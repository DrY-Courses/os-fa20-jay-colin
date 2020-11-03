#ifndef VM_SWAP_H
#define VM_SWAP_H

//swap.h

#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "threads/synch.h"

void swap_init();
void swap_in(int index, void *page);
int swap_out(void *page);

#endif