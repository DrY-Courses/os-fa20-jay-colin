#include <debug.h>
#include <round.h>
#include <string.h>

#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

static char zeros[BLOCK_SECTOR_SIZE];

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
    return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
 * within INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static block_sector_t
byte_to_sector(const struct inode *inode, off_t pos)
{
    ASSERT(inode != NULL);
    if (pos < inode->data.length) {
        //return inode->data.start + pos / BLOCK_SECTOR_SIZE;
        if(pos < (122 * BLOCK_SECTOR_SIZE))
        {
            return inode->data.directPointers[pos/BLOCK_SECTOR_SIZE];
        }
        else if(pos < ((122 + 128) * BLOCK_SECTOR_SIZE))
        {
            uint32_t buffer[128];
            block_read(fs_device, inode->data.singleIndirect, buffer);
            uint32_t index = (pos) - ((122 * BLOCK_SECTOR_SIZE));
            return buffer[index / BLOCK_SECTOR_SIZE];
        }
        else
        {
            pos = pos - ((122 + 128) * BLOCK_SECTOR_SIZE);
            uint32_t buffer[128];
            block_read(fs_device, inode->data.doubleIndirect, buffer);
            uint32_t index = (pos) / (128 * BLOCK_SECTOR_SIZE);
            uint32_t second_buffer[128];
            block_read(fs_device, buffer[index], second_buffer);
            uint32_t second_index = (pos - (index * BLOCK_SECTOR_SIZE * 128)) / BLOCK_SECTOR_SIZE;
            return second_buffer[second_index];
        }
        
    } else {
        return -1;
    }
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init(void)
{
    list_init(&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * device.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create(block_sector_t sector, off_t length, int type)
{
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
     * one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL) {
        size_t sectors = bytes_to_sectors(length);
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->type = type;
        disk_inode->singleIndirect = -1;
        disk_inode->doubleIndirect = -1;
        /*if (free_map_allocate(sectors, &disk_inode->start)) {
            block_write(fs_device, sector, disk_inode);
            if (sectors > 0) {
                size_t i;

                for (i = 0; i < sectors; i++) {
                    block_write(fs_device, disk_inode->start + i, zeros);
                }
            }
            success = true;
        }*/

        int d_sectors;
        if(sectors < 122)
            d_sectors = sectors;
        else
            d_sectors = 122;
        

        for(int i = 0; i < d_sectors; i++)
        {
            if (free_map_allocate(1, &disk_inode->directPointers[i])) 
            {
                 block_write(fs_device, disk_inode->directPointers[i], zeros);
            }
        }

        sectors -= d_sectors;

        int si_sectors;

        if(sectors > 0)
        {
            free_map_allocate(1, &disk_inode->singleIndirect);
            block_write(fs_device, disk_inode->singleIndirect, zeros);

            
            if(sectors < 128)
                si_sectors = sectors;
            else
                si_sectors = 128;

            uint32_t buffer[128];
            block_read(fs_device, disk_inode->singleIndirect, &buffer);

            for(int i = 0; i < si_sectors; i++)
            {
                if (free_map_allocate(1, &buffer[i])) 
                {
                    block_write(fs_device, buffer[i], zeros);
                }
            }

            block_write(fs_device, disk_inode->singleIndirect, &buffer);

            sectors -= si_sectors;

        }

        int di_sectors = sectors;
        if(sectors > 0)
        {
            free_map_allocate(1, &disk_inode->doubleIndirect);
            block_write(fs_device, disk_inode->doubleIndirect, zeros);

            uint32_t buffer[128];
            block_read(fs_device, disk_inode->doubleIndirect, &buffer);

            uint32_t s_ptrs = (sectors / 128) + 1;

            for(int i = 0; i < s_ptrs; i++)
            {
                if (free_map_allocate(1, &buffer[i])) 
                {
                    block_write(fs_device, buffer[i], zeros);

                    uint32_t sectors_remaining;
                    if(sectors < 128)
                        sectors_remaining = sectors;
                    else
                        sectors_remaining = 128;


                    uint32_t inner_buffer[128];
                    block_read(fs_device, buffer[i], &buffer);
                    
                    for(int j = 0; j < sectors_remaining; j++)
                    {
                        if(free_map_allocate(1, &inner_buffer[j]))
                        {
                            block_write(fs_device, inner_buffer[j], zeros);
                        }
                    }
                    block_write(fs_device, buffer[i], &inner_buffer);
                }

                sectors -= 128;
            }

            block_write(fs_device, disk_inode->doubleIndirect, &buffer);

            sectors -= si_sectors;

        }

        block_write(fs_device, sector, disk_inode);
        success = true;

        free(disk_inode);
    }
    return success;
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector)
{
    struct list_elem *e;
    struct inode *inode;

    /* Check whether this inode is already open. */
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
         e = list_next(e)) {
        inode = list_entry(e, struct inode, elem);
        if (inode->sector == sector) {
            inode_reopen(inode);
            return inode;
        }
    }

    /* Allocate memory. */
    inode = malloc(sizeof *inode);
    if (inode == NULL) {
        return NULL;
    }

    /* Initialize. */
    list_push_front(&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    block_read(fs_device, inode->sector, &inode->data);
    return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
    if (inode != NULL) {
        inode->open_cnt++;
    }
    return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber(const struct inode *inode)
{
    return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close(struct inode *inode)
{
    /* Ignore null pointer. */
    if (inode == NULL) {
        return;
    }

    /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0) {
        /* Remove from inode list and release lock. */
        list_remove(&inode->elem);

        /* Deallocate blocks if removed. */
        if (inode->removed) {
            free_map_release(inode->sector, 1);
            //free_map_release(inode->data.start,
                             //bytes_to_sectors(inode->data.length));
        }

        free(inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove(struct inode *inode)
{
    ASSERT(inode != NULL);
    inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    while (size > 0) {
        /* Disk sector to read, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0) {
            break;
        }

        if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
            /* Read full sector directly into caller's buffer. */
            block_read(fs_device, sector_idx, buffer + bytes_read);
        } else {
            /* Read sector into bounce buffer, then partially copy
             * into caller's buffer. */
            if (bounce == NULL) {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL) {
                    break;
                }
            }
            block_read(fs_device, sector_idx, bounce);
            memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
    }
    free(bounce);

    return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t
inode_write_at(struct inode *inode, const void *buffer_, off_t size,
               off_t offset)
{
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;

    if (inode->deny_write_cnt) {
        return 0;
    }

    if(size + offset > inode->data.length)
    {
            uint32_t sectors = ((size + offset) / BLOCK_SECTOR_SIZE) + 1;
            inode->data.length = size + offset;

            int d_sectors;
            if(sectors < 122)
                d_sectors = sectors;
            else
                d_sectors = 122;

            for(int i = 0; i < d_sectors; i++)
            {
                if (inode->data.directPointers[i] == 0 && free_map_allocate(1, &inode->data.directPointers[i])) 
                {
                    block_write(fs_device, inode->data.directPointers[i], zeros);
                }
            }

            sectors -= d_sectors;

        int si_sectors;

        if(sectors > 0)
        {
            if(inode->data.singleIndirect == -1)
            {
                free_map_allocate(1, &inode->data.singleIndirect);
                block_write(fs_device, inode->data.singleIndirect, zeros);
            }
            
  
            if(sectors < 128)
                si_sectors = sectors;
            else
                si_sectors = 128;

            uint32_t buffer_ind[128];
            block_read(fs_device, inode->data.singleIndirect, &buffer_ind);

            for(int i = 0; i < si_sectors; i++)
            {
                if (buffer_ind[i] == 0 && free_map_allocate(1, &buffer_ind[i])) 
                {
                    block_write(fs_device, buffer_ind[i], zeros);
                }
            }

            block_write(fs_device, inode->data.singleIndirect, &buffer_ind);

            sectors -= si_sectors;

        }

        int di_sectors = sectors;
        if(sectors > 0)
        {
            if(inode->data.doubleIndirect == -1)
            {
                free_map_allocate(1, &inode->data.doubleIndirect);
                block_write(fs_device, inode->data.doubleIndirect, zeros);
            }
            

            uint32_t buffer[128];
            block_read(fs_device, inode->data.doubleIndirect, &buffer);

            uint32_t s_ptrs = (sectors / 128) + 1;

            for(int i = 0; i < s_ptrs; i++)
            {
                if (buffer[i] == 0 && free_map_allocate(1, &buffer[i])) 
                {
                    block_write(fs_device, buffer[i], zeros);
                }
                    uint32_t sectors_remaining;
                    if(sectors < 128)
                        sectors_remaining = sectors;
                    else
                        sectors_remaining = 128;


                    uint32_t inner_buffer[128];
                    block_read(fs_device, buffer[i], &buffer);
                    
                    for(int j = 0; j < sectors_remaining; j++)
                    {
                        if(inner_buffer[j] == 0 && free_map_allocate(1, &inner_buffer[j]))
                        {
                            block_write(fs_device, inner_buffer[j], zeros);
                        }
                    }
                    block_write(fs_device, buffer[i], &inner_buffer);
                

                sectors -= 128;
            }

            block_write(fs_device, inode->data.doubleIndirect, &buffer);

            sectors -= si_sectors;

        }

        block_write(fs_device, inode->sector, &(inode->data));

    }

    while (size > 0) {
        /* Sector to write, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0) {
            break;
        }

        if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
            /* Write full sector directly to disk. */
            block_write(fs_device, sector_idx, buffer + bytes_written);
        } else {
            /* We need a bounce buffer. */
            if (bounce == NULL) {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL) {
                    break;
                }
            }

            /* If the sector contains data before or after the chunk
             * we're writing, then we need to read in the sector
             * first.  Otherwise we start with a sector of all zeros. */
            if (sector_ofs > 0 || chunk_size < sector_left) {
                block_read(fs_device, sector_idx, bounce);
            } else {
                memset(bounce, 0, BLOCK_SECTOR_SIZE);
            }
            memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
            block_write(fs_device, sector_idx, bounce);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
    }
    free(bounce);

    return bytes_written;
}

/* Disables writes to INODE.
 * May be called at most once per inode opener. */
void
inode_deny_write(struct inode *inode)
{
    inode->deny_write_cnt++;
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write(struct inode *inode)
{
    ASSERT(inode->deny_write_cnt > 0);
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length(const struct inode *inode)
{
    return inode->data.length;
}