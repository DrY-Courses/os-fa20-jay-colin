#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init(bool format)
{
    fs_device = block_get_role(BLOCK_FILESYS);
    if (fs_device == NULL) {
        PANIC("No file system device found, can't initialize file system.");
    }

    inode_init();
    free_map_init();

    if (format) {
        do_format();
    }

    free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done(void)
{
    free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create(const char *name, off_t initial_size, int type)
{
    block_sector_t inode_sector = 0;
    //struct dir *dir = dir_open_root();
    bool success;

    char** args = (char**)malloc((strlen(name)+1));
    int numArgs = 0;
    char *save_ptr, *token;
    char *copy = (char *) malloc((strlen(name) + 1));
    strlcpy(copy, name, strlen(name) + 1);


    struct dir * currentDirectory;

    if(strcmp(copy, "") == 0)
    {
        currentDirectory = dir_open_root();
        success = (currentDirectory != NULL
                        && free_map_allocate(1, &inode_sector)
                        && inode_create(inode_sector, initial_size, type)
                        && dir_add(currentDirectory, copy, inode_sector));

        if (!success && inode_sector != 0) {
            free_map_release(inode_sector, 1);
        }
        dir_close(currentDirectory);

    }
    else
    {
    
        if(copy[0] == '/' || thread_current()->currDirectory == NULL)
        {
            currentDirectory = dir_open_root();
            currentDirectory->inode->data.type = 1;
        }            
        else
        {
            currentDirectory = thread_current()->currDirectory;
        }
        
        while((token = strtok_r(copy, "/", &save_ptr)) != NULL){
            args[numArgs] = token;
            numArgs++;
            copy = NULL;
        }

        for(int i = 0; i < numArgs - 1; i++)
        {
            struct inode * inodePtr;

            if(dir_lookup(currentDirectory, args[i], &inodePtr) == false)
            {
                free(copy);
                return false;
            }
            else if(inodePtr->data.type == 1)
            {
                dir_close(currentDirectory);
                currentDirectory = dir_open(inodePtr);
            }
            else
            {
                inode_close(inodePtr);
            }
        
        }

        success = (currentDirectory != NULL
                        && free_map_allocate(1, &inode_sector)
                        && inode_create(inode_sector, initial_size, type)
                        && dir_add(currentDirectory, args[numArgs - 1], inode_sector));

        if (!success && inode_sector != 0) {
            free_map_release(inode_sector, 1);
        }

        //dir_close(currentDirectory);
    }

    free(copy);

    return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
    //struct dir *dir = dir_open_root();
    struct inode *inode = NULL;

    char** args = malloc(strlen(name)+1);
    int numArgs = 0;
    char *save_ptr, *token;
    char *copy = (char *) malloc((strlen(name) + 1));
    strlcpy(copy, name, strlen(name) + 1);

    struct dir * currentDirectory;

    if(strcmp(copy, "") == 0)
    {
        currentDirectory = dir_open_root();
        currentDirectory->inode->data.type = 1;
        if(currentDirectory != NULL)
        {
            dir_lookup(currentDirectory, copy, &inode);
        }
        dir_close(currentDirectory);

    }
    else if(strcmp(copy, "/") == 0)
    {
        currentDirectory = (struct file *)(dir_open_root());
        currentDirectory->inode->data.type = 1;
        return currentDirectory; 
    }     
    else
    {    

        if(copy[0] == '/' || thread_current()->currDirectory == NULL)
            currentDirectory = dir_open_root();
        else
        {
            currentDirectory = thread_current()->currDirectory;
        }
        

        while((token = strtok_r(copy, "/", &save_ptr)) != NULL){
            args[numArgs] = token;
            numArgs++;
            copy = NULL;
        }


        for(int i = 0; i < numArgs - 1; i++)
        {
            struct inode * inodePtr;
            
            if(dir_lookup(currentDirectory, args[i], &inodePtr) == false)
                return false;
            else if(inodePtr->data.type == 1)
            {
                dir_close(currentDirectory);
                currentDirectory = dir_open(inodePtr);
            }
            else
            {
                inode_close(inodePtr);
            }
            
        }

        if (currentDirectory != NULL) {
            dir_lookup(currentDirectory, args[numArgs - 1], &inode);
        }
        dir_close(currentDirectory);
    }

    free(copy);

    return file_open(inode);
    
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove(const char *name)
{
    //struct dir *dir = dir_open_root();
    bool success;

    char** args = malloc(strlen(name)+1);
    int numArgs = 0;
    char *save_ptr, *token;
    char *copy = (char *) malloc((strlen(name) + 1));
    strlcpy(copy, name, strlen(name) + 1);    

    struct dir * currentDirectory;

    if(strcmp(copy, "/") == 0)
        return false;
    else if(strcmp(copy, "") == 0)
    {
        currentDirectory = dir_open_root();
        currentDirectory->inode->data.type = 1;
        if(currentDirectory != NULL)
        {
            success = copy != NULL && dir_remove(currentDirectory, copy);
        }
        dir_close(currentDirectory);

    }  
    else
    {
        if(copy[0] == '/' || thread_current()->currDirectory == NULL)
            currentDirectory = dir_open_root();
        else
        {
            currentDirectory = thread_current()->currDirectory;
        }
        

        while((token = strtok_r(copy, "/", &save_ptr)) != NULL){
            args[numArgs] = token;
            numArgs++;
            copy = NULL;
        }


        for(int i = 0; i < numArgs - 1; i++)
        {
            struct inode * inodePtr;
            
            if(dir_lookup(currentDirectory, args[i], &inodePtr) == false)
                return false;
            else if(inodePtr->data.type == 1)
            {
                dir_close(currentDirectory);
                currentDirectory = dir_open(inodePtr);
            }
            else
            {
                inode_close(inodePtr);
            }
                
        }  

        success = args[numArgs - 1] != NULL && dir_remove(currentDirectory, args[numArgs - 1]);
        dir_close(currentDirectory);
    }

    free(copy);

    return success;
}

/* Formats the file system. */
static void
do_format(void)
{
    printf("Formatting file system...");
    free_map_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16)) {
        PANIC("root directory creation failed");
    }
    free_map_close();
    printf("done.\n");
}