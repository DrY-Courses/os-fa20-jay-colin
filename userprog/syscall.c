#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "string.h"
#include "stdlib.h"
#include "threads/synch.h"

static void syscall_handler(struct intr_frame *);
void sys_halt();
void sys_exit(int status);
pid_t sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
bool chdir(const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);

int add_file(struct thread *cur, struct file *fPtr, char *name);
void remove_file(int fd);
struct file_elem * get_file(int fd);

static struct lock file_system;

void
syscall_init(void)
{
    lock_init(&file_system);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{   
    uint32_t callNo;
    uint32_t *user_esp = f->esp;
    struct thread *t = thread_current();
    
    if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);

    callNo = *user_esp;

    switch(callNo)
    {
        case SYS_HALT:
        {
            sys_halt();
            break;
        }
        
        case SYS_EXIT:
        { 
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
                
            uint32_t status = (uint32_t)(*user_esp);
            sys_exit(status);
            break;
        }

        case SYS_EXEC:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t cmd = (uint32_t)(*user_esp);
            f->eax = sys_exec((char *) cmd);
            break;
        }

        case SYS_WAIT:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t pid = (uint32_t) (*user_esp);
            f->eax = sys_wait((pid_t) pid);
            break;
        }

        case SYS_CREATE:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t file = (uint32_t)(*user_esp);
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t init_size = (uint32_t)(*user_esp);
            f->eax = sys_create((char *) file, (unsigned)init_size);
            break;
        }

        case SYS_REMOVE:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t file = (uint32_t)(*user_esp);
            f->eax = sys_remove((char *) file);
            break;
        }

        case SYS_OPEN:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t file = (uint32_t)(*user_esp);
            f->eax = sys_open((char *) file);
            break;
        } 

        case SYS_FILESIZE:
        {   
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t fd = (uint32_t)(*user_esp);
            f->eax = sys_filesize((int) fd);
            break;
        } 

        case SYS_READ:
        {
            uint32_t fd;
            uint32_t buffer;
            uint32_t size;

            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            fd = (uint32_t) *user_esp;
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            buffer = (uint32_t) *user_esp;
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            size = (uint32_t) *user_esp;

            f->eax = sys_read((int) fd, (void *) buffer, (unsigned) size);

            break;
        } 

        case SYS_WRITE:
        {
            uint32_t fd;
            uint32_t buffer;
            uint32_t size;

            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            fd = (uint32_t) *user_esp;
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            buffer = (uint32_t) *user_esp;
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            size = (uint32_t) *user_esp;

            f->eax = sys_write((int) fd, (void *) buffer, (unsigned) size);

            break;
        } 

        case SYS_SEEK:
        {
            uint32_t fd;
            uint32_t position;

            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            fd = (uint32_t) *user_esp;
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            position = (uint32_t) *user_esp;

            sys_seek((int) fd, (unsigned) position);
            break;
        } 

        case SYS_TELL:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t fd = (uint32_t)(*user_esp);
            f->eax = sys_tell((int) fd);
            break;
        }

        case SYS_CLOSE:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t fd = (uint32_t)(*user_esp);
            sys_close((int) fd);
            break;
        }

        case SYS_CHDIR:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t dir = (uint32_t) *user_esp;
            f->eax = chdir((char *) dir);
            break;
        }

        case SYS_MKDIR:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t dir = (uint32_t) *user_esp;
            f->eax = mkdir((char *) dir);
            break;
        }

        case SYS_READDIR:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t fd = (uint32_t) *user_esp;
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t name = (uint32_t) *user_esp;

            f->eax = readdir((int)fd, (char*) name);
            break;
        }

        case SYS_ISDIR:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t fd = (uint32_t) *user_esp;
            f->eax = isdir((int) fd);
            break;
        }

        case SYS_INUMBER:
        {
            user_esp++;
            if(!is_user_vaddr(user_esp) || pagedir_get_page(t->pagedir, user_esp) == NULL)
                sys_exit(-1);
            uint32_t fd = (uint32_t) *user_esp;
            f->eax = inumber((int) fd);
            break;
        }  

    }

}

// Terminates Pintos by calling shutdown_power_off() (declared in "devices/shutdown.h"). 
// This should be seldom used, because you lose some information about possible deadlock situations, etc. 
void sys_halt()
{
    shutdown_power_off();
}

// Terminates the current user program, returning status to the kernel. 
// If the process's parent waits for it (see below), this is the status that will be returned. 
// Conventionally, a status of 0 indicates success and nonzero values indicate errors. 
void sys_exit(int status)
{
    struct thread *currentThread = thread_current();
    currentThread->exitValue = status;
    char *output = parse(currentThread->name);
    printf("%s: ", output);
    printf("exit(%d)\n", status);
    thread_exit();
}

//Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). 
//Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. 
//Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. 
//You must use appropriate synchronization to ensure this. 
pid_t sys_exec(const char *cmd_line)
{   
    struct thread *t = thread_current();

    if(cmd_line == NULL || !is_user_vaddr(cmd_line) || pagedir_get_page(t->pagedir, cmd_line) == NULL)
       sys_exit(-1);

    return process_execute(cmd_line);
} 


//Waits for a child process pid and retrieves the child's exit status.
//If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. 
//If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. 
//It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait, 
//but the kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel. 
int sys_wait(pid_t pid)
{
    int status = process_wait(pid);
    return status;
}

bool sys_create(const char *file, unsigned initial_size)
{
    struct thread *t = thread_current();
    
    if(file == NULL || !is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
       sys_exit(-1);
       

    lock_acquire(&file_system);
    bool retVal = filesys_create(file, initial_size, 0);
    lock_release(&file_system);

    return retVal;
}

//Deletes the file called file. Returns true if successful, false otherwise. 
//A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. 
bool sys_remove(const char *file)
{
    if(file == NULL)
        sys_exit(-1);

    lock_acquire(&file_system);
    bool retVal = filesys_remove(file);
    lock_release(&file_system);

    return retVal;
}  

//Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
//File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. 
//The open system call will never return either of these file descriptors, which are valid as system call arguments only as explicitly described below.
//Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.
//When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor. 
//Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position.
int sys_open(const char *file)
{
    struct thread *t = thread_current();

    if(file == NULL || !is_user_vaddr(file) || pagedir_get_page(t->pagedir, file) == NULL)
       sys_exit(-1);

    int fd = -1;
    struct thread *cur = thread_current();

    lock_acquire(&file_system);
    struct thread *filePtr = filesys_open(file);
    lock_release(&file_system);

    if(filePtr != NULL)
    {
        fd = add_file(cur, filePtr, file);
    }

    return fd;
}

//Returns the size, in bytes, of the file open as fd. 
int sys_filesize(int fd)
{
    struct file_elem *fPtr = get_file(fd);
    if(fPtr == NULL)
        return -1;

    lock_acquire(&file_system);
    int retVal = file_length(fPtr->file);
    lock_release(&file_system);

    return retVal;
}

//Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), 
//or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). 
int sys_read(int fd, void *buffer, unsigned size)
{
    struct thread *t = thread_current();

    if(buffer == NULL || !is_user_vaddr(buffer))
       sys_exit(-1);

    int retVal = -1;

    if(fd == 0)
    {
        for(int i = 0; i < size; i++)
        {
            ((char *) buffer)[i] = input_getc();
        }
        return size;
    }
    else if (fd != 1)
    {
        struct file_elem *fPtr = get_file(fd);
        if(fPtr == NULL)
            return retVal;

        lock_acquire(&file_system); 
        retVal = file_read(fPtr->file, buffer, size);
        lock_release(&file_system);
    }

    return retVal;
    
}

//Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, 
//which may be less than size if some bytes could not be written.
//Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. 
//The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, 
//or 0 if no bytes could be written at all.
//Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), 
//at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) 
//Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts. 
int sys_write(int fd, const void *buffer, unsigned size)
{
    struct thread *t = thread_current();

    if(buffer == NULL || !is_user_vaddr(buffer) || pagedir_get_page(t->pagedir, buffer) == NULL)
       sys_exit(-1);

    int retVal = -1;

    if(fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    else if (fd != 0)
    {
        struct file_elem *fPtr = get_file(fd);
        if(fPtr == NULL)
            return retVal;
        char *file_name = parse(t->name);
        if(strcmp(fPtr->name, file_name) == 0)
            return 0;

        lock_acquire(&file_system); 
        retVal = file_write(fPtr->file, buffer, size);
        lock_release(&file_system);
    }
    
    return retVal;
    
}

//Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. 
//(Thus, a position of 0 is the file's start.)
//A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. 
//A later write extends the file, filling any unwritten gap with zeros. 
//(However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.) 
//These semantics are implemented in the file system and do not require any special effort in system call implementation. 
void sys_seek(int fd, unsigned position)
{
    struct file_elem *fPtr = get_file(fd);
    if(fPtr == NULL)
        return;

    lock_acquire(&file_system); 
    file_seek(fPtr->file, position);
    lock_release(&file_system); 
}

//Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. 
unsigned sys_tell(int fd)
{
    struct file_elem *fPtr = get_file(fd);
    if(fPtr == NULL)
        return -1;
    
    lock_acquire(&file_system); 
    unsigned retVal = file_tell(fPtr->file);
    lock_release(&file_system); 
    
    return retVal;
}

//Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. 
void sys_close(int fd)
{
    struct file_elem *fPtr = get_file(fd);

    if(fPtr == NULL)
        return;
    list_remove(&(fPtr->elem));

    lock_acquire(&file_system); 
    file_close(fPtr->file);
    lock_release(&file_system); 

    free(fPtr);
    
} 

int add_file(struct thread *cur, struct file *fPtr, char *name)
{
    struct file_elem *file_e = (struct file_elem *)malloc(sizeof(struct file_elem));
    file_e->file = fPtr;
    file_e->fd = cur->fd_counter;
    file_e->name = name;
    int fd = file_e->fd;

    list_push_back(&(cur->file_list), &(file_e->elem));
    cur->fd_counter++;

    return fd;
}

// Changes the current working directory of the process to dir, which may be relative or absolute. Returns true if successful, false on failure. 
bool chdir(const char *dir)
{
    char** args = malloc(strlen(dir)+1);
    int numArgs = 0;
    char *save_ptr, *token;
    char *copy = (char *) malloc((strlen(dir) + 1));
    strlcpy(copy, dir, strlen(dir) + 1);

    struct dir * currentDirectory;

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

    for(int i = 0; i < numArgs; i++)
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

    thread_current()->currDirectory = currentDirectory;

    free(args);
    free(copy);

    return true;

}

//Creates the directory named dir, which may be relative or absolute. Returns true if successful, false on failure. 
//Fails if dir already exists or if any directory name in dir, besides the last, does not already exist. 
//That is, mkdir("/a/b/c") succeeds only if "/a/b" already exists and "/a/b/c" does not. 
bool mkdir (const char *dir)
{
    lock_acquire(&file_system); 
    bool retVal = filesys_create(dir, 512, 1);
    lock_release(&file_system);

    return retVal;
}

//Reads a directory entry from file descriptor fd, which must represent a directory. 
//If successful, stores the null-terminated file name in name, which must have room for READDIR_MAX_LEN + 1 bytes, and returns true. 
//If no entries are left in the directory, returns false.
//"." and ".." should not be returned by readdir.
//If the directory changes while it is open, then it is acceptable for some entries not to be read at all or to be read multiple times. 
//Otherwise, each directory entry should be read once, in any order. 
bool readdir (int fd, char *name)
{
    struct file_elem * fPtr = get_file(fd);

    if(fPtr == NULL)
        return false;
    
    struct file * filePtr = fPtr->file;

    if(filePtr->inode->data.type == 0)
        return false;

    bool retVal = dir_readdir((struct dir *)filePtr, name);
    return retVal;
} 

//Returns true if fd represents a directory, false if it represents an ordinary file. 
bool isdir (int fd)
{
    struct file_elem * fPtr = get_file(fd);
    
    if(fPtr == NULL)
        return false;
    
    struct file * filePtr = fPtr->file;

    return (filePtr->inode->data.type == 1);

}

//Returns the inode number of the inode associated with fd, which may represent an ordinary file or a directory.
//An inode number persistently identifies a file or directory. It is unique during the file's existence. 
//In Pintos, the sector number of the inode is suitable for use as an inode number. 
int inumber (int fd)
{
    struct file_elem * fPtr = get_file(fd);
    
    if(fPtr == NULL)
        return false;
    
    struct file * filePtr = fPtr->file;

    return inode_get_inumber(filePtr->inode);
}

struct file_elem * get_file(int fd)
{
    struct thread *cur = thread_current();

    struct list_elem *e;
    
    for (e = list_begin (&(cur->file_list)); e != list_end (&(cur->file_list)); e = list_next (e))
    {
        struct file_elem *fPtr = list_entry (e, struct file_elem, elem);
        if(fPtr->fd == fd)
            return fPtr;
    }
    return NULL;
}