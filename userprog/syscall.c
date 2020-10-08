#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "string.h"
#include "stdlib.h"

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

int add_file(struct thread *cur, struct file *fPtr, char *name);
void remove_file(int fd);
struct file_elem * get_file(int fd);


void
syscall_init(void)
{
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

    return filesys_create(file, initial_size);
}

//Deletes the file called file. Returns true if successful, false otherwise. 
//A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. 
bool sys_remove(const char *file)
{
    if(file == NULL)
        sys_exit(-1);

    return filesys_remove(file);
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
    struct thread *filePtr = filesys_open(file);
    
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
    return file_length(fPtr->file);
}

//Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), 
//or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). 
int sys_read(int fd, void *buffer, unsigned size)
{
    struct thread *t = thread_current();

    if(buffer == NULL || !is_user_vaddr(buffer) || pagedir_get_page(t->pagedir, buffer) == NULL)
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
        retVal = file_read(fPtr->file, buffer, size);
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
        retVal = file_write(fPtr->file, buffer, size);
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
    file_seek(fPtr->file, position); 
}

//Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. 
unsigned sys_tell(int fd)
{
    struct file_elem *fPtr = get_file(fd);
    if(fPtr == NULL)
        return -1;
    return file_tell(fPtr->file);
}

//Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. 
void sys_close(int fd)
{
    struct file_elem *fPtr = get_file(fd);

    if(fPtr == NULL)
        return;
    list_remove(&(fPtr->elem));
    file_close(fPtr->file);
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