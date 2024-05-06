#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <user/syscall.h>
#include <kernel/console.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "pagedir.h"

struct lock file_lock;

struct thread_file_descriptor
{
   int fd;
   struct file *file;
   struct list_elem file_elem;
};

static int get_user (const uint32_t *uaddr) ;
// static bool put_user (uint32_t *udst, uint8_t byte) ;
static bool is_valid_ptr(const uint32_t *uaddr, int args);
static void syscall_handler (struct intr_frame *);
static bool is_valid_ref(const char **uaddr, unsigned size);
static struct file* find_file(int fd);
static void close_file(struct list * cls_file, int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  if(!is_valid_ptr(f->esp, 1)){
        thread_exit(-1);
        return;
  }
  int syscall_no = *(int*)f->esp; // Read the system call from f->esp
  int exit_status;
  const char *buffer;
  int size;
  int fd;
  const char **file_name_ptr;
  struct file *file;
  int i;
  void * ptr;
  switch (syscall_no){
    case SYS_HALT:
      shutdown_power_off(); // Function to halt the machine
      break;
      
    case SYS_EXIT: 
      if(!is_valid_ptr(f->esp, 2)){
        thread_exit(-1);
        return;
      }
      exit_status = *(int *)(f->esp + 4); // Read exit status from f->esp (stack)

      thread_exit(exit_status); // Terminates the current process
      break;
    
    case SYS_WRITE: 
      if(!is_valid_ptr(f->esp, 4)){
        thread_exit(-1);
        return;
      }
      
      fd = *(int*)(f->esp + 4);
      buffer = *(char**)(f->esp + 8); // Read buffer pointer
      size = *(int*)(f->esp + 12); // Read number of bytes
      if(fd == 1)
      {
        putbuf(buffer, size); // Write data to the console
      }
      break;
    case SYS_EXEC:
        if(!is_valid_ptr(f->esp, 2)){
          thread_exit(-1);
          return;
        }
        char **cmd_line = (char **)(f->esp + 4);
        f->eax = process_execute(*cmd_line);
      break;
    case SYS_WAIT:
        if(!is_valid_ptr(f->esp, 2)){
          thread_exit(-1);
          return;
        }
        int child_pid = *(int*)(f->esp + 4);
        f->eax = process_wait(child_pid);
        return;
      break;
    case SYS_CREATE:
      if(!is_valid_ptr(f->esp, 3)){
        thread_exit(-1);
        return;
      }
      file_name_ptr = (const char **)(f->esp + 4);
      if(!is_valid_ref(file_name_ptr, INT32_MAX)){
        thread_exit(-1);
        return;
      }
      unsigned initial_size = *(int*)(f->esp + 8);
      f->eax = filesys_create (*file_name_ptr, initial_size);
      break;
    case SYS_REMOVE:
      if(!is_valid_ptr(f->esp, 2)){
        thread_exit(-1);
        return;
      }
      file_name_ptr = (const char **)(f->esp + 4);
      if(!is_valid_ref(file_name_ptr, INT32_MAX)){
        thread_exit(-1);
        return;
      }
      f->eax = filesys_remove (*file_name_ptr); 
      break;
    case SYS_OPEN:
      if(!is_valid_ptr(f->esp, 2)){
        thread_exit(-1);
        return;
      }
      file_name_ptr = (const char **)(f->esp + 4);
      if(!is_valid_ref(file_name_ptr, INT32_MAX)){
        thread_exit(-1);
        return;
      }
      file = filesys_open (*file_name_ptr);
      if(file == NULL){
        f->eax=-1;
        return;
      }
      f->eax=(int)file;
      break;
    case SYS_FILESIZE:
      if(!is_valid_ptr(f->esp, 2)){
        thread_exit(-1);
        return;
      }
      fd = *(int*)(f->esp + 4);
      file = find_file(fd);
      if(file==NULL){
        f->eax = -1;
        return;
      }
      f->eax = file_length (file);
      break;
    case SYS_READ:
      if(!is_valid_ptr(f->esp, 4)){
        thread_exit(-1);
        return;
      }
      fd = *(int*)(f->esp + 4);
      const char **buffer_ptr = (char**)(f->esp + 8);
      unsigned size = *(unsigned*)(f->esp + 12);
      if(size <=0){
        f->eax=size;
        return;
      }
      if(!is_valid_ref(buffer_ptr, size)){
        f->eax=-1;
        return;
      }
      char *buffer = *buffer_ptr;
      if(fd==0){
        i=0;
        while (i<(int)size){
          buffer[i] = input_getc();
          i++;
        }
        f->eax = size;
        return;
      }
      file = find_file(fd);
      if(file == NULL){
        f->eax = -1;
        return;
      }
      f->eax = file_read_at(file, buffer, size, 0);
      break;
    case SYS_SEEK:
      if (!is_valid_ptr(f->esp, 3)){
          thread_exit(-1);
          return;
      }
      ptr = pagedir_get_page(thread_current()->pagedir, f->esp+4);
      if (!ptr){
          thread_exit(-1);
          return;
      }
      lock_acquire (&file_lock);
      fd = *(int*)(f->esp + 4);
      unsigned ofs = *(unsigned*)(f->esp + 8);
      file = find_file(fd);
      file_seek(file, ofs);
      lock_release(&file_lock);
      break;
    case SYS_TELL:
      if (!is_valid_ptr(f->esp,2)){
      thread_exit(-1);
      return;
      }
      ptr = pagedir_get_page(thread_current()->pagedir, f->esp + 4);
      if (!ptr){
          thread_exit(-1);
          return;
      }
      lock_acquire (&file_lock);
      fd = *(int*)(f->esp + 4);
      file = find_file(fd);
      f->eax = file_tell(file);
      lock_release(&file_lock);
      break;
    case SYS_CLOSE: 
      if (!is_valid_ptr(f->esp,2)){
          thread_exit(-1);
          return;
      }
      ptr = pagedir_get_page(thread_current()->pagedir, f->esp + 4);
      if (!ptr){
          thread_exit(-1);
          return;
      }

      lock_acquire (&file_lock);
      fd = *(int*)(f->esp + 4);
      close_file(&thread_current()->file_descriptor_list, fd);
      lock_release(&file_lock);
      break;
  }
  
}

static void close_file(struct list * cls_file, int fd){

    struct list_elem * e;
    struct thread_file_descriptor * tfd;

    for (e = list_begin(cls_file); e != list_end(cls_file); e = list_next(e)){
            tfd = list_entry(e, struct thread_file_descriptor, file_elem);
            if(tfd->fd == fd){
                file_close(tfd->file);
                  list_remove(e);
            }
        }
} 

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint32_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

// /* Writes BYTE to user address UDST.
//    UDST must be below PHYS_BASE.
//    Returns true if successful, false if a segfault occurred. */
// static bool
// put_user (uint8_t *udst, uint8_t byte)
// {
//   int error_code;
//   asm ("movl $1f, %0; movb %b2, %1; 1:"
//        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
//   return error_code != -1;
// }

static bool
is_valid_ptr(const uint32_t *uaddr, int args){
  int size = args*4;
  if(uaddr==NULL){
    return false;
  }
  if(!is_user_vaddr(uaddr) || !is_user_vaddr(uaddr + size)){
    return false;
  }
  for (int i = 0; i < size; i++)
  {
    if(get_user(uaddr+i)==-1){
      return false;
    }
  }
  return true;
}

static bool
is_valid_ref(const char **uaddr, unsigned size){
  if(get_user((uint32_t *)*uaddr) == -1){
    return false;
  }
  if(*uaddr == NULL){
    return false;
  }
  const char *str = *uaddr;
  int i = 0;

  while (*(str + i) != '\0' && i<size)
  {
    if(get_user((uint32_t *)(str + i + 1)) == -1){
      return false;
    }
    i++;
  }
  if(*uaddr == NULL){
    return false;
  }
  return true;
}

static struct file*
find_file(int fd){
  struct thread *cur = thread_current();
  struct list_elem *f_elem = list_head (&cur->file_descriptor_list);
  struct thread_file_descriptor *file_descriptor;

  while ((f_elem = list_next (f_elem)) != list_end (&cur->file_descriptor_list)) 
  {
    file_descriptor = list_entry (f_elem, struct thread_file_descriptor, file_elem);
    if(fd == file_descriptor->fd){
      break;
    }
  }
  if(fd!=file_descriptor->fd){
    return NULL;
  }
  return file_descriptor->file;
}