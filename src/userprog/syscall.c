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
#include "threads/malloc.h"


struct thread_file_descriptor
{
   unsigned int fd;
   struct file *file;
   struct list_elem file_elem;
};
static void *get_ptr(const unsigned char *uaddr);
static void syscall_handler (struct intr_frame *);
static struct file* find_file(unsigned int fd);
static void close_file(struct list* cls_file, unsigned int fd);
static unsigned int open_file(struct file* file);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  const unsigned char *esp_tmp = f->esp;
  void *arg0 = get_ptr(esp_tmp);
  if(arg0 == NULL)
  {
    thread_exit(-1);
    return;
  }
  int syscall_no = *(int *)arg0; // Read the system call from f->esp
  void *arg1;
  void *arg2;
  void *arg3;
  void *arg4;
  struct file *file;
  int i;
  switch (syscall_no){
    case SYS_HALT:
      shutdown_power_off(); // Function to halt the machine
      break;
      
    case SYS_EXIT:
      arg1 = get_ptr(esp_tmp + 4); // exit_status
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      thread_exit(*(int *)arg1); // Terminates the current process
      break;
    
    case SYS_WRITE:
      arg1 = get_ptr(esp_tmp + 4); //fd
      arg2 = get_ptr(esp_tmp + 8); // buffer
      arg3 = get_ptr(esp_tmp + 12); // size
      if(arg1 == NULL || arg2 == NULL || arg3 == NULL){
        thread_exit(-1);
        return;
      }
      arg4 = get_ptr(*(void **)arg2);
      if(arg4 == NULL){
        thread_exit(-1);
        return;
      }
      if(*(unsigned int*)arg1 == 1)
      {
        lock_acquire (&filesys_lock);
        putbuf(arg4, *(int*)arg3); // Write data to the console
        lock_release (&filesys_lock);
      }
      file = find_file(*(unsigned int*)arg1);
      if(file==NULL){
        f->eax = -1;
        return;
      }
      lock_acquire (&filesys_lock);
      f->eax = file_write(file, arg2, *(off_t *)arg3);
      lock_release (&filesys_lock);
      break;
    case SYS_EXEC:
      arg1 = get_ptr(esp_tmp + 4); //cmd_line
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      arg2 = get_ptr(*(void **)arg1);
      if(arg2 == NULL){
        thread_exit(-1);
        return;
      }
      f->eax = process_execute(arg2);
      struct thread *child;
      struct list_elem *child_elem = &thread_current()->children_list.head;
      while ((child_elem = list_next (child_elem)) != list_end (&thread_current()->children_list)) 
      {
        child = list_entry(child_elem,struct thread, parent_elem);
        if(f->eax == child->tid){
          break;
        }
      }
      if(child->tid != f->eax){
        f->eax = -1;
        return;
      }
      sema_down(&child->start_sema);
      if(child->start_success == false){
        sema_up(&child->exit_sema);
        f->eax = -1;
        return;
      }
      break;
    case SYS_WAIT:
      arg1 = get_ptr(esp_tmp + 4); //child_pid
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      f->eax = process_wait(*(int*)arg1);
      return;
      break;
    case SYS_CREATE:
      arg1 = get_ptr(esp_tmp + 4); //file_name
      arg2 = get_ptr(esp_tmp + 8); //initial_size
      if(arg1 == NULL || arg2 == NULL){
        thread_exit(-1);
        return;
      }
      arg3 = get_ptr(*(void **)arg1);
      if(arg3 == NULL){
        thread_exit(-1);
        return;
      }
      lock_acquire (&filesys_lock);
      f->eax = filesys_create (arg3, *(unsigned int*)arg2);
      lock_release (&filesys_lock);
      break;
    case SYS_REMOVE:
      arg1 = get_ptr(esp_tmp + 4); //file_name
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      arg3 = get_ptr(*(void **)arg1);
      if(arg3 == NULL){
        thread_exit(-1);
        return;
      }
      lock_acquire (&filesys_lock);
      f->eax = filesys_remove (arg3); 
      lock_release (&filesys_lock);
      break;
    case SYS_OPEN:
      arg1 = get_ptr(esp_tmp + 4); //file_name pointer
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      arg3 = get_ptr(*(void **)arg1);
      if(arg3 == NULL){
        thread_exit(-1);
        return;
      }
      lock_acquire (&filesys_lock);
      file = filesys_open (arg3); 
      lock_release (&filesys_lock);
      if(file == NULL){
        f->eax=-1;
        return;
      }
      f->eax = open_file(file);
      break;
    case SYS_FILESIZE:
      arg1 = get_ptr(esp_tmp + 4); //fd
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      file = find_file(*(unsigned int*)arg1);
      if(file==NULL){
        f->eax = -1;
        return;
      }
      lock_acquire (&filesys_lock);
      f->eax = file_length (file);
      lock_release (&filesys_lock);
      break;
    case SYS_READ:
      arg1 = get_ptr(esp_tmp + 4); //fd
      arg2 = get_ptr(esp_tmp + 8); // buffer
      arg3 = get_ptr(esp_tmp + 12); // size
      if(arg1 == NULL || arg2 == NULL || arg3 == NULL){
        thread_exit(-1);
        return;
      }
      if(*(unsigned*)arg3 <=0){
        f->eax=*(unsigned*)arg3;
        return;
      }
      arg4 = get_ptr(*(void **)arg2);
      if(arg4 == NULL){
        thread_exit(-1);
        return;
      }
      if(*(unsigned int*)arg1==0){
        i=0;
        while (i<(int)*(unsigned*)arg3){
          ((char *)arg4)[i] = input_getc();
          i++;
        }
        f->eax = *(unsigned*)arg3;
        return;
      }
      file = find_file(*(unsigned int*)arg1);
      if(file == NULL){
        f->eax = -1;
        return;
      }
      lock_acquire (&filesys_lock);
      f->eax = file_read_at(file, arg4, *(unsigned*)arg3, 0);
      lock_release (&filesys_lock);
      break;
    case SYS_SEEK:
      arg1 = get_ptr(esp_tmp+4); //fd
      arg2 = get_ptr(esp_tmp+8); //offset
      if(arg1 == NULL || arg2 == NULL){
        thread_exit(-1);
        return;
      }
      file = find_file(*(unsigned int*)arg1);
      lock_acquire (&filesys_lock);
      file_seek(file, *(unsigned*)arg2);
      lock_release(&filesys_lock);
      break;
    case SYS_TELL:
      arg1 = get_ptr(esp_tmp + 4); //fd
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      file = find_file(*(unsigned int*)arg1);
      lock_acquire (&filesys_lock);
      f->eax = file_tell(file);
      lock_release(&filesys_lock);
      break;
    case SYS_CLOSE: 
      arg1 = get_ptr(esp_tmp + 4); //fd
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      lock_acquire (&filesys_lock);
      close_file(&thread_current()->file_descriptor_list, *(unsigned int*)arg1);
      lock_release(&filesys_lock);
      break;
  }
  
}

static void *
get_ptr(const unsigned char *uaddr)
{
  if(uaddr==NULL)
  {
    return NULL;
  }

  if(!is_user_vaddr(uaddr) || !is_user_vaddr(uaddr + 3))
  {
    return NULL;
  }

  if(uaddr < (void *)0x08048000UL)
  {
    return NULL;
  }
  if(pagedir_get_page(thread_current()->pagedir, uaddr+3) == NULL)
  {
    return NULL;
  }
  return pagedir_get_page(thread_current()->pagedir, uaddr);
}

static struct file*
find_file(unsigned int fd){
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

static unsigned int open_file(struct file* file)
{
  struct thread *cur = thread_current();
  struct list_elem *last_file_elem = list_rbegin(&cur->file_descriptor_list);
  unsigned int new_fd = 2; // if list is empty start from 2
  if(last_file_elem != &cur->file_descriptor_list.head){
    // if list has elements new fd is last element's fd + 1
    new_fd = list_entry(last_file_elem, struct thread_file_descriptor, file_elem)->fd + 1;
  }
  struct thread_file_descriptor *tfd = malloc(sizeof(*tfd));
  tfd->fd = new_fd;
  tfd->file = file;
  list_push_back(&cur->file_descriptor_list, &tfd->file_elem);
  return new_fd;
}
static void 
close_file(struct list * cls_file, unsigned int fd)
{
  struct list_elem * e;
  struct thread_file_descriptor * tfd;

  for (e = list_begin(cls_file); e != list_end(cls_file); e = list_next(e))
  {
    tfd = list_entry(e, struct thread_file_descriptor, file_elem);
    if(tfd->fd == fd){
      file_close(tfd->file);
      list_remove(e);
      free(tfd);
      break;
    }
  }
}