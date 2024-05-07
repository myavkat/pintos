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
static void *get_ptr(const unsigned char *uaddr);
static void syscall_handler (struct intr_frame *);
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
      if(*(int*)arg1 == 1)
      {
        putbuf(*(char**)arg2, *(int*)arg3); // Write data to the console
      }
      break;
    case SYS_EXEC:
      arg1 = get_ptr(esp_tmp + 4); //cmd_line
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      f->eax = process_execute(*(char **)arg1);
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
      f->eax = filesys_create (*(char **)arg1, *(int*)arg2);
      break;
    case SYS_REMOVE:
      arg1 = get_ptr(esp_tmp + 4); //file_name
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      f->eax = filesys_remove (*(const char **)arg1); 
      break;
    case SYS_OPEN:
      arg1 = get_ptr(esp_tmp + 4); //file_name
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      //TODOOOOOO
      // arg2 = filesys_open (*(const char **)arg1);
      // if(arg2 == NULL){
      //   f->eax=-1;
      //   return;
      // }
      // f->eax=(int)arg2;
      break;
    case SYS_FILESIZE:
      arg1 = get_ptr(esp_tmp + 4); //fd
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      arg2 = find_file(*(int*)arg1); // arg2 used as struct file *
      if(arg2==NULL){
        f->eax = -1;
        return;
      }
      f->eax = file_length (arg2);
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
      if(*(int*)arg1==0){
        i=0;
        while (i<(int)*(unsigned*)arg3){
          (*(char**)arg2)[i] = input_getc();
          i++;
        }
        f->eax = *(unsigned*)arg3;
        return;
      }
      arg4 = find_file(*(int*)arg1); // arg4 used as struct file *
      if(arg4 == NULL){
        f->eax = -1;
        return;
      }
      f->eax = file_read_at(arg4, *(char**)arg2, *(unsigned*)arg3, 0);
      break;
    case SYS_SEEK:
      arg1 = get_ptr(esp_tmp+4); //fd
      arg2 = get_ptr(esp_tmp+8); //offset
      if(arg1 == NULL || arg2 == NULL){
        thread_exit(-1);
        return;
      }
      lock_acquire (&file_lock);
      arg3 = find_file(*(int*)arg1); // arg3 used as struct file *
      file_seek(arg3, *(unsigned*)arg2);
      lock_release(&file_lock);
      break;
    case SYS_TELL:
      arg1 = get_ptr(esp_tmp + 4); //fd
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      lock_acquire (&file_lock);
      arg2 = find_file(*(int*)arg1); // arg2 used as struct file *
      f->eax = file_tell(arg2);
      lock_release(&file_lock);
      break;
    case SYS_CLOSE: 
      arg1 = get_ptr(esp_tmp + 4); //fd
      if(arg1 == NULL){
        thread_exit(-1);
        return;
      }
      lock_acquire (&file_lock);
      close_file(&thread_current()->file_descriptor_list, *(int*)arg1);
      lock_release(&file_lock);
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

static void 
close_file(struct list * cls_file, int fd)
{
  struct list_elem * e;
  struct thread_file_descriptor * tfd;

  for (e = list_begin(cls_file); e != list_end(cls_file); e = list_next(e))
  {
    tfd = list_entry(e, struct thread_file_descriptor, file_elem);
    if(tfd->fd == fd){
      file_close(tfd->file);
      list_remove(e);
    }
  }
}