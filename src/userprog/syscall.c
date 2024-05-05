#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <user/syscall.h>
#include <kernel/console.h>
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

static int get_user (const uint8_t *uaddr) ;
static bool put_user (uint8_t *udst, uint8_t byte) ;
static bool is_valid_ptr(const uint8_t *uaddr, int size);
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_no;
  
  syscall_no = *(int*)f->esp; // Read the system call from esp
  int exit_status;
  const char *buffer;
  int size;
  int fd;
  switch (syscall_no){
    case SYS_HALT:
      shutdown_power_off(); // Function to halt the machine
      break;
      
    case SYS_EXIT: 
      if(!is_valid_ptr(f->esp, 8)){
        thread_exit(-1);
        return;
      }
      exit_status = *(int *)((int)f->esp + 4); // Read exit status from esp (stack)

      thread_exit(exit_status); // Terminates the current process
      break;
    
    case SYS_WRITE: 
      if(!is_valid_ptr(f->esp, 16)){
        thread_exit(-1);
        return;
      }
      
      fd = *(int*)((char *)(f->esp) + 4);
      buffer = *(char**)((char *)(f->esp) + 8); // Read buffer pointer
      size = *(int*)((char *)(f->esp) + 12); // Read number of bytes
      if(fd == 1)
      {
        putbuf(buffer, size); // Write data to the console
      }
      break;
    case SYS_EXEC:
      break;
    //othersss
  }
  
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static bool
is_valid_ptr(const uint8_t *uaddr, int size){
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