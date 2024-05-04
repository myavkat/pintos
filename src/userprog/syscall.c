#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <user/syscall.h>
#include <kernel/console.h>
#include "devices/shutdown.h"
#include "userprog/process.h"

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
      exit_status = *(char *)f->esp; // Read exit status from esp (stack)

      process_exit(exit_status); // Terminates the current process
      break;
    
    case SYS_WRITE: 
      fd = *(int*)((intptr_t)(f->esp) + 4);
      buffer = *(char**)((intptr_t)(f->esp) + 8); // Read buffer pointer
      size = *(int*)((intptr_t)(f->esp) + 12); // Read number of bytes
      if(fd == 1)
      {
        putbuf(buffer, size); // Write data to the console
      }
      break;
    
    //othersss
  }

  printf ("wrong system call!\n");
}
