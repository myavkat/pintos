#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <user/syscall.h>
#include <user/console.h>

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_no;
  
  syscall_no = *(int*)f->esp; // Read the system call from esp
  
  switch (syscall_no){
    case SYS_HLT:
      shutdown_power_off(); // Function to halt the machine
      break;
      
    case SYS_EXIT: 
      int exit_status = *(int*)f->esp; // Read exit status from esp (stack)
      process_exit(exit_status); // Terminates the current process
      break;
    
    case SYS_WRITE: 
      const char *buffer = *(char**)(f->esp + 4); // Read buffer pointer
      int size = *(int*)(f->esp + 8); // Read number of bytes
      putbuf(buffer, size); // Write data to the console
      break;
    
    //othersss
  }

  printf ("system call!\n");
  thread_exit ();
}
