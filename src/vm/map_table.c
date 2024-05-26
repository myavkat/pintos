#include <stdbool.h>
#include <kernel/list.h>
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "map_table.h"
#include <stdio.h>

bool add_vm_entry(struct list map_table_entries, uint32_t *pagedir, struct MapTableEntry mte)
{
    if(mte.virtual_address == NULL)
        return false;
    switch(mte.map_type){
        case FRAME:
            // pagetable'a virt address daha önceden kayıtlı mı 
            if(pagedir_get_page (pagedir, mte.virtual_address)!=NULL)
                return false;
            // yeni bir frame al
            void *kpage = palloc_get_page(PAL_ZERO | PAL_USER);
            if (kpage == NULL) 
                return false;
            //virt addressi frame'e kaydet
            if(!pagedir_set_page(pagedir, mte.virtual_address, kpage, true))
                return false;
            mte.mapped_address = kpage;
            list_push_back(&map_table_entries, &mte.map_table_elem);
            break;
        case SWAP:
            break;
        case MMAP:
            //todofileptr
            break;
        default:
            return false;
    }
    return true;
}

void remove_vm_entry(struct list map_table_entries, uint32_t *pagedir, struct list_elem mte_elem)
{
    struct MapTableEntry *mte = list_entry(&mte_elem, struct MapTableEntry, map_table_elem);
    if(mte->virtual_address == NULL || mte->mapped_address == NULL)
        return;
    switch(mte->map_type){
        case FRAME:
            pagedir_clear_page(pagedir, mte->virtual_address);
            palloc_free_page(mte->mapped_address);
            list_remove(&mte->map_table_elem);
            //todo free mte
            break;
        case SWAP:
            break;
        case MMAP:
            break;
    }
}