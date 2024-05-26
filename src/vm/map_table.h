#include <stdbool.h>
#include <kernel/list.h>

// Define the enum for mapping type
enum MapType {
    FRAME,
    SWAP,
    MMAP
};

// Define the struct to hold the information
struct MapTableEntry{
    struct list_elem map_table_elem;
    void* virtual_address;  // Virtual address pointer
    void* mapped_address;   // Mapped pointer
    enum MapType map_type;       // Mapping type
    struct File* file_ptr;         // File pointer
};

bool add_vm_entry(struct list map_table_entries, uint32_t *pagedir, struct MapTableEntry mte);
void remove_vm_entry(struct list map_table_entries, uint32_t *pagedir, struct list_elem mte_elem);