#ifndef LS_MAP_H
#define LS_MAP_H

#include <linux/types.h>
#include <linux/mm.h>
#include <asm/pgtable.h>

unsigned long inject_ghost_mapping(pid_t target_pid,
                                   unsigned long payload_src_addr,
                                   size_t payload_size,
                                   bool zero);
bool inject_ghost_pte(struct mm_struct *mm, unsigned long va, pte_t new_pte);
pte_t forge_xom_pte_from_user(pid_t target_pid,
                              unsigned long src_user_vaddr,
                              size_t code_size,
                              unsigned long *out_kaddr,
                              bool copy_instructions);

#endif
