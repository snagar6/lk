/*
 * Copyright (c) 2008 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef __ARCH_ARM_MMU_H
#define __ARCH_ARM_MMU_H

#include <sys/types.h>
#include <compiler.h>

__BEGIN_CDECLS

void x86_mmu_init(void);

#define X86_MMU_PG_P		0x001           /* P    Valid                   */
#define X86_MMU_PG_RW		0x002           /* R/W  Read/Write              */
#define X86_MMU_PG_U		0x004           /* U/S  User/Supervisor         */
#define X86_MMU_PG_PS		0x080           /* PS   Page size (0=4k,1=4M)   */
#define X86_MMU_PG_PTE_PAT	0x080           /* PAT  PAT index               */
#define X86_MMU_PG_G		0x100           /* G    Global                  */
#define X86_MMU_PG_PCD		0x010		/* PCD				*/
#define X86_MMU_CLEAR		0x0
#define X86_DIRTY_ACCESS_MASK	0xf9f
#define X86_PG_FRAME		(0xfffff000)
#define X86_FLAGS_MASK          (0x00000fff)
#define X86_PTE_NOT_PRESENT     (0xfffffffe)
#define X86_4MB_PAGE_FRAME      (0xffc00000)
#define PAGE_OFFSET_MASK_4KB    (0x00000fff)
#define PAGE_OFFSET_MASK_4MB    (0x003fffff)

#define NO_OF_PT_ENTRIES	1024
#define X86_32_PAGING_LEVELS	2
#define PAGE_SIZE		4096
#define PAGE_DIV_SHIFT		12
#define PD_SHIFT		22
#define PT_SHIFT		12
#define ADDR_OFFSET		10

#define X86_PHYS_TO_VIRT(x)     (x)
#define X86_VIRT_TO_PHYS(x)     (x)

/* Different page table levels in the page table mgmt hirerachy */
enum page_table_levels {
        PF_L,
        PT_L,
        PD_L,
} page_level;

struct map_range {
	vaddr_t start_vaddr;
	paddr_t start_paddr;
	uint32_t size;
};

status_t x86_mmu_map_range (vaddr_t pdpt, struct map_range *range, uint32_t flags);
status_t x86_mmu_check_mapping (vaddr_t pdpt, paddr_t paddr,
				vaddr_t vaddr, uint32_t in_flags,
				uint32_t *ret_level, uint32_t *ret_flags,
				uint32_t *last_valid_entry);
__END_CDECLS

#endif
