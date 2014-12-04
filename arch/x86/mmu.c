/*
 * Copyright (c) 2009 Corey Tabaka
 * Copyright (c) 2014 Intel Corporation
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
#include <debug.h>
#include <sys/types.h>
#include <compiler.h>
#include <arch.h>
#include <arch/x86.h>
#include <arch/x86/mmu.h>
#include <stdlib.h>
#include <string.h>
#include <arch/mmu.h>
#include <assert.h>
#include <err.h>
#include <arch/arch_ops.h>

/* Enable debug mode */
#define MMU_DEBUG	0

static inline uint32_t get_pd_entry_from_pd_table(vaddr_t vaddr, vaddr_t pdt)
{
	uint32_t pd_index;
	uint32_t *pd_table;

	pd_index = ((vaddr >> PD_SHIFT) & ((1 << ADDR_OFFSET) - 1));
	pd_table = (uint32_t *)(pdt & X86_PG_FRAME);
	return X86_PHYS_TO_VIRT(pd_table[pd_index]);
}

static inline uint32_t get_pt_entry_from_page_table(vaddr_t vaddr, uint32_t pt)
{
	uint32_t pt_index;
	uint32_t *pt_table;

	pt_index = ((vaddr >> PT_SHIFT) & ((1 << ADDR_OFFSET) - 1));
	pt_table = (uint32_t *)(pt & X86_PG_FRAME);
	return X86_PHYS_TO_VIRT(pt_table[pt_index]);
}

static inline uint32_t get_pfn_from_pte(uint32_t pte)
{
	uint32_t pfn;

	pfn = (pte & X86_PG_FRAME);
	return X86_PHYS_TO_VIRT(pfn);
}

static inline uint32_t get_pfn_from_pde(uint32_t pde)
{
	uint32_t pfn;

	pfn = (pde & X86_4MB_PAGE_FRAME);
	return X86_PHYS_TO_VIRT(pfn);
}

/**
 * @brief  Walk the page table structures
 *
 */
static status_t x86_mmu_page_walking(vaddr_t pdt, vaddr_t vaddr, uint32_t *ret_level,
				uint32_t *existing_flags, uint32_t *last_valid_entry)
{
	uint32_t pt, pte;

	DEBUG_ASSERT(pdt);
	if((!ret_level) || (!last_valid_entry) || (!existing_flags)) {
		return ERR_INVALID_ARGS;
	}

	*ret_level = PD_L;
	*last_valid_entry = pdt;
	*existing_flags = 0;

	pt = get_pd_entry_from_pd_table(vaddr, pdt);
	if ((pt & X86_MMU_PG_P) == 0)
		return ERR_NOT_FOUND;

	/* 4 MB pages */
	/* In this case, the page directory entry is NOT actually a PT (page table) */
	if (pt & X86_MMU_PG_PS) {
		/* Getting the Page frame & adding the 4MB page offset from the vaddr */
		*last_valid_entry = get_pfn_from_pde(pt) + (vaddr & PAGE_OFFSET_MASK_4MB);
		*existing_flags = (X86_PHYS_TO_VIRT(pt)) & X86_FLAGS_MASK;
		goto last;
	}

	/* 4 KB pages */
	pte = get_pt_entry_from_page_table(vaddr, pt);
	if ((pte & X86_MMU_PG_P) == 0) {
		*ret_level = PT_L;
		*last_valid_entry = pt;
		return ERR_NOT_FOUND;
	}

	/* Getting the Page frame & adding the 4KB page offset from the vaddr */
	*last_valid_entry = get_pfn_from_pte(pte) + (vaddr & PAGE_OFFSET_MASK_4KB);
	*existing_flags = (X86_PHYS_TO_VIRT(pte)) & X86_FLAGS_MASK;

last:
	*ret_level = PF_L;
	return NO_ERROR;
}

/**
 * Walk the page table structures to see if the mapping between a virtual address
 * and a physical address exists. Also, check the flags.
 *
 */
status_t x86_mmu_check_mapping(vaddr_t pdt, paddr_t paddr,
				vaddr_t vaddr, uint32_t in_flags,
				uint32_t *ret_level, uint32_t *ret_flags,
				uint32_t *last_valid_entry)
{
	status_t status;
	uint32_t existing_flags = 0;

	DEBUG_ASSERT(pdt);
	if((!ret_level) || (!last_valid_entry) || (!ret_flags) ||
		(!IS_ALIGNED(vaddr, PAGE_SIZE)) ||
		(!IS_ALIGNED(paddr, PAGE_SIZE))) {
		return ERR_INVALID_ARGS;
	}

	status = x86_mmu_page_walking(pdt, vaddr, ret_level, &existing_flags, last_valid_entry);
	if(status || ((*last_valid_entry) != (uint32_t)paddr)) {
		/* We did not reach till we check the access flags for the mapping */
		*ret_flags = in_flags;
		return ERR_NOT_FOUND;
	}

	/* Checking the access flags for the mapped address. If it is not zero, then
	 * the access flags are different & the return flag will have those access bits
	 * which are different.
	 */
	*ret_flags = (in_flags ^ existing_flags) & X86_DIRTY_ACCESS_MASK;

	if(!(*ret_flags))
		return NO_ERROR;

	return ERR_NOT_FOUND;
}

static void update_pt_entry(vaddr_t vaddr, paddr_t paddr, uint32_t flags, uint32_t pt)
{
	uint32_t pt_index;

	uint32_t *pt_table = (uint32_t *)(pt & X86_PG_FRAME);
	pt_index = ((vaddr >> PT_SHIFT) & ((1 << ADDR_OFFSET) - 1));
	pt_table[pt_index] = paddr;
	pt_table[pt_index] |= flags;
}

static void update_pd_entry(vaddr_t vaddr, uint32_t pdt, uint32_t *m)
{
	uint32_t pd_index;

	uint32_t *pd_table = (uint32_t *)(pdt & X86_PG_FRAME);
	pd_index = ((vaddr >> PD_SHIFT) & ((1 << ADDR_OFFSET) - 1));
	pd_table[pd_index] = (uint32_t)m;
	pd_table[pd_index] |= X86_MMU_PG_P | X86_MMU_PG_RW;
}

/**
 * @brief Allocating a new page table
 */
static uint32_t *_map_alloc_page()
{
	uint32_t *page_ptr = memalign(PAGE_SIZE, PAGE_SIZE);

	if(page_ptr)
		memset(page_ptr, 0, PAGE_SIZE);

	return page_ptr;
}

/**
 * @brief  Add a new mapping for the given virtual address & physical address
 *
 * This is a API which handles the mapping b/w a virtual address & physical address
 * either by checking if the mapping already exists and is valid OR by adding a
 * new mapping with the required flags.
 *
 */
static status_t x86_mmu_add_mapping(vaddr_t pdt, paddr_t paddr,
				vaddr_t vaddr, uint32_t flags)
{
	uint32_t pt, *m = NULL;
	status_t ret = NO_ERROR;

	DEBUG_ASSERT(pdt);
	if((!IS_ALIGNED(vaddr, PAGE_SIZE)) || (!IS_ALIGNED(paddr, PAGE_SIZE)) )
		return ERR_INVALID_ARGS;

	pt = get_pd_entry_from_pd_table(vaddr, pdt);
	if((pt & X86_MMU_PG_P) == 0) {
		/* Creating a new pt */
		m  = _map_alloc_page();
		if(m == NULL) {
			ret = ERR_NO_MEMORY;
			goto clean;
		}

		update_pd_entry(vaddr, pdt, m);
		pt = (uint32_t)m;
	}

	/* Updating the page table entry with the paddr and access flags required for the mapping */
	update_pt_entry(vaddr, paddr, flags, pt);
	ret = NO_ERROR;
	clean:
		return ret;
}

/**
 * @brief  x86 MMU unmap an entry in the page tables recursively and clear out tables
 *
 */
static void x86_mmu_unmap_entry(vaddr_t vaddr, int level, uint32_t table_entry)
{
	uint32_t offset = 0, next_level_offset = 0;
	uint32_t *table, *next_table_addr, value;

	next_table_addr = NULL;
	table = (uint32_t *)(X86_VIRT_TO_PHYS(table_entry) & X86_PG_FRAME);

	switch(level)
	{
		case PD_L:
			offset = ((vaddr >> PD_SHIFT) & ((1 << ADDR_OFFSET) - 1));
			next_table_addr = (uint32_t *)X86_PHYS_TO_VIRT(table[offset]);
			if((X86_PHYS_TO_VIRT(table[offset]) & X86_MMU_PG_P) == 0)
				return;
			break;
		case PT_L:
			offset = ((vaddr >> PT_SHIFT) & ((1 << ADDR_OFFSET) - 1));
			next_table_addr = (uint32_t *)X86_PHYS_TO_VIRT(table[offset]);
			if((X86_PHYS_TO_VIRT(table[offset]) & X86_MMU_PG_P) == 0)
				return;
			break;
		case PF_L:
			/* Reached page frame, Let's go back */
		default:
			return;
	}

	level -= 1;
	x86_mmu_unmap_entry(vaddr, level,(uint32_t)next_table_addr);
	level += 1;

	next_table_addr = (uint32_t *)((uint32_t)(X86_VIRT_TO_PHYS(next_table_addr)) & X86_PG_FRAME);
	if(level > PT_L) {
	/* Check all entries of next level table for present bit */
		for (next_level_offset = 0; next_level_offset < NO_OF_PT_ENTRIES; next_level_offset++) {
			if((next_table_addr[next_level_offset] & X86_MMU_PG_P) != 0)
				return;	/* There is an entry in the next level table */
		}
		free(next_table_addr);
	}
	/* All present bits for all entries in next level table for this address are 0 */
	if((X86_PHYS_TO_VIRT(table[offset]) & X86_MMU_PG_P) != 0) {
		arch_disable_ints();
		value = table[offset];
		value = value & X86_PTE_NOT_PRESENT;
		table[offset] = value;
		arch_enable_ints();
	}
}

static int x86_mmu_unmap(vaddr_t pdt, vaddr_t vaddr, uint count)
{
	int unmapped = 0;
	vaddr_t next_aligned_v_addr;

	DEBUG_ASSERT(pdt);
	if(!IS_ALIGNED(vaddr, PAGE_SIZE))
		return ERR_INVALID_ARGS;

	if (count == 0)
		return NO_ERROR;

	next_aligned_v_addr = vaddr;
	while (count > 0) {
		x86_mmu_unmap_entry(next_aligned_v_addr, X86_32_PAGING_LEVELS, pdt);
		next_aligned_v_addr += PAGE_SIZE;
		unmapped++;
		count--;
	}
	return unmapped;
}

int arch_mmu_unmap(vaddr_t vaddr, uint count)
{
	uint32_t pdt_from_cr3;

	if(!IS_ALIGNED(vaddr, PAGE_SIZE))
		return ERR_INVALID_ARGS;

	if (count == 0)
		return NO_ERROR;

	DEBUG_ASSERT(x86_get_cr3());
	pdt_from_cr3 = x86_get_cr3();

	return(x86_mmu_unmap(pdt_from_cr3, vaddr, count));
}

/**
 * @brief  Mapping a section/range with specific permissions
 *
 */
status_t x86_mmu_map_range(vaddr_t pdt, struct map_range *range, uint32_t flags)
{
	vaddr_t next_aligned_v_addr;
	paddr_t next_aligned_p_addr;
	status_t map_status;
	uint32_t no_of_pages, index;

	DEBUG_ASSERT(pdt);
	if(!range)
		return ERR_INVALID_ARGS;

	/* Calculating the number of 4k pages */
	if(IS_ALIGNED(range->size, PAGE_SIZE))
		no_of_pages = (range->size) >> PAGE_DIV_SHIFT;
	else
		no_of_pages = ((range->size) >> PAGE_DIV_SHIFT) + 1;

	next_aligned_v_addr = range->start_vaddr;
	next_aligned_p_addr = range->start_paddr;

	for(index = 0; index < no_of_pages; index++) {
		map_status = x86_mmu_add_mapping(pdt, next_aligned_p_addr, next_aligned_v_addr, flags);
		if(map_status) {
			dprintf(SPEW, "Add mapping failed with err=%d\n", map_status);
			/* Unmap the partial mapping - if any */
			x86_mmu_unmap(pdt, range->start_vaddr, index);
			return map_status;
		}
		next_aligned_v_addr += PAGE_SIZE;
		next_aligned_p_addr += PAGE_SIZE;
	}

	return NO_ERROR;
}

status_t arch_mmu_query(vaddr_t vaddr, paddr_t *paddr, uint *flags)
{
	uint32_t current_cr3_val, last_valid_entry, ret_level, ret_flags;
	status_t stat;

	if(!paddr || !flags)
		return ERR_INVALID_ARGS;

	DEBUG_ASSERT(x86_get_cr3());
	current_cr3_val = x86_get_cr3();

	stat = x86_mmu_page_walking(current_cr3_val, vaddr, &ret_level, &ret_flags, &last_valid_entry);
	if(stat)
		return stat;

	*paddr = (paddr_t)(last_valid_entry);

	/* converting x86 arch specific flags to arch mmu flags */
	*flags = 0;
	if(!(ret_flags & X86_MMU_PG_RW))
		*flags |= ARCH_MMU_FLAG_PERM_RO;

	if(ret_flags & X86_MMU_PG_U)
		*flags |= ARCH_MMU_FLAG_PERM_USER;

	return NO_ERROR;
}

int arch_mmu_map(vaddr_t vaddr, paddr_t paddr, uint count, uint flags)
{
	uint32_t current_cr3_val;
	struct map_range range;
	uint32_t arch_flags = X86_MMU_PG_P;

	if((!IS_ALIGNED(paddr, PAGE_SIZE)) || (!IS_ALIGNED(vaddr, PAGE_SIZE)))
		return ERR_INVALID_ARGS;

	if (count == 0)
		return NO_ERROR;

	DEBUG_ASSERT(x86_get_cr3());
	current_cr3_val = x86_get_cr3();

	range.start_vaddr = vaddr;
	range.start_paddr = paddr;
	range.size = count * PAGE_SIZE;

	/* converting arch mmu flags to x86 arch specific flags */
	if(!(flags & ARCH_MMU_FLAG_PERM_RO))
		arch_flags |= X86_MMU_PG_RW;

	if(flags & ARCH_MMU_FLAG_PERM_USER)
		arch_flags |= X86_MMU_PG_U;

	return(x86_mmu_map_range(current_cr3_val, &range, arch_flags));
}

/**
 * @brief  x86 MMU basic initialization
 *
 */
void arch_mmu_init(void)
{
	uint32_t cr0;

	/* Set WP bit in CR0*/
	cr0 = x86_get_cr0();
	cr0 |= X86_CR0_WP;
	x86_set_cr0(cr0);
}
