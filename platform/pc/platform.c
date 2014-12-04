/*
 * Copyright (c) 2009 Corey Tabaka
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
#include <err.h>
#include <debug.h>
#include <arch/x86/mmu.h>
#include <platform.h>
#include "platform_p.h"
#include <platform/pc.h>
#include <platform/multiboot.h>
#include <platform/console.h>
#include <platform/keyboard.h>
#include <dev/pci.h>
#include <dev/uart.h>
#include <arch/x86.h>
#include <arch/mmu.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>

extern multiboot_info_t *_multiboot_info;
extern uintptr_t _heap_end;
extern uint32_t __code_start;
extern uint32_t __code_end;
extern uint32_t __rodata_start;
extern uint32_t __rodata_end;
extern uint32_t __data_start;
extern uint32_t __data_end;
extern uint32_t __bss_start;
extern uint32_t __bss_end;

/* Address width */
uint32_t g_addr_width;

void platform_init_mmu_mappings(void)
{
	vaddr_t *new_pdt;
	paddr_t phy_pdt;
	struct map_range range;
	uint32_t access = 0;
	uint32_t cr4;

	/* getting the address width from CPUID instr */
	g_addr_width = x86_get_address_width();

	/* creating a new pd table  */
	new_pdt = memalign(PAGE_SIZE, PAGE_SIZE);
	ASSERT(new_pdt);
	memset(new_pdt, 0, PAGE_SIZE);
	phy_pdt = (uint32_t)X86_VIRT_TO_PHYS(new_pdt);

        /* kernel code section mapping */
	access = X86_MMU_PG_P;
	range.start_vaddr = range.start_paddr = (uint32_t) &__code_start;
	range.size = ((uint32_t)&__code_end) - ((uint32_t)&__code_start);
	x86_mmu_map_range(phy_pdt, &range, access);

	/* kernel data section mapping */
	access = X86_MMU_PG_RW | X86_MMU_PG_P;
	range.start_vaddr = range.start_paddr = (uint32_t) &__data_start;
	range.size = ((uint32_t)&__data_end) - ((uint32_t)&__data_start);
	x86_mmu_map_range(phy_pdt, &range, access);

	/* kernel rodata section mapping */
	access = X86_MMU_PG_P;
	range.start_vaddr = range.start_paddr = (uint32_t) &__rodata_start;
	range.size = ((uint32_t)&__rodata_end) - ((uint32_t)&__rodata_start);
	x86_mmu_map_range(phy_pdt, &range, access);

	/* kernel bss section and kernel heap mappings */
	access = X86_MMU_PG_RW | X86_MMU_PG_P;
	range.start_vaddr = range.start_paddr = (uint32_t) &__bss_start;
	range.size = ((uint32_t)_heap_end) - ((uint32_t)&__bss_start);
	x86_mmu_map_range(phy_pdt, &range, access);

	x86_set_cr3((uint32_t)phy_pdt);

	/* Disable PSE bit in the CR4 */
	cr4 = x86_get_cr4();
	cr4 &= X86_CR4_PSE;
	x86_set_cr4(cr4);
}

void platform_init_multiboot_info(void)
{
	unsigned int i;

	if (_multiboot_info) {
		if (_multiboot_info->flags & MB_INFO_MEM_SIZE) {
			_heap_end = _multiboot_info->mem_upper * 1024;
		}

		if (_multiboot_info->flags & MB_INFO_MMAP) {
			memory_map_t *mmap = (memory_map_t *) (_multiboot_info->mmap_addr - 4);

			dprintf(SPEW, "mmap length: %u\n", _multiboot_info->mmap_length);

			for (i=0; i < _multiboot_info->mmap_length / sizeof(memory_map_t); i++) {
				dprintf(SPEW, "base=%08x, length=%08x, type=%02x\n",
				        mmap[i].base_addr_low, mmap[i].length_low, mmap[i].type);

				if (mmap[i].type == MB_MMAP_TYPE_AVAILABLE && mmap[i].base_addr_low >= _heap_end) {
					_heap_end = mmap[i].base_addr_low + mmap[i].length_low;
				} else if (mmap[i].type != MB_MMAP_TYPE_AVAILABLE && mmap[i].base_addr_low >= _heap_end) {
					/*
					 * break on first memory hole above default heap end for now.
					 * later we can add facilities for adding free chunks to the
					 * heap for each segregated memory region.
					 */
					break;
				}
			}
		}
	}
}

void platform_early_init(void)
{
	platform_init_uart();

	/* update the heap end so we can take advantage of more ram */
	platform_init_multiboot_info();

	/* get the text console working */
	platform_init_console();

	/* initialize the interrupt controller */
	platform_init_interrupts();

	/* initialize the timer */
	platform_init_timer();
}

void platform_init(void)
{
	uart_init();

	platform_init_keyboard();
#ifndef ARCH_X86
	pci_init();
#endif
	arch_mmu_init();
	platform_init_mmu_mappings();
}
