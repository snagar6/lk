/*
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
#include <app/tests.h>
#include <stdio.h>
#include <arch/mmu.h>
#include <err.h>
#include <debug.h>
#include <arch/x86/mmu.h>
#include <arch/x86.h>
#include <err.h>

extern uint64_t __code_start;
extern uint64_t __code_end;
extern uint64_t __rodata_start;
extern uint64_t __rodata_end;
extern uint64_t __data_start;
extern uint64_t __data_end;
extern uint64_t __bss_start;
extern uint64_t __bss_end;

#define test_value1 (0xdeadbeef)
#define test_value2 (0xdeadcafe)

/* testing the ARCH independent map & query routine */
int arch_mmu_map_test(vaddr_t vaddr, paddr_t paddr, uint count, uint map_flags, uint skip_unmap)
{
	vaddr_t *test_vaddr_first, *test_vaddr_last;
	paddr_t out_paddr;
	uint ret_flags;
	status_t ret;

#ifdef ARCH_X86_64
	/* Do the Mapping */
	ret = arch_mmu_map(vaddr, paddr, count, map_flags);
	if(ret)
		return ret;
	printf("\nAdd Mapping => Vaddr:%llx Paddr:%llx pages=%u flags:%u\n", vaddr, paddr, count, map_flags);

	if(count > 0) {
		/* Check the mapping */
		ret = arch_mmu_query((vaddr_t)vaddr, &out_paddr, &ret_flags);
		if(ret)
			return ret;

		if(out_paddr != paddr)
			return 1;

		if(map_flags != ret_flags)
			return 2;

		printf("Querying the existing mapping - successfull (Paddr:%llx) (Flags:%u)\n", out_paddr, ret_flags);

		/* Write and Read test */
		if (!(ret_flags & ARCH_MMU_FLAG_PERM_RO)) {
			/* first page */
			test_vaddr_first = (vaddr_t *)vaddr;
			*test_vaddr_first = test_value1;
			printf("Reading MAPPED addr => Vaddr:%llx Value=%llx\n", test_vaddr_first, *test_vaddr_first);

			/* last page */
			test_vaddr_last = (vaddr_t *)(vaddr + ((count-1)*PAGE_SIZE));
			*test_vaddr_last = test_value2;
			printf("Reading MAPPED addr => Vaddr:%llx Value=%llx\n", test_vaddr_last, *test_vaddr_last);
		}
		else
			printf("Can't write onto these addresses (NO RW permission) - Will cause FAULT\n");
	}

	if (skip_unmap) {
		/* Unmap */
		ret = arch_mmu_unmap((vaddr_t)vaddr, count);
		if(ret != (int)count)
			return 3;

		printf("Remove Mapping => Vaddr:%llx pages=%u\n", vaddr, count);

		/* Check the mapping again - mappnig should NOT be found now */
		ret = arch_mmu_query((vaddr_t)vaddr, &out_paddr, &ret_flags);
		if(ret != ERR_NOT_FOUND)
			return 4;
	}

#endif
	return NO_ERROR;
}

int kernel_sections_map_query_test()
{
	status_t ret;
	paddr_t out_paddr;
	uint ret_flags;
	vaddr_t vaddr;

#ifdef ARCH_X86_64
	/* 1. lk kernel code */
	/* For some virtual address in the lk kernel code section */
	vaddr = (vaddr_t)(((uint64_t)&__code_start) + 0xff);
	ret = arch_mmu_query(vaddr, &out_paddr, &ret_flags);
	if(ret)
		return ret;

	/* assuming that lk kernel was mapped 1:1 */
	if(out_paddr != vaddr)
		return 1;

	/* flags for lk code section */
	if(ret_flags != ARCH_MMU_FLAG_PERM_RO)
		return 2;

	printf("lk kernel code <test vaddr = 0x%llx> is mapped Ok, flags <%u> are Ok\n", vaddr, ret_flags);

	/* 2. lk kernel data */
	/* For some virtual address in the lk kernel data section */
	vaddr = (vaddr_t)(((uint64_t)&__data_start) + 0x3f);
	ret = arch_mmu_query(vaddr, &out_paddr, &ret_flags);
	if(ret)
		return ret;

        /* assuming that lk kernel was mapped 1:1 */
	if(out_paddr != vaddr)
		return 1;

	/* flags for lk data section */
	if(ret_flags != ARCH_MMU_FLAG_PERM_NO_EXECUTE)
		return 2;

	printf("lk kernel data <test vaddr = 0x%llx> is mapped Ok, flags <%u> are Ok\n", vaddr, ret_flags);

	/* 3. lk kernel rodata */
	/* For some virtual address in the lk kernel rodata section */
	vaddr = (vaddr_t)(((uint64_t)&__rodata_start) + 0xf);
	ret = arch_mmu_query(vaddr, &out_paddr, &ret_flags);
	if(ret)
		return ret;

	/* assuming that lk kernel was mapped 1:1 */
	if(out_paddr != vaddr)
		return 1;

	/* flags for lk rodata section */
	if(ret_flags != (ARCH_MMU_FLAG_PERM_RO | ARCH_MMU_FLAG_PERM_NO_EXECUTE))
		return 2;

	printf("lk kernel rodata <test vaddr = 0x%llx> is mapped Ok, flags <%u> are Ok\n", vaddr, ret_flags);

#endif
	return NO_ERROR;
}

int x86_64_arch_mmu_tests(void)
{
	int return_status;
	uint flags = 0;

#ifdef ARCH_X86_64
	/* Test Case # 1 */
	flags = ARCH_MMU_FLAG_PERM_RO | ARCH_MMU_FLAG_PERM_USER;
	return_status = arch_mmu_map_test((0x17efe000),(0x17efe000), 512, flags, 0);
	if(!return_status)
		printf("\n---- x86 MMU Test result:SUCCESS ----\n");
	else
		printf("\n----- x86 MMU Test result:FAILURE (Return status:%d) ----\n", return_status);

	/* Test Case # 2 */
	flags = ARCH_MMU_FLAG_PERM_RO;
	return_status = arch_mmu_map_test((0x17efe000),(0x17efe000), 0, flags, 0);
	if(!return_status)
		printf("\n----- x86 MMU Test result:SUCCESS ----\n");
	else
		printf("\n ----- x86 MMU Test result:FAILURE (Return status:%d) ----\n", return_status);

	/* Test Case # 3 */
	flags = ARCH_MMU_FLAG_PERM_NO_EXECUTE;
	return_status = arch_mmu_map_test((0x7fffe0000),(0x17ffe000), 256, flags, 0);
	if(!return_status)
		printf("\n----- x86 MMU Test result:SUCCESS ---- \n");
	else
		printf("\n----- x86 MMU Test result:FAILURE (Return status:%d) ----\n", return_status);

	/* Test case # 4 */
	flags = ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_PERM_RO;
	return_status = arch_mmu_map_test((0x7fffe0000),(0x17ffe000), 1024, flags, 1);
	if(!return_status)
		printf("\n----- x86 MMU Test result:SUCCESS ----\n");
	else
		printf("\n----- x86 MMU Test result:FAILURE (Return status:%d) ----\n", return_status);

	/* Test case # 5 */
	flags = 0;
	return_status = arch_mmu_map_test((0x7fffe0000),(0x17ffe000), 1024, flags, 0);
        if(!return_status)
		printf("\n----- x86 MMU Test result:SUCCESS ----\n");
	else
		printf("\n----- x86 MMU Test result:FAILURE (Return status:%d) ----\n", return_status);

	/* Test case # 6 */
	return_status = kernel_sections_map_query_test();
	if(!return_status)
		printf("\n----- x86 MMU Test result:SUCCESS ----\n");
	else
		printf("\n----- x86 MMU Test result:FAILURE (Return status:%d) ----\n", return_status);
#endif
	return 0;
}
