/*
 * Dummy Remote Processor resource table
 *
 * Copyright (C) 2014 Huawei Technologies
 *
 * Author: Veaceslav Falico <veaceslav.falico@huawei.com>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#ifndef DUMMY_PROC_H
#define DUMMY_PROC_H

#define DRV_NAME "dummy-rproc"

#define VMLINUX_FIRMWARE_SIZE			(200*1024*1024)

#define DUMMY_LPROC_BSP_ID	0

#define DUMMY_LPROC_IS_BSP()	(dummy_lproc_id == DUMMY_LPROC_BSP_ID)

u32 dummy_lproc_id = DUMMY_LPROC_BSP_ID;

int dummy_lproc_set_bsp_callback(void (*fn)(void *), void *data);
int dummy_lproc_boot_remote_cpu(int boot_cpu, void *start_addr, void *boot_params);

extern const unsigned char x86_trampoline_bsp_start [];
extern const unsigned char x86_trampoline_bsp_end   [];
extern unsigned char *x86_trampoline_bsp_base;
extern unsigned long kernel_phys_addr;
extern unsigned long boot_params_phys_addr;

#define TRAMPOLINE_SYM_BSP(x)						\
	((void *)(x86_trampoline_bsp_base +					\
		  ((const unsigned char *)(x) - x86_trampoline_bsp_start)))

#endif /* DUMMY_PROC_H */
