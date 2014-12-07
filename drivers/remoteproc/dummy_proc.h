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
#define LDRV_NAME "dummy-lproc"

#define VMLINUX_FIRMWARE_SIZE			(200*1024*1024)

#define DUMMY_LPROC_BSP_ID	0

#define DUMMY_LPROC_IS_BSP()	(dummy_lproc_id == DUMMY_LPROC_BSP_ID)

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

struct dummy_rproc_resourcetable {
	struct resource_table		main_hdr;
	u32				offset[2];
	/* We'd need some physical mem */
	struct fw_rsc_hdr		rsc_hdr_mem;
	struct fw_rsc_carveout		rsc_mem;
	/* And some rpmsg rings */
	struct fw_rsc_hdr		rsc_hdr_vdev;
	struct fw_rsc_vdev		rsc_vdev;
	struct fw_rsc_vdev_vring	rsc_ring0;
	struct fw_rsc_vdev_vring	rsc_ring1;
	struct fw_rsc_vdev_vring	rsc_ring2;
	u8				rsc_vdev_cfg[24];
};


#endif /* DUMMY_PROC_H */
