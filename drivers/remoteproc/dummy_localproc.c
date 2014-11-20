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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/remoteproc.h>
#include <linux/virtio_ids.h>
#include <asm/cacheflush.h>
#include <linux/memblock.h>
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <asm/apic.h>
#include <asm/tlbflush.h>
#include <linux/mc146818rtc.h>
#include <asm/smpboot_hooks.h>
#include <asm/uv/uv.h>
#include <linux/cpu.h>
#include <asm/x86_init.h>

#include "dummy_proc.h"

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
};

struct dummy_rproc_resourcetable dummy_remoteproc_resourcetable
	__attribute__((section(".resource_table"), aligned(PAGE_SIZE))) =
{
	.main_hdr = {
		.ver =		1,			/* version */
		.num =		2,			/* we have 2 entries - mem and rpmsg */
		.reserved =	{ 0, 0 },		/* reserved - must be 0 */
	},
	.offset = {					/* offsets to our resource entries */
		offsetof(struct dummy_rproc_resourcetable, rsc_hdr_mem),
		offsetof(struct dummy_rproc_resourcetable, rsc_hdr_vdev),
	},
	.rsc_hdr_mem = {
		.type =		RSC_CARVEOUT,		/* mem resource */
	},
	.rsc_mem = {
		.da =		CONFIG_PHYSICAL_START,	/* we don't care about the dev address */
		.pa =		CONFIG_PHYSICAL_START,	/* we actually need to be here */
		.len =		VMLINUX_FIRMWARE_SIZE,	/* size please */
		.flags =	0,			/* TODO flags */
		.reserved =	0,			/* reserved - 0 */
		.name =		"dummy-rproc-mem",
	},
	.rsc_hdr_vdev = {
		.type =		RSC_VDEV,		/* vdev resource */
	},
	.rsc_vdev = {
		.id =		VIRTIO_ID_RPMSG,	/* found in virtio_ids.h */
		.notifyid =	0,			/* magic number for IPC */
		.dfeatures =	0,			/* features - none (??) */
		.gfeatures =	0,			/* negotiated features - blank */
		.config_len =	0,			/* config len - none (??) */
		.status =	0,			/* status - updated by bsp */
		.num_of_vrings=	2,			/* we have 2 rings */
		.reserved =	{ 0, 0},		/* reserved */
	},
	.rsc_ring0 = {
		.da =		0,			/* we don't (??) care about the da */
		.align =	PAGE_SIZE,		/* alignment */
		.num =		512,			/* number of buffers */
		.notifyid =	0,			/* magic number for IPC */
		.reserved =	0,			/* reserved - 0 */
	},
	.rsc_ring1 = {
		.da =		0,			/* we don't (??) care about the da */
		.align =	PAGE_SIZE,		/* alignment */
		.num =		512,			/* number of buffers */
		.notifyid =	0,			/* magic number for IPC */
		.reserved =	0,			/* reserved - 0 */
	},
};

struct dummy_rproc_resourcetable *lproc = &dummy_remoteproc_resourcetable;
unsigned char *x86_trampoline_bsp_base;

int dummy_lproc_boot_remote_cpu(int boot_cpu, void *start_addr, void *boot_params)
{
	unsigned long boot_error = 0, start_ip;
	int apicid, send_status = 0, j, accept_status, ret;

	ret = cpu_down(boot_cpu);

	if (ret) {
		printk(KERN_ERR "%s: couldn't cpu_down() cpu %d (errno %d)\n",
		       __func__, boot_cpu, ret);
		return ret;
	}

	apicid = per_cpu(x86_bios_cpu_apicid, boot_cpu);

	*(unsigned long *)TRAMPOLINE_SYM_BSP(&kernel_phys_addr) = (unsigned long)start_addr;
	*(unsigned long *)TRAMPOLINE_SYM_BSP(&boot_params_phys_addr) = __pa(boot_params);

	start_ip = __pa(TRAMPOLINE_SYM_BSP(trampoline_data_bsp));
	BUG_ON(!IS_ALIGNED(start_ip, PAGE_SIZE));

	smpboot_setup_warm_reset_vector(start_ip);

	apic_write(APIC_ESR, 0);
	apic_read(APIC_ESR);
	apic_icr_write(APIC_INT_LEVELTRIG | APIC_INT_ASSERT | APIC_DM_INIT,
		       apicid);
	send_status |= safe_apic_wait_icr_idle();
	mdelay(10);

	apic_icr_write(APIC_INT_LEVELTRIG | APIC_DM_INIT, apicid);
	send_status |= safe_apic_wait_icr_idle();
	mdelay(10);

	for (j = 0; j < 2; j++) {
		apic_write(APIC_ESR, 0);
		apic_read(APIC_ESR);
		apic_icr_write(APIC_DM_STARTUP | (start_ip >> 12),
			       apicid);
		udelay(300);
		send_status = safe_apic_wait_icr_idle();
		udelay(200);
		apic_write(APIC_ESR, 0);

		accept_status = (apic_read(APIC_ESR) & 0xEF);
		if (send_status || accept_status)
			break;
	}

	boot_error = send_status | accept_status;

	if (boot_error) {
		pr_err("%s: error waking up cpu %d (apic %d), start_ip 0x%p\n",
		       __func__, boot_cpu, apicid, (void *)start_ip);
		return boot_error;
	}

	udelay(100);

	WARN_ON(*(volatile u32 *)TRAMPOLINE_SYM_BSP(trampoline_status_bsp) != 0xA5A5A5A5);

	*(volatile u32 *)TRAMPOLINE_SYM_BSP(trampoline_status_bsp) = 0;

	return boot_error;
}
EXPORT_SYMBOL(dummy_lproc_boot_remote_cpu);

static int __init dummy_lproc_kick_bsp(void)
{
	if (DUMMY_LPROC_IS_BSP())
		return 0;

	printk(KERN_INFO "Kicking BSP.\n");
	apic->send_IPI_mask(cpumask_of(0), DUMMY_RPROC_VECTOR);

	return 0;
}
late_initcall(dummy_lproc_kick_bsp);

void __visible smp_dummy_lproc_kicked(void)
{
	ack_APIC_irq();
	irq_enter();

	printk(KERN_INFO "AP got kicked.\n");

	irq_exit();
}

void (*dummy_lproc_bsp_callback)(void *) = NULL;
void *dummy_lproc_bsp_data;

int dummy_lproc_set_bsp_callback(void (*fn)(void *), void *data)
{
	if (unlikely(!DUMMY_LPROC_IS_BSP())) {
		printk(KERN_ERR "%s: tried to register bsp callback on non-bsp.\n", __func__);
		return -EFAULT;
	}

	dummy_lproc_bsp_callback = fn;
	dummy_lproc_bsp_data = data;

	return 0;
}
EXPORT_SYMBOL_GPL(dummy_lproc_set_bsp_callback);

void __visible smp_dummy_rproc_kicked(void)
{
	ack_APIC_irq();
	irq_enter();

	if (likely(dummy_lproc_bsp_callback))
		dummy_lproc_bsp_callback(dummy_lproc_bsp_data);
	else
		WARN_ONCE(1, "%s: got an IPI on BSP without any callback.\n", __func__);

	irq_exit();
}

static int __init dummy_proc_setup_intr(void)
{
	if (!DUMMY_LPROC_IS_BSP()) {
		alloc_intr_gate(DUMMY_LPROC_VECTOR, dummy_lproc_kicked);
		printk(KERN_INFO "Registered AP interrupt vector %d\n", DUMMY_LPROC_VECTOR);
	} else {
		alloc_intr_gate(DUMMY_RPROC_VECTOR, dummy_rproc_kicked);
		printk(KERN_INFO "Registered BSP interrupt vector %d\n", DUMMY_RPROC_VECTOR);
	}

	return 0;
}
pure_initcall(dummy_proc_setup_intr);

static int __init dummy_lproc_configure_trampoline(void)
{
	size_t size;

	if (!DUMMY_LPROC_IS_BSP())
		return 0;

	size = PAGE_ALIGN(x86_trampoline_bsp_end - x86_trampoline_bsp_start);

	set_memory_x((unsigned long)x86_trampoline_bsp_base, size >> PAGE_SHIFT);
	return 0;
}
arch_initcall(dummy_lproc_configure_trampoline);

static void __init dummy_lproc_setup_trampoline(void)
{
	phys_addr_t mem;
	size_t size = PAGE_ALIGN(x86_trampoline_bsp_end - x86_trampoline_bsp_start);

	/* Has to be in very low memory so we can execute real-mode AP code. */
	mem = memblock_find_in_range(0, 1<<20, size, PAGE_SIZE);
	if (!mem)
		panic("Cannot allocate trampoline\n");

	x86_trampoline_bsp_base = __va(mem);
	memblock_reserve(mem, size);

	printk(KERN_DEBUG "Base memory trampoline BSP at [%p] %llx size %zu\n",
	       x86_trampoline_bsp_base, (unsigned long long)mem, size);

	memcpy(x86_trampoline_bsp_base, x86_trampoline_bsp_start, size);
}

static int __init dummy_lproc_init(void)
{
	if (!DUMMY_LPROC_IS_BSP())
		return 0;

	printk(KERN_INFO "%s: we're the BSP\n", __func__);

	dummy_lproc_setup_trampoline();

	return 0;

}
early_initcall(dummy_lproc_init);

static DECLARE_BITMAP(dummy_lproc_cpu_bits, CONFIG_NR_CPUS) __read_mostly;
static struct cpumask *dummy_lproc_cpu_mask = to_cpumask(dummy_lproc_cpu_bits);

void __init dummy_lproc_show_banner(void)
{
	char cpus[NR_CPUS*5];

	cpulist_scnprintf(cpus, sizeof(cpus), dummy_lproc_cpu_mask);
	printk(KERN_INFO "dummy_lproc: booting on CPU(s) %s\n", cpus);

	setup_max_cpus = cpumask_weight(dummy_lproc_cpu_mask);

	cpumask_copy((struct cpumask *)cpu_present_mask, dummy_lproc_cpu_mask);
	cpumask_clear((struct cpumask *)cpu_online_mask);
	cpumask_set_cpu(first_cpu(cpumask_bits(cpu_present_mask)),
			(struct cpumask *)cpu_online_mask);
	cpumask_copy((struct cpumask *)cpu_active_mask, cpu_online_mask);
}

static int __init dummy_lproc_early_param(char *p)
{
	if (cpulist_parse(p, dummy_lproc_cpu_mask)) {
		printk(KERN_ERR "%s: failed to parse lproc cpu list, bailing out.\n",
		       __func__);
		return -EFAULT;
	}

	printk(KERN_INFO "%s: We're the AP, vring0 pa 0x%lx vring1 pa 0x%lx\n",
	       __func__, lproc->rsc_ring0.da, lproc->rsc_ring1.da);

	dummy_lproc_id = 1;

	x86_init.oem.banner = dummy_lproc_show_banner;

	return 0;
}

early_param("lproc", dummy_lproc_early_param);
