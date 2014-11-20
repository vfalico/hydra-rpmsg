/*
 * Remote Processor Framework Elf loader
 *
 * Copyright (C) 2011 Texas Instruments, Inc.
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2014 Huawei Technologies
 *
 * Ohad Ben-Cohen <ohad@wizery.com>
 * Brian Swetland <swetland@google.com>
 * Mark Grosen <mgrosen@ti.com>
 * Fernando Guzman Lugo <fernando.lugo@ti.com>
 * Suman Anna <s-anna@ti.com>
 * Robert Tivy <rtivy@ti.com>
 * Armando Uribe De Leon <x0095078@ti.com>
 * Sjur Brændeland <sjur.brandeland@stericsson.com>
 * Paul Mundt <paul.mundt@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt)    "%s: " fmt, __func__

#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/remoteproc.h>
#include <linux/elf.h>

#include "remoteproc_internal.h"

#ifdef CONFIG_REMOTEPROC_FW_V2
#define RPROC_MAX_FW_VERSION	2
#else
#define RPROC_MAX_FW_VERSION	1
#endif

/**
 * rproc_elf64_get_boot_addr() - Get rproc's boot address.
 * @rproc: the remote processor handle
 * @fw: the ELF firmware image
 *
 * This function returns the entry point address of the ELF64
 * image.
 *
 * Note that the boot address is not a configurable property of all remote
 * processors. Some will always boot at a specific hard-coded address.
 */
static unsigned long
rproc_elf64_get_boot_addr(struct rproc *rproc, const struct firmware *fw)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)fw->data;

	return ehdr->e_entry;
}

/**
 * rproc_elf32_get_boot_addr() - Get rproc's boot address.
 * @rproc: the remote processor handle
 * @fw: the ELF firmware image
 *
 * This function returns the entry point address of the ELF32
 * image.
 *
 * Note that the boot address is not a configurable property of all remote
 * processors. Some will always boot at a specific hard-coded address.
 */
static unsigned long
rproc_elf32_get_boot_addr(struct rproc *rproc, const struct firmware *fw)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)fw->data;

	return ehdr->e_entry;
}

/**
 * rproc_elf64_load_segments() - load firmware segments to memory
 * @rproc: remote processor which will be booted using these fw segments
 * @fw: the ELF64 firmware image
 *
 * This function loads the firmware segments to memory, where the remote
 * processor expects them.
 *
 * Some remote processors will expect their code and data to be placed
 * in specific device addresses, and can't have them dynamically assigned.
 *
 * We currently support only those kind of remote processors, and expect
 * the program header's paddr member to contain those addresses. We then go
 * through the physically contiguous "carveout" memory regions which we
 * allocated (and mapped) earlier on behalf of the remote processor,
 * and "translate" device address to kernel addresses, so we can copy the
 * segments where they are expected.
 *
 * Currently we only support remote processors that required carveout
 * allocations and got them mapped onto their iommus. Some processors
 * might be different: they might not have iommus, and would prefer to
 * directly allocate memory for every segment/resource. This is not yet
 * supported, though.
 */
static int
rproc_elf64_load_segments(struct rproc *rproc, const struct firmware *fw)
{
	struct device *dev = &rproc->dev;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	int i, ret = 0;
	const u8 *elf_data = fw->data;

	ehdr = (Elf64_Ehdr *)elf_data;
	phdr = (Elf64_Phdr *)(elf_data + ehdr->e_phoff);

	/* go through the available ELF segments */
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		unsigned long da = phdr->p_paddr;
		unsigned long memsz = phdr->p_memsz;
		unsigned long filesz = phdr->p_filesz;
		unsigned long offset = phdr->p_offset;
		void *ptr;

		if (phdr->p_type != PT_LOAD)
			continue;

		dev_dbg(dev, "phdr: type %d da 0x%lx memsz 0x%lx filesz 0x%lx\n",
					phdr->p_type, da, memsz, filesz);

		if (filesz > memsz) {
			dev_err(dev, "bad phdr filesz 0x%lx memsz 0x%lx\n",
							filesz, memsz);
			ret = -EINVAL;
			break;
		}

		if (offset + filesz > fw->size) {
			dev_err(dev, "truncated fw: need 0x%lx avail 0x%zx\n",
					offset + filesz, fw->size);
			ret = -EINVAL;
			break;
		}

		/* grab the kernel address for this device address */
		ptr = rproc_da_to_va(rproc, da, memsz);
		if (!ptr) {
			dev_err(dev, "bad phdr da 0x%lx mem 0x%lx\n", da, memsz);
			ret = -EINVAL;
			break;
		}

		/* put the segment where the remote processor expects it */
		if (phdr->p_filesz)
			memcpy(ptr, elf_data + phdr->p_offset, filesz);

		/*
		 * Zero out remaining memory for this segment.
		 *
		 * This isn't strictly required since dma_alloc_coherent already
		 * did this for us. albeit harmless, we may consider removing
		 * this.
		 */
		if (memsz > filesz)
			memset(ptr + filesz, 0, memsz - filesz);
	}

	return ret;
}

/**
 * rproc_elf32_load_segments() - load firmware segments to memory
 * @rproc: remote processor which will be booted using these fw segments
 * @fw: the ELF32 firmware image
 *
 * This function loads the firmware segments to memory, where the remote
 * processor expects them.
 *
 * Some remote processors will expect their code and data to be placed
 * in specific device addresses, and can't have them dynamically assigned.
 *
 * We currently support only those kind of remote processors, and expect
 * the program header's paddr member to contain those addresses. We then go
 * through the physically contiguous "carveout" memory regions which we
 * allocated (and mapped) earlier on behalf of the remote processor,
 * and "translate" device address to kernel addresses, so we can copy the
 * segments where they are expected.
 *
 * Currently we only support remote processors that required carveout
 * allocations and got them mapped onto their iommus. Some processors
 * might be different: they might not have iommus, and would prefer to
 * directly allocate memory for every segment/resource. This is not yet
 * supported, though.
 */
static int
rproc_elf32_load_segments(struct rproc *rproc, const struct firmware *fw)
{
	struct device *dev = &rproc->dev;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	int i, ret = 0;
	const u8 *elf_data = fw->data;

	ehdr = (Elf32_Ehdr *)elf_data;
	phdr = (Elf32_Phdr *)(elf_data + ehdr->e_phoff);

	/* go through the available ELF segments */
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		unsigned long da = phdr->p_paddr;
		unsigned long memsz = phdr->p_memsz;
		unsigned long filesz = phdr->p_filesz;
		unsigned long offset = phdr->p_offset;
		void *ptr;

		if (phdr->p_type != PT_LOAD)
			continue;

		dev_dbg(dev, "phdr: type %d da 0x%lx memsz 0x%lx filesz 0x%lx\n",
					phdr->p_type, da, memsz, filesz);

		if (filesz > memsz) {
			dev_err(dev, "bad phdr filesz 0x%lx memsz 0x%lx\n",
							filesz, memsz);
			ret = -EINVAL;
			break;
		}

		if (offset + filesz > fw->size) {
			dev_err(dev, "truncated fw: need 0x%lx avail 0x%zx\n",
					offset + filesz, fw->size);
			ret = -EINVAL;
			break;
		}

		/* grab the kernel address for this device address */
		ptr = rproc_da_to_va(rproc, da, memsz);
		if (!ptr) {
			dev_err(dev, "bad phdr da 0x%lx mem 0x%lx\n", da, memsz);
			ret = -EINVAL;
			break;
		}

		/* put the segment where the remote processor expects it */
		if (phdr->p_filesz)
			memcpy(ptr, elf_data + phdr->p_offset, filesz);

		/*
		 * Zero out remaining memory for this segment.
		 *
		 * This isn't strictly required since dma_alloc_coherent already
		 * did this for us. albeit harmless, we may consider removing
		 * this.
		 */
		if (memsz > filesz)
			memset(ptr + filesz, 0, memsz - filesz);
	}

	return ret;
}

static Elf64_Shdr *find_elf64_table(struct device *dev, Elf64_Ehdr *ehdr,
				    size_t fw_size)
{
	Elf64_Shdr *shdr;
	int i;
	const char *name_table;
	struct resource_table *table = NULL;
	const u8 *elf_data = (void *)ehdr;

	/* look for the resource table and handle it */
	shdr = (Elf64_Shdr *)(elf_data + ehdr->e_shoff);
	name_table = elf_data + shdr[ehdr->e_shstrndx].sh_offset;

	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		unsigned long size = shdr->sh_size;
		unsigned long offset = shdr->sh_offset;

		if (strcmp(name_table + shdr->sh_name, ".resource_table"))
			continue;

		table = (struct resource_table *)(elf_data + offset);

		/* make sure we have the entire table */
		if (offset + size > fw_size || offset + size < size) {
			dev_err(dev, "resource table truncated\n");
			return NULL;
		}

		/* make sure table has at least the header */
		if (sizeof(struct resource_table) > size) {
			dev_err(dev, "header-less resource table\n");
			return NULL;
		}

		/* Basic sanity checks for firmware versions */
		if (!table->ver || table->ver > RPROC_MAX_FW_VERSION) {
			dev_err(dev, "unsupported fw ver: %d\n", table->ver);
			return NULL;
		}

		/* make sure reserved bytes are zeroes */
		if (table->reserved[0] || table->reserved[1]) {
			dev_err(dev, "non zero reserved bytes\n");
			return NULL;
		}

		/* make sure the offsets array isn't truncated */
		if (table->num * sizeof(table->offset[0]) +
				sizeof(struct resource_table) > size) {
			dev_err(dev, "resource table incomplete\n");
			return NULL;
		}

		return shdr;
	}

	return NULL;
}

static Elf32_Shdr *find_elf32_table(struct device *dev, Elf32_Ehdr *ehdr,
				    size_t fw_size)
{
	Elf32_Shdr *shdr;
	int i;
	const char *name_table;
	struct resource_table *table = NULL;
	const u8 *elf_data = (void *)ehdr;

	/* look for the resource table and handle it */
	shdr = (Elf32_Shdr *)(elf_data + ehdr->e_shoff);
	name_table = elf_data + shdr[ehdr->e_shstrndx].sh_offset;

	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		unsigned long size = shdr->sh_size;
		unsigned long offset = shdr->sh_offset;

		if (strcmp(name_table + shdr->sh_name, ".resource_table"))
			continue;

		table = (struct resource_table *)(elf_data + offset);

		/* make sure we have the entire table */
		if (offset + size > fw_size || offset + size < size) {
			dev_err(dev, "resource table truncated\n");
			return NULL;
		}

		/* make sure table has at least the header */
		if (sizeof(struct resource_table) > size) {
			dev_err(dev, "header-less resource table\n");
			return NULL;
		}

		/* Basic sanity checks for firmware versions */
		if (!table->ver || table->ver > RPROC_MAX_FW_VERSION) {
			dev_err(dev, "unsupported fw ver: %d\n", table->ver);
			return NULL;
		}

		/* make sure reserved bytes are zeroes */
		if (table->reserved[0] || table->reserved[1]) {
			dev_err(dev, "non zero reserved bytes\n");
			return NULL;
		}

		/* make sure the offsets array isn't truncated */
		if (table->num * sizeof(table->offset[0]) +
				sizeof(struct resource_table) > size) {
			dev_err(dev, "resource table incomplete\n");
			return NULL;
		}

		return shdr;
	}

	return NULL;
}

/**
 * rproc_elf64_find_rsc_table() - find the resource table
 * @rproc: the rproc handle
 * @fw: the ELF64 firmware image
 * @tablesz: place holder for providing back the table size
 *
 * This function finds the resource table inside the remote processor's
 * firmware. It is used both upon the registration of @rproc (in order
 * to look for and register the supported virito devices), and when the
 * @rproc is booted.
 *
 * Returns the pointer to the resource table if it is found, and write its
 * size into @tablesz. If a valid table isn't found, NULL is returned
 * (and @tablesz isn't set).
 */
static struct resource_table *
rproc_elf64_find_rsc_table(struct rproc *rproc, const struct firmware *fw,
			   int *tablesz)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	struct device *dev = &rproc->dev;
	struct resource_table *table = NULL;
	const u8 *elf_data = fw->data;

	ehdr = (Elf64_Ehdr *)elf_data;

	shdr = find_elf64_table(dev, ehdr, fw->size);
	if (!shdr)
		return NULL;

	table = (struct resource_table *)(elf_data + shdr->sh_offset);
	*tablesz = shdr->sh_size;

	return table;
}

/**
 * rproc_elf32_find_rsc_table() - find the resource table
 * @rproc: the rproc handle
 * @fw: the ELF32 firmware image
 * @tablesz: place holder for providing back the table size
 *
 * This function finds the resource table inside the remote processor's
 * firmware. It is used both upon the registration of @rproc (in order
 * to look for and register the supported virito devices), and when the
 * @rproc is booted.
 *
 * Returns the pointer to the resource table if it is found, and write its
 * size into @tablesz. If a valid table isn't found, NULL is returned
 * (and @tablesz isn't set).
 */
static struct resource_table *
rproc_elf32_find_rsc_table(struct rproc *rproc, const struct firmware *fw,
			   int *tablesz)
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	struct device *dev = &rproc->dev;
	struct resource_table *table = NULL;
	const u8 *elf_data = fw->data;

	ehdr = (Elf32_Ehdr *)elf_data;

	shdr = find_elf32_table(dev, ehdr, fw->size);
	if (!shdr)
		return NULL;

	table = (struct resource_table *)(elf_data + shdr->sh_offset);
	*tablesz = shdr->sh_size;

	return table;
}

/**
 * rproc_elf64_find_loaded_rsc_table() - find the loaded resource table
 * @rproc: the rproc handle
 * @fw: the ELF64 firmware image
 *
 * This function finds the location of the loaded resource table. Don't
 * call this function if the table wasn't loaded yet - it's a bug if you do.
 *
 * Returns the pointer to the resource table if it is found or NULL otherwise.
 * If the table wasn't loaded yet the result is unspecified.
 */
static struct resource_table *
rproc_elf64_find_loaded_rsc_table(struct rproc *rproc,
				  const struct firmware *fw)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)fw->data;
	Elf64_Shdr *shdr, *text_shdr;
	u64 da;

	shdr = find_elf64_table(&rproc->dev, ehdr, fw->size);
	if (!shdr)
		return NULL;

	da = shdr->sh_addr;

	/* the sh_addr contains the virtual address, so we must calculate
	 * the physical one, judging by the offset */
	if (da > PAGE_OFFSET) {
		text_shdr = &(((Elf64_Shdr *)(fw->data + ehdr->e_shoff))[1]);
		da = da - text_shdr->sh_addr + ehdr->e_entry;
	}

	return rproc_da_to_va(rproc, da, shdr->sh_size);
}

/**
 * rproc_elf32_find_loaded_rsc_table() - find the loaded resource table
 * @rproc: the rproc handle
 * @fw: the ELF32 firmware image
 *
 * This function finds the location of the loaded resource table. Don't
 * call this function if the table wasn't loaded yet - it's a bug if you do.
 *
 * Returns the pointer to the resource table if it is found or NULL otherwise.
 * If the table wasn't loaded yet the result is unspecified.
 */
static struct resource_table *
rproc_elf32_find_loaded_rsc_table(struct rproc *rproc,
				  const struct firmware *fw)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)fw->data;
	Elf32_Shdr *shdr, *text_shdr;
	u32 da;

	shdr = find_elf32_table(&rproc->dev, ehdr, fw->size);
	if (!shdr)
		return NULL;

	da = shdr->sh_addr;

	/* the sh_addr contains the virtual address, so we must calculate
	 * the physical one, judging by the offset */
	if (da > PAGE_OFFSET) {
		text_shdr = &(((Elf64_Shdr *)(fw->data + ehdr->e_shoff))[1]);
		da = da - text_shdr->sh_addr + ehdr->e_entry;
	}

	return rproc_da_to_va(rproc, da, shdr->sh_size);
}

static int rproc_elf64_sanity_check(struct rproc *rproc,
				    const struct firmware *fw)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)fw->data;
	struct device *dev = &rproc->dev;
	struct rproc_fw_ops *ops = rproc->fw_ops;

	if (fw->size < ehdr->e_shoff + sizeof(Elf64_Shdr)) {
		dev_err(dev, "Image is too small\n");
		return -EINVAL;
	}

	if (ehdr->e_phnum == 0) {
		dev_err(dev, "No loadable segments\n");
		return -EINVAL;
	}

	if (ehdr->e_phoff > fw->size) {
		dev_err(dev, "Firmware size is too small\n");
		return -EINVAL;
	}

	mutex_lock(&rproc->lock);

	ops->load = rproc_elf64_load_segments;
	ops->find_rsc_table = rproc_elf64_find_rsc_table;
	ops->find_loaded_rsc_table = rproc_elf64_find_loaded_rsc_table;
	ops->get_boot_addr = rproc_elf64_get_boot_addr;

	mutex_unlock(&rproc->lock);

	return 0;
}

static int rproc_elf32_sanity_check(struct rproc *rproc,
				    const struct firmware *fw)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)fw->data;
	struct device *dev = &rproc->dev;
	struct rproc_fw_ops *ops = rproc->fw_ops;

	if (fw->size < ehdr->e_shoff + sizeof(Elf32_Shdr)) {
		dev_err(dev, "Image is too small\n");
		return -EINVAL;
	}

	if (ehdr->e_phnum == 0) {
		dev_err(dev, "No loadable segments\n");
		return -EINVAL;
	}

	if (ehdr->e_phoff > fw->size) {
		dev_err(dev, "Firmware size is too small\n");
		return -EINVAL;
	}

	mutex_lock(&rproc->lock);

	ops->load = rproc_elf32_load_segments;
	ops->find_rsc_table = rproc_elf32_find_rsc_table;
	ops->find_loaded_rsc_table = rproc_elf32_find_loaded_rsc_table;
	ops->get_boot_addr = rproc_elf32_get_boot_addr;

	mutex_unlock(&rproc->lock);

	return 0;
}

/**
 * rproc_elf_sanity_check() - Sanity Check ELF firmware image
 * @rproc: the remote processor handle
 * @fw: the ELF firmware image
 *
 * Make sure this fw image is sane.
 */
static int
rproc_elf_sanity_check(struct rproc *rproc, const struct firmware *fw)
{
	const char *name = rproc->firmware;
	struct device *dev = &rproc->dev;
	unsigned char e_ident[EI_NIDENT];
	int ret;

	if (!fw) {
		dev_err(dev, "failed to load %s\n", name);
		return -EINVAL;
	}

	memcpy(&e_ident, (void *)fw->data, sizeof(e_ident));

	if (memcmp(e_ident, ELFMAG, SELFMAG)) {
		dev_err(dev, "Image is corrupted (bad magic)\n");
		return -EINVAL;
	}

	/* We assume the firmware has the same endianness as the host */
# ifdef __LITTLE_ENDIAN
	if (e_ident[EI_DATA] != ELFDATA2LSB) {
# else /* BIG ENDIAN */
	if (e_ident[EI_DATA] != ELFDATA2MSB) {
# endif
		dev_err(dev, "Unsupported firmware endianness\n");
		return -EINVAL;
	}

	if (e_ident[EI_CLASS] == ELFCLASS64) {
		ret = rproc_elf64_sanity_check(rproc, fw);
		if (ret)
			return ret;
	} else {
		ret = rproc_elf32_sanity_check(rproc, fw);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Initial sanity checks for ELF header, rest of the operations are filled in
 * based on the ELF class.
 */
struct rproc_fw_ops rproc_elf_fw_ops = {
	.sanity_check = rproc_elf_sanity_check,
};
