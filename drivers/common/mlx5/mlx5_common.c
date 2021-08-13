/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_class.h>
#include <rte_malloc.h>

#include "mlx5_common.h"
#include "mlx5_common_os.h"
#include "mlx5_common_log.h"
#include "mlx5_common_private.h"

uint8_t haswell_broadwell_cpu;

/* In case this is an x86_64 intel processor to check if
 * we should use relaxed ordering.
 */
#ifdef RTE_ARCH_X86_64
/**
 * This function returns processor identification and feature information
 * into the registers.
 *
 * @param eax, ebx, ecx, edx
 *		Pointers to the registers that will hold cpu information.
 * @param level
 *		The main category of information returned.
 */
static inline void mlx5_cpu_id(unsigned int level,
				unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	__asm__("cpuid\n\t"
		: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		: "0" (level));
}
#endif

RTE_LOG_REGISTER_DEFAULT(mlx5_common_logtype, NOTICE)

/* Head of list of drivers. */
static TAILQ_HEAD(mlx5_drivers, mlx5_class_driver) drivers_list =
				TAILQ_HEAD_INITIALIZER(drivers_list);

/* Head of devices. */
static TAILQ_HEAD(mlx5_devices, mlx5_common_device) devices_list =
				TAILQ_HEAD_INITIALIZER(devices_list);

static const struct {
	const char *name;
	unsigned int drv_class;
} mlx5_classes[] = {
	{ .name = "vdpa", .drv_class = MLX5_CLASS_VDPA },
	{ .name = "eth", .drv_class = MLX5_CLASS_ETH },
	/* Keep class "net" for backward compatibility. */
	{ .name = "net", .drv_class = MLX5_CLASS_ETH },
	{ .name = "regex", .drv_class = MLX5_CLASS_REGEX },
	{ .name = "compress", .drv_class = MLX5_CLASS_COMPRESS },
	{ .name = "crypto", .drv_class = MLX5_CLASS_CRYPTO },
};

static int
class_name_to_value(const char *class_name)
{
	unsigned int i;

	for (i = 0; i < RTE_DIM(mlx5_classes); i++) {
		if (strcmp(class_name, mlx5_classes[i].name) == 0)
			return mlx5_classes[i].drv_class;
	}
	return -EINVAL;
}

static struct mlx5_class_driver *
driver_get(uint32_t class)
{
	struct mlx5_class_driver *driver;

	TAILQ_FOREACH(driver, &drivers_list, next) {
		if ((uint32_t)driver->drv_class == class)
			return driver;
	}
	return NULL;
}

static int
devargs_class_handler(__rte_unused const char *key,
		      const char *class_names, void *opaque)
{
	int *ret = opaque;
	int class_val;
	char *scratch;
	char *found;
	char *refstr = NULL;

	*ret = 0;
	scratch = strdup(class_names);
	if (scratch == NULL) {
		*ret = -ENOMEM;
		return *ret;
	}
	found = strtok_r(scratch, ":", &refstr);
	if (found == NULL)
		/* Empty string. */
		goto err;
	do {
		/* Extract each individual class name. Multiple
		 * classes can be supplied as class=net:regex:foo:bar.
		 */
		class_val = class_name_to_value(found);
		/* Check if its a valid class. */
		if (class_val < 0) {
			*ret = -EINVAL;
			goto err;
		}
		*ret |= class_val;
		found = strtok_r(NULL, ":", &refstr);
	} while (found != NULL);
err:
	free(scratch);
	if (*ret < 0)
		DRV_LOG(ERR, "Invalid mlx5 class options: %s.\n", class_names);
	return *ret;
}

static int
parse_class_options(const struct rte_devargs *devargs)
{
	struct rte_kvargs *kvlist;
	int ret = 0;

	if (devargs == NULL)
		return 0;
	if (devargs->cls != NULL && devargs->cls->name != NULL)
		/* Global syntax, only one class type. */
		return class_name_to_value(devargs->cls->name);
	/* Legacy devargs support multiple classes. */
	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		return 0;
	rte_kvargs_process(kvlist, RTE_DEVARGS_KEY_CLASS,
			   devargs_class_handler, &ret);
	rte_kvargs_free(kvlist);
	return ret;
}

static const unsigned int mlx5_class_invalid_combinations[] = {
	MLX5_CLASS_ETH | MLX5_CLASS_VDPA,
	/* New class combination should be added here. */
};

static int
is_valid_class_combination(uint32_t user_classes)
{
	unsigned int i;

	/* Verify if user specified unsupported combination. */
	for (i = 0; i < RTE_DIM(mlx5_class_invalid_combinations); i++) {
		if ((mlx5_class_invalid_combinations[i] & user_classes) ==
		    mlx5_class_invalid_combinations[i])
			return -EINVAL;
	}
	/* Not found any invalid class combination. */
	return 0;
}

static bool
device_class_enabled(const struct mlx5_common_device *device, uint32_t class)
{
	return (device->classes_loaded & class) > 0;
}

static bool
mlx5_bus_match(const struct mlx5_class_driver *drv,
	       const struct rte_device *dev)
{
	if (mlx5_dev_is_pci(dev))
		return mlx5_dev_pci_match(drv, dev);
	return true;
}

static struct mlx5_common_device *
to_mlx5_device(const struct rte_device *rte_dev)
{
	struct mlx5_common_device *dev;

	TAILQ_FOREACH(dev, &devices_list, next) {
		if (rte_dev == dev->dev)
			return dev;
	}
	return NULL;
}

int
mlx5_dev_to_pci_str(const struct rte_device *dev, char *addr, size_t size)
{
	struct rte_pci_addr pci_addr = { 0 };
	int ret;

	if (mlx5_dev_is_pci(dev)) {
		/* Input might be <BDF>, format PCI address to <DBDF>. */
		ret = rte_pci_addr_parse(dev->name, &pci_addr);
		if (ret != 0)
			return -ENODEV;
		rte_pci_device_name(&pci_addr, addr, size);
		return 0;
	}
#ifdef RTE_EXEC_ENV_LINUX
	return mlx5_auxiliary_get_pci_str(RTE_DEV_TO_AUXILIARY_CONST(dev),
			addr, size);
#else
	rte_errno = ENODEV;
	return -rte_errno;
#endif
}

static void
dev_release(struct mlx5_common_device *dev)
{
	TAILQ_REMOVE(&devices_list, dev, next);
	rte_free(dev);
}

static int
drivers_remove(struct mlx5_common_device *dev, uint32_t enabled_classes)
{
	struct mlx5_class_driver *driver;
	int local_ret = -ENODEV;
	unsigned int i = 0;
	int ret = 0;

	enabled_classes &= dev->classes_loaded;
	while (enabled_classes) {
		driver = driver_get(RTE_BIT64(i));
		if (driver != NULL) {
			local_ret = driver->remove(dev->dev);
			if (local_ret == 0)
				dev->classes_loaded &= ~RTE_BIT64(i);
			else if (ret == 0)
				ret = local_ret;
		}
		enabled_classes &= ~RTE_BIT64(i);
		i++;
	}
	if (local_ret != 0 && ret == 0)
		ret = local_ret;
	return ret;
}

static int
drivers_probe(struct mlx5_common_device *dev, uint32_t user_classes)
{
	struct mlx5_class_driver *driver;
	uint32_t enabled_classes = 0;
	bool already_loaded;
	int ret;

	TAILQ_FOREACH(driver, &drivers_list, next) {
		if ((driver->drv_class & user_classes) == 0)
			continue;
		if (!mlx5_bus_match(driver, dev->dev))
			continue;
		already_loaded = dev->classes_loaded & driver->drv_class;
		if (already_loaded && driver->probe_again == 0) {
			DRV_LOG(ERR, "Device %s is already probed",
				dev->dev->name);
			ret = -EEXIST;
			goto probe_err;
		}
		ret = driver->probe(dev->dev);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to load driver %s",
				driver->name);
			goto probe_err;
		}
		enabled_classes |= driver->drv_class;
	}
	dev->classes_loaded |= enabled_classes;
	return 0;
probe_err:
	/* Only unload drivers which are enabled which were enabled
	 * in this probe instance.
	 */
	drivers_remove(dev, enabled_classes);
	return ret;
}

int
mlx5_common_dev_probe(struct rte_device *eal_dev)
{
	struct mlx5_common_device *dev;
	uint32_t classes = 0;
	bool new_device = false;
	int ret;

	DRV_LOG(INFO, "probe device \"%s\".", eal_dev->name);
	ret = parse_class_options(eal_dev->devargs);
	if (ret < 0) {
		DRV_LOG(ERR, "Unsupported mlx5 class type: %s",
			eal_dev->devargs->args);
		return ret;
	}
	classes = ret;
	if (classes == 0)
		/* Default to net class. */
		classes = MLX5_CLASS_ETH;
	dev = to_mlx5_device(eal_dev);
	if (!dev) {
		dev = rte_zmalloc("mlx5_common_device", sizeof(*dev), 0);
		if (!dev)
			return -ENOMEM;
		dev->dev = eal_dev;
		TAILQ_INSERT_HEAD(&devices_list, dev, next);
		new_device = true;
	} else {
		/* Validate combination here. */
		ret = is_valid_class_combination(classes |
						 dev->classes_loaded);
		if (ret != 0) {
			DRV_LOG(ERR, "Unsupported mlx5 classes combination.");
			return ret;
		}
	}
	ret = drivers_probe(dev, classes);
	if (ret)
		goto class_err;
	return 0;
class_err:
	if (new_device)
		dev_release(dev);
	return ret;
}

int
mlx5_common_dev_remove(struct rte_device *eal_dev)
{
	struct mlx5_common_device *dev;
	int ret;

	dev = to_mlx5_device(eal_dev);
	if (!dev)
		return -ENODEV;
	/* Matching device found, cleanup and unload drivers. */
	ret = drivers_remove(dev, dev->classes_loaded);
	if (ret != 0)
		dev_release(dev);
	return ret;
}

int
mlx5_common_dev_dma_map(struct rte_device *dev, void *addr, uint64_t iova,
			size_t len)
{
	struct mlx5_class_driver *driver = NULL;
	struct mlx5_class_driver *temp;
	struct mlx5_common_device *mdev;
	int ret = -EINVAL;

	mdev = to_mlx5_device(dev);
	if (!mdev)
		return -ENODEV;
	TAILQ_FOREACH(driver, &drivers_list, next) {
		if (!device_class_enabled(mdev, driver->drv_class) ||
		    driver->dma_map == NULL)
			continue;
		ret = driver->dma_map(dev, addr, iova, len);
		if (ret)
			goto map_err;
	}
	return ret;
map_err:
	TAILQ_FOREACH(temp, &drivers_list, next) {
		if (temp == driver)
			break;
		if (device_class_enabled(mdev, temp->drv_class) &&
		    temp->dma_map && temp->dma_unmap)
			temp->dma_unmap(dev, addr, iova, len);
	}
	return ret;
}

int
mlx5_common_dev_dma_unmap(struct rte_device *dev, void *addr, uint64_t iova,
			  size_t len)
{
	struct mlx5_class_driver *driver;
	struct mlx5_common_device *mdev;
	int local_ret = -EINVAL;
	int ret = 0;

	mdev = to_mlx5_device(dev);
	if (!mdev)
		return -ENODEV;
	/* There is no unmap error recovery in current implementation. */
	TAILQ_FOREACH_REVERSE(driver, &drivers_list, mlx5_drivers, next) {
		if (!device_class_enabled(mdev, driver->drv_class) ||
		    driver->dma_unmap == NULL)
			continue;
		local_ret = driver->dma_unmap(dev, addr, iova, len);
		if (local_ret && (ret == 0))
			ret = local_ret;
	}
	if (local_ret)
		ret = local_ret;
	return ret;
}

void
mlx5_class_driver_register(struct mlx5_class_driver *driver)
{
	mlx5_common_driver_on_register_pci(driver);
	TAILQ_INSERT_TAIL(&drivers_list, driver, next);
}

static void mlx5_common_driver_init(void)
{
	mlx5_common_pci_init();
#ifdef RTE_EXEC_ENV_LINUX
	mlx5_common_auxiliary_init();
#endif
}

static bool mlx5_common_initialized;

/**
 * One time innitialization routine for run-time dependency on glue library
 * for multiple PMDs. Each mlx5 PMD that depends on mlx5_common module,
 * must invoke in its constructor.
 */
void
mlx5_common_init(void)
{
	if (mlx5_common_initialized)
		return;

	mlx5_glue_constructor();
	mlx5_common_driver_init();
	mlx5_common_initialized = true;
}

/**
 * This function is responsible of initializing the variable
 *  haswell_broadwell_cpu by checking if the cpu is intel
 *  and reading the data returned from mlx5_cpu_id().
 *  since haswell and broadwell cpus don't have improved performance
 *  when using relaxed ordering we want to check the cpu type before
 *  before deciding whether to enable RO or not.
 *  if the cpu is haswell or broadwell the variable will be set to 1
 *  otherwise it will be 0.
 */
RTE_INIT_PRIO(mlx5_is_haswell_broadwell_cpu, LOG)
{
#ifdef RTE_ARCH_X86_64
	unsigned int broadwell_models[4] = {0x3d, 0x47, 0x4F, 0x56};
	unsigned int haswell_models[4] = {0x3c, 0x3f, 0x45, 0x46};
	unsigned int i, model, family, brand_id, vendor;
	unsigned int signature_intel_ebx = 0x756e6547;
	unsigned int extended_model;
	unsigned int eax = 0;
	unsigned int ebx = 0;
	unsigned int ecx = 0;
	unsigned int edx = 0;
	int max_level;

	mlx5_cpu_id(0, &eax, &ebx, &ecx, &edx);
	vendor = ebx;
	max_level = eax;
	if (max_level < 1) {
		haswell_broadwell_cpu = 0;
		return;
	}
	mlx5_cpu_id(1, &eax, &ebx, &ecx, &edx);
	model = (eax >> 4) & 0x0f;
	family = (eax >> 8) & 0x0f;
	brand_id = ebx & 0xff;
	extended_model = (eax >> 12) & 0xf0;
	/* Check if the processor is Haswell or Broadwell */
	if (vendor == signature_intel_ebx) {
		if (family == 0x06)
			model += extended_model;
		if (brand_id == 0 && family == 0x6) {
			for (i = 0; i < RTE_DIM(broadwell_models); i++)
				if (model == broadwell_models[i]) {
					haswell_broadwell_cpu = 1;
					return;
				}
			for (i = 0; i < RTE_DIM(haswell_models); i++)
				if (model == haswell_models[i]) {
					haswell_broadwell_cpu = 1;
					return;
				}
		}
	}
#endif
	haswell_broadwell_cpu = 0;
}

/**
 * Allocate the User Access Region with DevX on specified device.
 *
 * @param [in] ctx
 *   Infiniband device context to perform allocation on.
 * @param [in] mapping
 *   MLX5DV_UAR_ALLOC_TYPE_BF - allocate as cached memory with write-combining
 *				attributes (if supported by the host), the
 *				writes to the UAR registers must be followed
 *				by write memory barrier.
 *   MLX5DV_UAR_ALLOC_TYPE_NC - allocate as non-cached nenory, all writes are
 *				promoted to the registers immediately, no
 *				memory barriers needed.
 *   mapping < 0 - the first attempt is performed with MLX5DV_UAR_ALLOC_TYPE_BF,
 *		   if this fails the next attempt with MLX5DV_UAR_ALLOC_TYPE_NC
 *		   is performed. The drivers specifying negative values should
 *		   always provide the write memory barrier operation after UAR
 *		   register writings.
 * If there is no definitions for the MLX5DV_UAR_ALLOC_TYPE_xx (older rdma
 * library headers), the caller can specify 0.
 *
 * @return
 *   UAR object pointer on success, NULL otherwise and rte_errno is set.
 */
void *
mlx5_devx_alloc_uar(void *ctx, int mapping)
{
	void *uar;
	uint32_t retry, uar_mapping;
	void *base_addr;

	for (retry = 0; retry < MLX5_ALLOC_UAR_RETRY; ++retry) {
#ifdef MLX5DV_UAR_ALLOC_TYPE_NC
		/* Control the mapping type according to the settings. */
		uar_mapping = (mapping < 0) ?
			      MLX5DV_UAR_ALLOC_TYPE_NC : mapping;
#else
		/*
		 * It seems we have no way to control the memory mapping type
		 * for the UAR, the default "Write-Combining" type is supposed.
		 */
		uar_mapping = 0;
		RTE_SET_USED(mapping);
#endif
		uar = mlx5_glue->devx_alloc_uar(ctx, uar_mapping);
#ifdef MLX5DV_UAR_ALLOC_TYPE_NC
		if (!uar &&
		    mapping < 0 &&
		    uar_mapping == MLX5DV_UAR_ALLOC_TYPE_BF) {
			/*
			 * In some environments like virtual machine the
			 * Write Combining mapped might be not supported and
			 * UAR allocation fails. We tried "Non-Cached" mapping
			 * for the case.
			 */
			DRV_LOG(WARNING, "Failed to allocate DevX UAR (BF)");
			uar_mapping = MLX5DV_UAR_ALLOC_TYPE_NC;
			uar = mlx5_glue->devx_alloc_uar(ctx, uar_mapping);
		} else if (!uar &&
			   mapping < 0 &&
			   uar_mapping == MLX5DV_UAR_ALLOC_TYPE_NC) {
			/*
			 * If Verbs/kernel does not support "Non-Cached"
			 * try the "Write-Combining".
			 */
			DRV_LOG(WARNING, "Failed to allocate DevX UAR (NC)");
			uar_mapping = MLX5DV_UAR_ALLOC_TYPE_BF;
			uar = mlx5_glue->devx_alloc_uar(ctx, uar_mapping);
		}
#endif
		if (!uar) {
			DRV_LOG(ERR, "Failed to allocate DevX UAR (BF/NC)");
			rte_errno = ENOMEM;
			goto exit;
		}
		base_addr = mlx5_os_get_devx_uar_base_addr(uar);
		if (base_addr)
			break;
		/*
		 * The UARs are allocated by rdma_core within the
		 * IB device context, on context closure all UARs
		 * will be freed, should be no memory/object leakage.
		 */
		DRV_LOG(WARNING, "Retrying to allocate DevX UAR");
		uar = NULL;
	}
	/* Check whether we finally succeeded with valid UAR allocation. */
	if (!uar) {
		DRV_LOG(ERR, "Failed to allocate DevX UAR (NULL base)");
		rte_errno = ENOMEM;
	}
	/*
	 * Return void * instead of struct mlx5dv_devx_uar *
	 * is for compatibility with older rdma-core library headers.
	 */
exit:
	return uar;
}

RTE_PMD_EXPORT_NAME(mlx5_common_driver, __COUNTER__);
