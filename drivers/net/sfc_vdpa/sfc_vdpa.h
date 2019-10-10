
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_bus_pci.h>
#include <rte_vhost.h>
#include <rte_vdpa.h>
#include <rte_vfio.h>
#include <rte_spinlock.h>
#include <rte_log.h>

#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <linux/virtio_net.h>
#include <stdbool.h>
#include <rte_kvargs.h>
#include <rte_devargs.h>

#include "efx.h"
#include "sfc_log.h"
#include "sfc_debug.h"


#define SFC_VDPA_MAX_QUEUES		1

/* It will be used for target VF when calling function is not PF */
#define SFC_VDPA_VF_NULL		0xFFFF

#define SFC_VDPA_MODE			"vdpa"

#define SFC_VDPA_MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
				sizeof(int) * (SFC_VDPA_MAX_QUEUES * 2 + 1))

enum sfc_vdpa_mcdi_state {
	SFC_MCDI_UNINITIALIZED = 0,
	SFC_MCDI_INITIALIZED,
	SFC_MCDI_BUSY,
	SFC_MCDI_COMPLETED,
	SFC_MCDI_NSTATES
};

struct sfc_vdpa_mcdi {
	rte_spinlock_t			lock;
	efsys_mem_t			mem;
	enum sfc_vdpa_mcdi_state	state;
	efx_mcdi_transport_t		transport;
	uint32_t			logtype;
};

enum sfc_vdpa_adapter_state {
	SFC_VDPA_ADAPTER_UNINITIALIZED = 0,
	SFC_VDPA_ADAPTER_INITIALIZED,
	SFC_VDPA_ADAPTER_CONFIGURING,
	SFC_VDPA_ADAPTER_CONFIGURED,
	SFC_VDPA_ADAPTER_CLOSING,
	SFC_VDPA_ADAPTER_STARTING,
	SFC_VDPA_ADAPTER_STARTED,
	SFC_VDPA_ADAPTER_STOPPING,

	SFC_VDPA_ADAPTER_NSTATES
};

struct sfc_vdpa_vring_info {
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	uint64_t size;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
};

/* Adapter private data */
struct sfc_vdpa_adapter {
	/*
	 * PMD setup and configuration is not thread safe. Since it is not
	 * performance sensitive, it is better to guarantee thread-safety
	 * and add device level lock. Adapter control operations which
	 * change its state should acquire the lock.
	 */
	struct rte_vdpa_dev_addr dev_addr;
	struct rte_pci_device *pdev;
	struct rte_pci_addr pci_addr;
	rte_spinlock_t nic_lock;
	int vfio_container_fd;
	int vfio_group_fd;
	int vfio_dev_fd;
	uint32_t logtype_main;
	efx_nic_t *nic;
	efsys_bar_t mem_bar;
	efx_family_t family;
	enum sfc_vdpa_adapter_state state;
	struct sfc_vdpa_mcdi mcdi;
	int vid; /* vhost_id */
	int did; /* dev id */
	uint16_t max_queues;
	uint64_t drv_features; /* Features supported by device */
	uint64_t dev_features; /* Features supported by device */
	rte_atomic32_t dev_attached;
	rte_atomic32_t running;
	rte_spinlock_t lock;
	rte_atomic32_t restart_required;
	uint64_t req_features;
	uint16_t num_vring;
	struct sfc_vdpa_vring_info vring[SFC_VDPA_MAX_QUEUES * 2];
	struct efx_virtio_vq_s *vq[SFC_VDPA_MAX_QUEUES * 2]; /* virtq context */
	uint32_t pidx[SFC_VDPA_MAX_QUEUES *2];
	uint32_t cidx[SFC_VDPA_MAX_QUEUES *2];
};

struct sfc_vdpa_adapter_list {
	TAILQ_ENTRY(sfc_vdpa_adapter_list) next;
	struct sfc_vdpa_adapter *sva;
};

TAILQ_HEAD(sfc_vdpa_adapter_list_head, sfc_vdpa_adapter_list);
static struct sfc_vdpa_adapter_list_head sfc_vdpa_adapter_list =
	TAILQ_HEAD_INITIALIZER(sfc_vdpa_adapter_list);

/*
 * Add wrapper functions to acquire/release lock to be able to remove or
 * change the lock in one place.
 */

static inline void
sfc_vdpa_adapter_lock_init(struct sfc_vdpa_adapter *sa)
{
	rte_spinlock_init(&sa->lock);
}

static inline int
sfc_vdpa_adapter_is_locked(struct sfc_vdpa_adapter *sa)
{
	return rte_spinlock_is_locked(&sa->lock);
}

static inline void
sfc_vdpa_adapter_lock(struct sfc_vdpa_adapter *sa)
{
	rte_spinlock_lock(&sa->lock);
}

static inline int
sfc_vdpa_adapter_trylock(struct sfc_vdpa_adapter *sa)
{
	return rte_spinlock_trylock(&sa->lock);
}

static inline void
sfc_vdpa_adapter_unlock(struct sfc_vdpa_adapter *sa)
{
	rte_spinlock_unlock(&sa->lock);
}

static inline void
sfc_vdpa_adapter_lock_fini(__rte_unused struct sfc_vdpa_adapter *sa)
{
	/* Just for symmetry of the API */
}

int
sfc_vdpa_device_init(struct sfc_vdpa_adapter *sva);

void
sfc_vdpa_device_fini(struct sfc_vdpa_adapter *sa);


int
sfc_vdpa_mcdi_init(struct sfc_vdpa_adapter *sva);

void
sfc_vdpa_mcdi_fini(struct sfc_vdpa_adapter *sva);

int
sfc_dma_alloc(const struct sfc_vdpa_adapter *sva, const char *name, uint16_t id,
              size_t len, efsys_mem_t *esmp);

void
sfc_dma_free(const struct sfc_vdpa_adapter *sva, efsys_mem_t *esmp);

uint32_t
sfc_vdpa_register_logtype(struct sfc_vdpa_adapter *sva, const char *lt_prefix_str,
	                     uint32_t ll_default);
