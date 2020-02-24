
#ifndef _SFC_VDPA_H
#define _SFC_VDPA_H

#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <linux/virtio_net.h>

#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_bus_pci.h>
#include <rte_vdpa.h>
#include <rte_vfio.h>
#include <rte_spinlock.h>
#include <rte_log.h>
#include <rte_ethdev.h>

#include <rte_kvargs.h>
#include <rte_devargs.h>

#include "efx.h"
#include "sfc_log.h"
#include "sfc_debug.h"
#include "sfc_vdpa_ops.h"


/* It will be used for target VF when calling function is not PF */
#define SFC_VDPA_VF_NULL		0xFFFF

#define SFC_VDPA_MODE			"vdpa"

#define SFC_VDPA_MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
				sizeof(int) * (SFC_VDPA_MAX_QUEUES * 2 + 1))

/* Proxy cmd req/resp header */
#define PROXY_HDR_SIZE		8

enum sfc_vdpa_mcdi_state {
	SFC_VDPA_MCDI_UNINITIALIZED = 0,
	SFC_VDPA_MCDI_INITIALIZED,
	SFC_VDPA_MCDI_BUSY,
	SFC_VDPA_MCDI_COMPLETED,
	SFC_VDPA_MCDI_NSTATES
};

struct sfc_vdpa_mcdi {
	rte_spinlock_t			lock;
	efsys_mem_t			mem;
	enum sfc_vdpa_mcdi_state	state;
	efx_mcdi_transport_t		transport;
	uint32_t			logtype;
};

/* Structures to help parsing of MCDI request and response buffers */
typedef struct {
  uint8_t      *emr_out_buf;
} sfc_outbuf_t;

typedef struct {
  uint8_t     *emr_in_buf;
} sfc_inbuf_t;

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
		
	uint32_t logtype_main;
	efsys_bar_t mem_bar;
	efx_family_t family;
	struct sfc_vdpa_mcdi mcdi;
	
	rte_atomic32_t running;
	rte_spinlock_t lock;
	rte_atomic32_t restart_required;
	
	struct sfc_vdpa_ops_data *vdpa_data;
};

struct sfc_vdpa_adapter_list {
	TAILQ_ENTRY(sfc_vdpa_adapter_list) next;
	struct sfc_vdpa_adapter *sva;
};

TAILQ_HEAD(sfc_vdpa_adapter_list_head, sfc_vdpa_adapter_list);
static struct sfc_vdpa_adapter_list_head sfc_vdpa_adapter_list =
	TAILQ_HEAD_INITIALIZER(sfc_vdpa_adapter_list);

struct sfc_vdpa_ops_data *get_vdpa_data_by_did(int did);
struct sfc_vdpa_adapter_list *
get_adapter_by_dev(struct rte_pci_device *pdev);

int
sfc_vdpa_device_init(struct sfc_vdpa_adapter *sva);

void
sfc_vdpa_device_fini(struct sfc_vdpa_adapter *sa);

int
sfc_vdpa_mcdi_init(struct sfc_vdpa_adapter *sva);

void
sfc_vdpa_mcdi_fini(struct sfc_vdpa_adapter *sva);

int
sfc_vdpa_dma_alloc(const struct sfc_vdpa_adapter *sva, const char *name, uint16_t id,
              size_t len, efsys_mem_t *esmp);

void
sfc_vdpa_dma_free(const struct sfc_vdpa_adapter *sva, efsys_mem_t *esmp);

uint32_t
sfc_vdpa_register_logtype(struct sfc_vdpa_adapter *sva, const char *lt_prefix_str,
	                     uint32_t ll_default);


#endif  /* _SFC_VDPA_H */

