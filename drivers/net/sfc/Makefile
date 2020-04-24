# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright(c) 2019-2020 Xilinx, Inc.
# Copyright(c) 2016-2019 Solarflare Communications Inc.
#
# This software was jointly developed between OKTET Labs (under contract
# for Solarflare) and Solarflare Communications, Inc.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_sfc_efx.a

CFLAGS += -I$(RTE_SDK)/drivers/common/sfc_efx/base
CFLAGS += -I$(RTE_SDK)/drivers/common/sfc_efx
CFLAGS += -I$(SRCDIR)
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
# Strict-aliasing rules are violated by rte_eth_link to uint64_t casts
CFLAGS += -Wno-strict-aliasing

# Enable extra warnings
CFLAGS += -Wextra

# More warnings not enabled by above aggregators
CFLAGS += -Wdisabled-optimization

# Compiler and version dependent flags
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS += -Waggregate-return
CFLAGS += -Wnested-externs
else ifeq ($(CONFIG_RTE_TOOLCHAIN_CLANG),y)
CFLAGS += -Waggregate-return
CFLAGS += -Wbad-function-cast
else ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
# Suppress ICC false positive warning on 'bulk' may be used before its
# value is set
CFLAGS_sfc_ef10_tx.o += -diag-disable 3656
endif
LDLIBS += -lrte_common_sfc_efx
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_pci -lrte_pci

EXPORT_MAP := rte_pmd_sfc_version.map

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_kvargs.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_mcdi.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_sriov.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_intr.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_ev.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_port.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_tx.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_tso.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_filter.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_flow.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_dp.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_ef10_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_ef10_essb_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_EFX_PMD) += sfc_ef10_tx.c

include $(RTE_SDK)/mk/rte.lib.mk
