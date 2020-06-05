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
LIB = librte_pmd_sfc_vdpa.a

CFLAGS += -I$(RTE_SDK)/drivers/common/sfc_efx/base
CFLAGS += -I$(RTE_SDK)/drivers/common/sfc_efx
CFLAGS += -I$(RTE_SDK)/drivers/net/sfc
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
endif
LDLIBS += -lrte_common_sfc_efx
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_pci -lrte_pci

EXPORT_MAP := rte_pmd_sfc_version.map

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_SFC_VDPA_PMD) += sfc_vdpa.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_VDPA_PMD) += sfc_vdpa_ops.c
SRCS-$(CONFIG_RTE_LIBRTE_SFC_VDPA_PMD) += sfc_vdpa_filter.c

include $(RTE_SDK)/mk/rte.lib.mk
