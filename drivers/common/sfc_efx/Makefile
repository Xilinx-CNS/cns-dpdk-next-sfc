# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright(c) 2019-2020 Xilinx, Inc.
#
# This software was jointly developed between OKTET Labs (under contract
# for Solarflare) and Solarflare Communications, Inc.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_common_sfc_efx.a

CFLAGS += -I$(SRCDIR)/base/
CFLAGS += -I$(SRCDIR)
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

# Enable extra warnings
CFLAGS += -Wextra

# More warnings not enabled by above aggregators
CFLAGS += -Wdisabled-optimization

# Extra CFLAGS for base driver files
CFLAGS_BASE_DRIVER += -Wno-sign-compare
CFLAGS_BASE_DRIVER += -Wno-unused-parameter
CFLAGS_BASE_DRIVER += -Wno-unused-variable

# Compiler and version dependent flags
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS += -Waggregate-return
CFLAGS += -Wnested-externs
CFLAGS_BASE_DRIVER += -Wno-empty-body
CFLAGS_BASE_DRIVER += -Wno-unused-but-set-variable
else ifeq ($(CONFIG_RTE_TOOLCHAIN_CLANG),y)
CFLAGS += -Waggregate-return
CFLAGS += -Wbad-function-cast
CFLAGS_BASE_DRIVER += -Wno-empty-body
else ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS_BASE_DRIVER += -Wno-unused-but-set-variable
endif
LDLIBS += -lrte_eal

#
# List of base driver object files for which
# special CFLAGS above should be applied
#
BASE_DRIVER_OBJS=$(sort $(patsubst %.c,%.o,$(notdir $(wildcard $(SRCDIR)/base/*.c))))
$(foreach obj, $(BASE_DRIVER_OBJS), \
  $(eval CFLAGS_$(obj)+=$(CFLAGS_BASE_DRIVER)))

EXPORT_MAP := rte_common_sfc_efx_version.map

#
# all source are stored in SRCS-y
#

SRCS-y += sfc_efx.c

VPATH += $(SRCDIR)/base

SRCS-y += efx_bootcfg.c
SRCS-y += efx_crc32.c
SRCS-y += efx_ev.c
SRCS-y += efx_evb.c
SRCS-y += efx_filter.c
SRCS-y += efx_hash.c
SRCS-y += efx_intr.c
SRCS-y += efx_lic.c
SRCS-y += efx_mac.c
SRCS-y += efx_mcdi.c
SRCS-y += efx_mon.c
SRCS-y += efx_nic.c
SRCS-y += efx_nvram.c
SRCS-y += efx_phy.c
SRCS-y += efx_port.c
SRCS-y += efx_proxy.c
SRCS-y += efx_rx.c
SRCS-y += efx_sram.c
SRCS-y += efx_tunnel.c
SRCS-y += efx_tx.c
SRCS-y += efx_vpd.c
SRCS-y += mcdi_mon.c
SRCS-y += siena_mac.c
SRCS-y += siena_mcdi.c
SRCS-y += siena_nic.c
SRCS-y += siena_nvram.c
SRCS-y += siena_phy.c
SRCS-y += siena_sram.c
SRCS-y += siena_vpd.c
SRCS-y += ef10_ev.c
SRCS-y += ef10_evb.c
SRCS-y += ef10_filter.c
SRCS-y += ef10_intr.c
SRCS-y += ef10_image.c
SRCS-y += ef10_mac.c
SRCS-y += ef10_mcdi.c
SRCS-y += ef10_nic.c
SRCS-y += ef10_nvram.c
SRCS-y += ef10_phy.c
SRCS-y += ef10_proxy.c
SRCS-y += ef10_rx.c
SRCS-y += ef10_tx.c
SRCS-y += ef10_vpd.c
SRCS-y += hunt_nic.c
SRCS-y += medford_nic.c
SRCS-y += medford2_nic.c

include $(RTE_SDK)/mk/rte.lib.mk
