# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022, Advanced Micro Devices, Inc.

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

deps += ['dmadev']

# Enable experimental API flag
allow_experimental_apis = true
deps += ['dma_cdx']
sources = files(
        'main.c',
)

includes += include_directories('../../drivers/dma/cdx/')
includes += include_directories('../../drivers/bus/cdx/')
