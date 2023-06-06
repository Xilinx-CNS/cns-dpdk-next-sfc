# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023, Advanced Micro Devices, Inc.

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'


# Enable experimental API flag
allow_experimental_apis = true
sources = files(
        'main.c',
        'eftest_mcdi.c',
)
deps += ['rawdev', 'raw_cdx_exerciser', 'mcdi']
