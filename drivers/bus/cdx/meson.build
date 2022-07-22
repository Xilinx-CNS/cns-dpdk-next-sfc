# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022-2023, Advanced Micro Devices, Inc.

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

headers = files('rte_bus_cdx.h')
sources = files(
        'cdx.c',
        'cdx_vfio.c',
)
