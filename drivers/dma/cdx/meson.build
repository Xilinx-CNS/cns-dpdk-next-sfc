# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022, Advanced Micro Devices, Inc.

if not is_linux
    build = false
    reason = 'only supported on linux'
endif

deps += ['dmadev', 'bus_cdx']
sources = files('cdx_cdma.c')
