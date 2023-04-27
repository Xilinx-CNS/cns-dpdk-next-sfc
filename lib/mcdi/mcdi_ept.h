/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int mcdi_create_device_ep(uint16_t bus_id, uint16_t dev_id);
void mcdi_destroy_device_ep(int fd);
