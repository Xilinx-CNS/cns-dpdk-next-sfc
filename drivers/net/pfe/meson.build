# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP

if host_machine.system() != 'linux'
	build = false
endif
deps += ['bus_dpaa']

sources = files('pfe_ethdev.c',
		'pfe_hal.c',
		'pfe_hif_lib.c',
		'pfe_hif.c')

# Driver uses below experimental APIs
# rte_mem_iova2virt
# rte_mem_virt2memseg
allow_experimental_apis = true

includes += include_directories('base')
