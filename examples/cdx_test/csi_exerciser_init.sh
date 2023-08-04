#!/bin/bash

# Set NPR, CMPL, PR dest_id for returning the dest credit"
devmem 0x20300100000 w 0x00000008
devmem 0x20300100004 w 0x00000009
devmem 0x20300100008 w 0x0000000A
#Set NPR, CMPL, PR init credits"
devmem 0x20300100010 w 0x118
devmem 0x20300100044 w 0x118
devmem 0x2030010002C w 0x0
devmem 0x20300100030 w 0x0
devmem 0x2030010001C w 0x0
devmem 0x20300100034 w 0x4
devmem 0x20300100038 w 0xC
# reset counters, encode & req_gen logic"
devmem 0x20300100028 w 0x300
# Load Initial credit for all the flow"
devmem 0x20300100028 w 0x038
# Enabling CMPL txn at user port if it receives NPR"
devmem 0x20300100028 w 0x002
devmem 0x20300100028 w 0x000




