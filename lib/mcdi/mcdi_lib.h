/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#pragma once

#include <stdint.h>
#include "mc_driver_pcol.h"
#include "mcdi_ept.h"

#define BITFIELD_MASK(_field)                                           \
  ((_field ## _WIDTH == 32)                                             \
   ? UINT32_C(0xffffffff)                                               \
   : ((UINT32_C(1) << _field ## _WIDTH) - 1))

#define BITFIELD_GET(_dword, _field)                                    \
  (((_dword) >> _field ## _LBN) & BITFIELD_MASK(_field))

#define BITFIELD_SET(_dword, _field, _value)                            \
  do {                                                                  \
    (_dword) = ((_dword) & ~(BITFIELD_MASK(_field) << _field ## _LBN))  \
      | ((uint32_t)(_value) << _field ## _LBN);                         \
  } while(0)

/**
 * Parameters for mc_cmd_read32_enc command
 */
typedef struct mc_cmd_read32_enc_s
{
  uint32_t addr;
  uint32_t numwords;
} mc_cmd_read32_enc_t;

/**
 * Read multiple 32byte words from MC memory.
 *
 * Note - this command really belongs to INSECURE category but is required by
 * shmboot. The command handler has additional checks to reject insecure
 * calls.
 *
 * @param buf           Buffer to use
 * @param bufsize       Buffer size
 * @param msg           MCDI message parameters
 *
 * @return              Encoded command length or -ERRNO
 */
int mc_cmd_read32_enc(void *buf, size_t bufsize, mc_cmd_read32_enc_t *msg);

/**
 * Parameters for mc_cmd_read32_dec command
 */
typedef struct mc_cmd_read32_dec_s
{
  /**
   * Size of the buffer field
   */
  size_t buffer_size;

  uint32_t buffer[MC_CMD_READ32_OUT_BUFFER_MAXNUM_MCDI2];
} mc_cmd_read32_dec_t;

/**
 * Read multiple 32byte words from MC memory.
 *
 * Note - this command really belongs to INSECURE category but is required by
 * shmboot. The command handler has additional checks to reject insecure
 * calls.
 *
 * @param buf           Buffer to use
 * @param bufsize       Buffer size
 * @param msg           MCDI message parameters
 *
 * @return              0 for success, -ERRNO otherwise
 */
int mc_cmd_read32_dec(void *buf, size_t bufsize, mc_cmd_read32_dec_t *msg);

/**
 * Parameters for mc_cmd_write32_enc command
 */
typedef struct mc_cmd_write32_enc_s
{
  uint32_t addr;
  /**
   * Size of the buffer field
   */
  size_t buffer_size;

  uint32_t buffer[MC_CMD_WRITE32_IN_BUFFER_MAXNUM_MCDI2];
} mc_cmd_write32_enc_t;

/**
 * Write multiple 32byte words to MC memory.
 *
 * @param buf           Buffer to use
 * @param bufsize       Buffer size
 * @param msg           MCDI message parameters
 *
 * @return              Encoded command length or -ERRNO
 */
int mc_cmd_write32_enc(void *buf, size_t bufsize, mc_cmd_write32_enc_t *msg);

/**
 * Write multiple 32byte words to MC memory.
 *
 * @param buf           Buffer to use
 * @param bufsize       Buffer size
 *
 * @return              0 for success, -ERRNO otherwise
 */
int mc_cmd_write32_dec(void *buf, size_t bufsize);

/**
 * Parameters for mc_cmd_get_version_ext_enc command
 */
typedef struct mc_cmd_get_version_ext_enc_s
{
  /**
   * placeholder, set to 0
   */
  uint32_t ext_flags;
} mc_cmd_get_version_ext_enc_t;

/**
 * Get version information about adapter components.
 *
 * @param buf           Buffer to use
 * @param bufsize       Buffer size
 * @param msg           MCDI message parameters
 *
 * @return              Encoded command length or -ERRNO
 */
int mc_cmd_get_version_ext_enc(void *buf, size_t bufsize, mc_cmd_get_version_ext_enc_t *msg);

/**
 * Parameters for mc_cmd_get_version_v5_dec command
 */
typedef struct mc_cmd_get_version_v5_dec_s
{
  /**
   * This is normally the UTC build time in seconds since epoch or one of the
   * special values listed
   */
  uint32_t mc_cmd_get_version_out_firmware;

  uint32_t pcol;
  /**
   * 128bit mask of functions supported by the current firmware
   */
  uint32_t supported_funcs[(MC_CMD_GET_VERSION_V5_OUT_SUPPORTED_FUNCS_LEN / 4)];

  uint64_t version;
  /**
   * extra info
   */
  uint8_t extra[MC_CMD_GET_VERSION_V5_OUT_EXTRA_LEN];
  /**
   * Flags indicating which extended fields are valid
   */
  uint32_t flags;
  /**
   * MC firmware unique build ID (as binary SHA-1 value)
   */
  uint8_t mcfw_build_id[MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_ID_LEN];
  /**
   * MC firmware security level
   */
  uint32_t mcfw_security_level;
  /**
   * MC firmware build name (as null-terminated US-ASCII string)
   */
  uint8_t mcfw_build_name[MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_NAME_LEN];
  /**
   * The SUC firmware version as four numbers - a.b.c.d
   */
  uint32_t sucfw_version[MC_CMD_GET_VERSION_V5_OUT_SUCFW_VERSION_NUM];
  /**
   * SUC firmware build date (as 64-bit Unix timestamp)
   */
  uint64_t sucfw_build_date;
  /**
   * The ID of the SUC chip.  This is specific to the platform but typically
   * indicates family, memory sizes etc. See SF-116728-SW for further details.
   */
  uint32_t sucfw_chip_id;
  /**
   * The CMC firmware version as four numbers - a.b.c.d
   */
  uint32_t cmcfw_version[MC_CMD_GET_VERSION_V5_OUT_CMCFW_VERSION_NUM];
  /**
   * CMC firmware build date (as 64-bit Unix timestamp)
   */
  uint64_t cmcfw_build_date;
  /**
   * FPGA version as three numbers.
   *
   * On Riverhead based systems this field uses the same encoding as hardware
   * version ID registers (MC_FPGA_BUILD_HWRD_REG):
   *
   * FPGA_VERSION[0]: x => Image H{x}
   *
   * FPGA_VERSION[1]: Revision letter (0 => A, 1 => B, ...)
   *
   * FPGA_VERSION[2]: Sub-revision number
   */
  uint32_t fpga_version[MC_CMD_GET_VERSION_V5_OUT_FPGA_VERSION_NUM];
  /**
   * Extra FPGA revision information (as null-terminated US-ASCII string)
   */
  uint8_t fpga_extra[MC_CMD_GET_VERSION_V5_OUT_FPGA_EXTRA_LEN];
  /**
   * Board name / adapter model (as null-terminated US-ASCII string)
   */
  uint8_t board_name[MC_CMD_GET_VERSION_V5_OUT_BOARD_NAME_LEN];
  /**
   * Board revision number
   */
  uint32_t board_revision;
  /**
   * Board serial number (as null-terminated US-ASCII string)
   */
  uint8_t board_serial[MC_CMD_GET_VERSION_V5_OUT_BOARD_SERIAL_LEN];
  /**
   * The version of the datapath hardware design as three number - a.b.c
   */
  uint32_t datapath_hw_version[MC_CMD_GET_VERSION_V5_OUT_DATAPATH_HW_VERSION_NUM];
  /**
   * The version of the firmware library used to control the datapath as three
   * number - a.b.c
   */
  uint32_t datapath_fw_version[MC_CMD_GET_VERSION_V5_OUT_DATAPATH_FW_VERSION_NUM];
  /**
   * The SOC boot version as four numbers - a.b.c.d
   */
  uint32_t soc_boot_version[MC_CMD_GET_VERSION_V5_OUT_SOC_BOOT_VERSION_NUM];
  /**
   * The SOC uboot version as four numbers - a.b.c.d
   */
  uint32_t soc_uboot_version[MC_CMD_GET_VERSION_V5_OUT_SOC_UBOOT_VERSION_NUM];
  /**
   * The SOC main rootfs version as four numbers - a.b.c.d
   */
  uint32_t soc_main_rootfs_version[MC_CMD_GET_VERSION_V5_OUT_SOC_MAIN_ROOTFS_VERSION_NUM];
  /**
   * The SOC recovery buildroot version as four numbers - a.b.c.d
   */
  uint32_t soc_recovery_buildroot_version[MC_CMD_GET_VERSION_V5_OUT_SOC_RECOVERY_BUILDROOT_VERSION_NUM];
  /**
   * Board version as four numbers - a.b.c.d.
   *
   * BOARD_VERSION[0] duplicates the BOARD_REVISION field
   */
  uint32_t board_version[MC_CMD_GET_VERSION_V5_OUT_BOARD_VERSION_NUM];
  /**
   * Bundle version as four numbers - a.b.c.d
   */
  uint32_t bundle_version[MC_CMD_GET_VERSION_V5_OUT_BUNDLE_VERSION_NUM];
} mc_cmd_get_version_v5_dec_t;

/**
 * Get version information about adapter components.
 *
 * @param buf           Buffer to use
 * @param bufsize       Buffer size
 * @param msg           MCDI message parameters
 *
 * @return              0 for success, -ERRNO otherwise
 */
int mc_cmd_get_version_v5_dec(void *buf, size_t bufsize, mc_cmd_get_version_v5_dec_t *msg);

/* encoders for requests */
int mc_cmd_read32_enc2(
  void *buf,
  size_t bufsize,
  uint32_t addr,
  uint32_t numwords
);

int mc_cmd_write32_enc2(
  void *buf,
  size_t bufsize,
  uint32_t addr,
  uint32_t *buffer,
  size_t buffer_size
);

int mc_cmd_get_version_ext_enc2(
  void *buf,
  size_t bufsize,
  uint32_t ext_flags
);

/* decoders for responses */
int mc_cmd_read32_dec2(
  void *buf,
  size_t bufsize,
  uint32_t *buffer,
  size_t *buffer_size
);

int mc_cmd_write32_dec2(
  void *buf,
  size_t bufsize
);

int mc_cmd_get_version_v5_dec2(
  void *buf,
  size_t bufsize,
  uint32_t *mc_cmd_get_version_out_firmware,
  uint32_t *pcol,
  uint32_t *supported_funcs,
  uint64_t *version,
  uint8_t *extra,
  uint32_t *flags,
  uint8_t *mcfw_build_id,
  uint32_t *mcfw_security_level,
  uint8_t *mcfw_build_name,
  uint32_t *sucfw_version,
  uint64_t *sucfw_build_date,
  uint32_t *sucfw_chip_id,
  uint32_t *cmcfw_version,
  uint64_t *cmcfw_build_date,
  uint32_t *fpga_version,
  uint8_t *fpga_extra,
  uint8_t *board_name,
  uint32_t *board_revision,
  uint8_t *board_serial,
  uint32_t *datapath_hw_version,
  uint32_t *datapath_fw_version,
  uint32_t *soc_boot_version,
  uint32_t *soc_uboot_version,
  uint32_t *soc_main_rootfs_version,
  uint32_t *soc_recovery_buildroot_version,
  uint32_t *board_version,
  uint32_t *bundle_version
);
