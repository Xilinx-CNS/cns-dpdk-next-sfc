/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "mcdi_lib.h"

#define MCDI_HEADER_LEN 8

#define MCDI_V1_HEADER_INIT(_buf) do { (_buf)[0] = 0; } while (0)
#define MCDI_V2_HEADER_INIT(_buf) do { (_buf)[1] = 0; } while (0)

#define MCDI_V1_HEADER_GET(_buf, _member)                               \
  BITFIELD_GET((_buf)[0], MCDI_HEADER_ ## _member)

#define MCDI_V1_HEADER_SET(_buf, _member, _value)                       \
  BITFIELD_SET((_buf)[0], MCDI_HEADER_ ## _member, _value)

#define MCDI_V2_HEADER_GET(_buf, _member)                               \
  BITFIELD_GET((_buf)[1], MC_CMD_V2_EXTN_IN_ ## _member)

#define MCDI_V2_HEADER_SET(_buf, _member, _value)                       \
  BITFIELD_SET((_buf)[1], MC_CMD_V2_EXTN_IN_ ## _member, _value)

#define MCDI_HEADER_BUILD(_buf, _code, _len)                            \
  do {                                                                  \
    MCDI_V1_HEADER_INIT(_buf);                                          \
    MCDI_V1_HEADER_SET(_buf, CODE, MC_CMD_V2_EXTN);                     \
    MCDI_V1_HEADER_SET(_buf, DATALEN, 0);                               \
    MCDI_V2_HEADER_INIT(_buf);                                          \
    MCDI_V2_HEADER_SET(_buf, EXTENDED_CMD, _code);                      \
    MCDI_V2_HEADER_SET(_buf, ACTUAL_LEN, _len);                         \
  } while(0)

#define MCDI_HEADER_UPDATE_CSUM(_buf, _len)                             \
  do {                                                                  \
    uint8_t _csum;                                                      \
    MCDI_V1_HEADER_SET(_buf, XFLAGS, 0);                                \
    _csum = mcdi_csum(_buf, _len);                                      \
    MCDI_V1_HEADER_SET(_buf, XFLAGS, _csum);                            \
  } while (0)

#define MCDI_HEADER_VERIFY_CSUM(_buf, _len)                             \
  (mcdi_csum(_buf, _len) == 0)

/* return 0 if _cond is true, otherwise compile time error */
#define ZERO_OR_COMPILE_ERROR(_cond) ((int)(sizeof(struct {int:(-!(_cond));})))

/* return 0 if aligned, otherwise compile time error */
#define CHECK_ALIGN(_addr, _align) \
  ZERO_OR_COMPILE_ERROR((((uintptr_t)(_addr)) & ((_align) - 1)) == 0)

#define MCDI_MEMBER_VOID_PTR(_buf, _member)                             \
  (void*)(((uint8_t*)(_buf)) + _member ## _OFST)

#define MCDI_MEMBER_U64(_buf, _member)                                  \
  (uint64_t)(MCDI_MEMBER_U32_IDX(_buf, _member, 0) |                    \
             ((uint64_t)MCDI_MEMBER_U32_IDX(_buf, _member, 1) << 32))

#define MCDI_MEMBER_U32_PTR(_buf, _member)                              \
  (((uint32_t*)MCDI_MEMBER_VOID_PTR(_buf, _member)) +                   \
   CHECK_ALIGN(_member ## _OFST, 4))

#define MCDI_MEMBER_U32(_buf, _member)                                  \
  *MCDI_MEMBER_U32_PTR(_buf, _member)

#define MCDI_MEMBER_U32_IDX(_buf, _member, _idx)                        \
  MCDI_MEMBER_U32_PTR(_buf, _member)[_idx]

#define MCDI_MEMBER_U16_PTR(_buf, _member)                              \
  (((uint16_t*)MCDI_MEMBER_VOID_PTR(_buf, _member)) +                   \
   CHECK_ALIGN(_member ## _OFST, 2))

#define MCDI_MEMBER_U16(_buf, _member)                                  \
  *MCDI_MEMBER_U16_PTR(_buf, _member)

#define MCDI_MEMBER_U16_IDX(_buf, _member, _idx)                        \
  MCDI_MEMBER_U16_PTR(_buf, _member)[_idx]

#define MCDI_MEMBER_U8_PTR(_buf, _member)                               \
  ((uint8_t*)MCDI_MEMBER_VOID_PTR(_buf, _member))

#define MCDI_MEMBER_U8(_buf, _member)                                   \
  *MCDI_MEMBER_U8_PTR(_buf, _member)

#define MCDI_MEMBER_U8_IDX(_buf, _member, _idx)                         \
  MCDI_MEMBER_U8_PTR(_buf, _member)[_idx]

static uint8_t mcdi_csum(const void *buf, int bufsize)
{
  const uint8_t *p = (const uint8_t*)buf;
  uint8_t csum = 0;

  while (bufsize--)
    csum += *p++;

  return ~csum;
}

int mc_cmd_read32_enc(void *buf, size_t bufsize, mc_cmd_read32_enc_t *msg)
{
  uint32_t *hdr = buf;
  uint8_t *p = (uint8_t*)&hdr[2];
  size_t msg_len;

  if (!msg)
    return -EINVAL;

  msg_len = MC_CMD_READ32_IN_LEN;
  if (bufsize < MCDI_HEADER_LEN + msg_len)
    return -ENOSPC;

  memset(p, 0, msg_len);

  MCDI_HEADER_BUILD(hdr, MC_CMD_READ32, msg_len);

  MCDI_MEMBER_U32(p, MC_CMD_READ32_IN_ADDR) = msg->addr;
  MCDI_MEMBER_U32(p, MC_CMD_READ32_IN_NUMWORDS) = msg->numwords;

  MCDI_HEADER_UPDATE_CSUM(hdr, MCDI_HEADER_LEN + msg_len);

  return MCDI_HEADER_LEN + msg_len;
}

int mc_cmd_read32_dec(void *buf, size_t bufsize, mc_cmd_read32_dec_t *msg)
{
  uint32_t *hdr = buf;
  size_t msg_len;
  uint8_t *p = (uint8_t*)&hdr[2];

  if (!msg)
    return -EINVAL;
  if (bufsize < MCDI_HEADER_LEN ||
      MCDI_V1_HEADER_GET(hdr, CODE) != MC_CMD_V2_EXTN ||
      MCDI_V1_HEADER_GET(hdr, RESYNC) != 1 ||
      MCDI_V2_HEADER_GET(hdr, EXTENDED_CMD) != MC_CMD_READ32)
    return -EINVAL;

  msg_len = MCDI_V2_HEADER_GET(hdr, ACTUAL_LEN);
  if ((MCDI_HEADER_LEN + msg_len) != bufsize)
    return -EINVAL;
  if (msg_len < MC_CMD_READ32_OUT_LENMIN || msg_len > MC_CMD_READ32_OUT_LENMAX)
    return -EINVAL;
  msg->buffer_size = MC_CMD_READ32_OUT_BUFFER_NUM(msg_len);
  for (size_t i = 0; i < MC_CMD_READ32_OUT_BUFFER_NUM(msg_len); i++) {
    msg->buffer[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_READ32_OUT_BUFFER, i);
  }
  return 0;
}

int mc_cmd_write32_enc(void *buf, size_t bufsize, mc_cmd_write32_enc_t *msg)
{
  uint32_t *hdr = buf;
  uint8_t *p = (uint8_t*)&hdr[2];
  size_t msg_len;

  if (!msg)
    return -EINVAL;

  if (msg->buffer_size < MC_CMD_WRITE32_IN_BUFFER_MINNUM ||
      msg->buffer_size > MC_CMD_WRITE32_IN_BUFFER_MAXNUM_MCDI2)
    return -EINVAL;

  msg_len = MC_CMD_WRITE32_IN_LEN(msg->buffer_size);
  if (bufsize < MCDI_HEADER_LEN + msg_len)
    return -ENOSPC;

  memset(p, 0, msg_len);

  MCDI_HEADER_BUILD(hdr, MC_CMD_WRITE32, msg_len);

  MCDI_MEMBER_U32(p, MC_CMD_WRITE32_IN_ADDR) = msg->addr;
  for (size_t i = 0; i < msg->buffer_size; i++)
    MCDI_MEMBER_U32_IDX(p, MC_CMD_WRITE32_IN_BUFFER, i) = msg->buffer[i];

  MCDI_HEADER_UPDATE_CSUM(hdr, MCDI_HEADER_LEN + msg_len);

  return MCDI_HEADER_LEN + msg_len;
}

int mc_cmd_write32_dec(void *buf, size_t bufsize)
{
  uint32_t *hdr = buf;
  size_t msg_len;
  if (bufsize < MCDI_HEADER_LEN ||
      MCDI_V1_HEADER_GET(hdr, CODE) != MC_CMD_V2_EXTN ||
      MCDI_V1_HEADER_GET(hdr, RESYNC) != 1 ||
      MCDI_V2_HEADER_GET(hdr, EXTENDED_CMD) != MC_CMD_WRITE32)
    return -EINVAL;

  msg_len = MCDI_V2_HEADER_GET(hdr, ACTUAL_LEN);
  if ((MCDI_HEADER_LEN + msg_len) != bufsize)
    return -EINVAL;
  if (msg_len != MC_CMD_WRITE32_OUT_LEN)
    return -EINVAL;
  return 0;
}

int mc_cmd_get_version_ext_enc(void *buf, size_t bufsize, mc_cmd_get_version_ext_enc_t *msg)
{
  uint32_t *hdr = buf;
  uint8_t *p = (uint8_t*)&hdr[2];
  size_t msg_len;

  if (!msg)
    return -EINVAL;

  msg_len = MC_CMD_GET_VERSION_EXT_IN_LEN;
  if (bufsize < MCDI_HEADER_LEN + msg_len)
    return -ENOSPC;

  memset(p, 0, msg_len);

  MCDI_HEADER_BUILD(hdr, MC_CMD_GET_VERSION, msg_len);

  MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_EXT_IN_EXT_FLAGS) = msg->ext_flags;

  MCDI_HEADER_UPDATE_CSUM(hdr, MCDI_HEADER_LEN + msg_len);

  return MCDI_HEADER_LEN + msg_len;
}

int mc_cmd_get_version_v5_dec(void *buf, size_t bufsize, mc_cmd_get_version_v5_dec_t *msg)
{
  uint32_t *hdr = buf;
  size_t msg_len;
  uint8_t *p = (uint8_t*)&hdr[2];

  if (!msg)
    return -EINVAL;
  if (bufsize < MCDI_HEADER_LEN ||
      MCDI_V1_HEADER_GET(hdr, CODE) != MC_CMD_V2_EXTN ||
      MCDI_V1_HEADER_GET(hdr, RESYNC) != 1 ||
      MCDI_V2_HEADER_GET(hdr, EXTENDED_CMD) != MC_CMD_GET_VERSION)
    return -EINVAL;

  msg_len = MCDI_V2_HEADER_GET(hdr, ACTUAL_LEN);
  if ((MCDI_HEADER_LEN + msg_len) != bufsize)
    return -EINVAL;
  if (msg_len != MC_CMD_GET_VERSION_V5_OUT_LEN)
    return -EINVAL;
  msg->mc_cmd_get_version_out_firmware = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_OUT_FIRMWARE);
  msg->pcol = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_PCOL);
  for (size_t i = 0; i < (MC_CMD_GET_VERSION_V5_OUT_SUPPORTED_FUNCS_LEN / 4); i++) {
    msg->supported_funcs[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SUPPORTED_FUNCS, i);
  }
  msg->version = MCDI_MEMBER_U64(p, MC_CMD_GET_VERSION_V5_OUT_VERSION);
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_EXTRA_LEN; i++) {
    msg->extra[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_EXTRA, i);
  }
  msg->flags = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_FLAGS);
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_ID_LEN; i++) {
    msg->mcfw_build_id[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_ID, i);
  }
  msg->mcfw_security_level = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_MCFW_SECURITY_LEVEL);
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_NAME_LEN; i++) {
    msg->mcfw_build_name[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_NAME, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SUCFW_VERSION_NUM; i++) {
    msg->sucfw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SUCFW_VERSION, i);
  }
  msg->sucfw_build_date = MCDI_MEMBER_U64(p, MC_CMD_GET_VERSION_V5_OUT_SUCFW_BUILD_DATE);
  msg->sucfw_chip_id = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_SUCFW_CHIP_ID);
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_CMCFW_VERSION_NUM; i++) {
    msg->cmcfw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_CMCFW_VERSION, i);
  }
  msg->cmcfw_build_date = MCDI_MEMBER_U64(p, MC_CMD_GET_VERSION_V5_OUT_CMCFW_BUILD_DATE);
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_FPGA_VERSION_NUM; i++) {
    msg->fpga_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_FPGA_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_FPGA_EXTRA_LEN; i++) {
    msg->fpga_extra[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_FPGA_EXTRA, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BOARD_NAME_LEN; i++) {
    msg->board_name[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_NAME, i);
  }
  msg->board_revision = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_REVISION);
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BOARD_SERIAL_LEN; i++) {
    msg->board_serial[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_SERIAL, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_DATAPATH_HW_VERSION_NUM; i++) {
    msg->datapath_hw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_DATAPATH_HW_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_DATAPATH_FW_VERSION_NUM; i++) {
    msg->datapath_fw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_DATAPATH_FW_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_BOOT_VERSION_NUM; i++) {
    msg->soc_boot_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_BOOT_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_UBOOT_VERSION_NUM; i++) {
    msg->soc_uboot_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_UBOOT_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_MAIN_ROOTFS_VERSION_NUM; i++) {
    msg->soc_main_rootfs_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_MAIN_ROOTFS_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_RECOVERY_BUILDROOT_VERSION_NUM; i++) {
    msg->soc_recovery_buildroot_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_RECOVERY_BUILDROOT_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BOARD_VERSION_NUM; i++) {
    msg->board_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_VERSION, i);
  }
  for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BUNDLE_VERSION_NUM; i++) {
    msg->bundle_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BUNDLE_VERSION, i);
  }
  return 0;
}

/* encoders for requests */
int mc_cmd_read32_enc2(
  void *buf,
  size_t bufsize,
  uint32_t addr,
  uint32_t numwords
)
{
  uint32_t *hdr = buf;
  uint8_t *p = (uint8_t*)&hdr[2];
  size_t msg_len;

  msg_len = MC_CMD_READ32_IN_LEN;
  if (bufsize < MCDI_HEADER_LEN + msg_len)
    return -ENOSPC;

  memset(p, 0, msg_len);

  MCDI_HEADER_BUILD(hdr, MC_CMD_READ32, msg_len);

  MCDI_MEMBER_U32(p, MC_CMD_READ32_IN_ADDR) = addr;
  MCDI_MEMBER_U32(p, MC_CMD_READ32_IN_NUMWORDS) = numwords;

  MCDI_HEADER_UPDATE_CSUM(hdr, MCDI_HEADER_LEN + msg_len);

  return MCDI_HEADER_LEN + msg_len;
}

int mc_cmd_write32_enc2(
  void *buf,
  size_t bufsize,
  uint32_t addr,
  uint32_t *buffer,
  size_t buffer_size
)
{
  uint32_t *hdr = buf;
  uint8_t *p = (uint8_t*)&hdr[2];
  size_t msg_len;

  if (buffer_size < MC_CMD_WRITE32_IN_BUFFER_MINNUM ||
      buffer_size > MC_CMD_WRITE32_IN_BUFFER_MAXNUM_MCDI2)
    return -EINVAL;

  msg_len = MC_CMD_WRITE32_IN_LEN(buffer_size);
  if (bufsize < MCDI_HEADER_LEN + msg_len)
    return -ENOSPC;

  memset(p, 0, msg_len);

  MCDI_HEADER_BUILD(hdr, MC_CMD_WRITE32, msg_len);

  MCDI_MEMBER_U32(p, MC_CMD_WRITE32_IN_ADDR) = addr;
  for (size_t i = 0; i < buffer_size; i++)
    MCDI_MEMBER_U32_IDX(p, MC_CMD_WRITE32_IN_BUFFER, i) = buffer[i];

  MCDI_HEADER_UPDATE_CSUM(hdr, MCDI_HEADER_LEN + msg_len);

  return MCDI_HEADER_LEN + msg_len;
}

int mc_cmd_get_version_ext_enc2(
  void *buf,
  size_t bufsize,
  uint32_t ext_flags
)
{
  uint32_t *hdr = buf;
  uint8_t *p = (uint8_t*)&hdr[2];
  size_t msg_len;

  msg_len = MC_CMD_GET_VERSION_EXT_IN_LEN;
  if (bufsize < MCDI_HEADER_LEN + msg_len)
    return -ENOSPC;

  memset(p, 0, msg_len);

  MCDI_HEADER_BUILD(hdr, MC_CMD_GET_VERSION, msg_len);

  MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_EXT_IN_EXT_FLAGS) = ext_flags;

  MCDI_HEADER_UPDATE_CSUM(hdr, MCDI_HEADER_LEN + msg_len);

  return MCDI_HEADER_LEN + msg_len;
}

/* decoders for responses */
int mc_cmd_read32_dec2(
  void *buf,
  size_t bufsize,
  uint32_t *buffer,
  size_t *buffer_size
)
{
  uint32_t *hdr = buf;
  size_t msg_len;
  uint8_t *p = (uint8_t*)&hdr[2];

  if (bufsize < MCDI_HEADER_LEN ||
      MCDI_V1_HEADER_GET(hdr, CODE) != MC_CMD_V2_EXTN ||
      MCDI_V1_HEADER_GET(hdr, RESYNC) != 1 ||
      MCDI_V2_HEADER_GET(hdr, EXTENDED_CMD) != MC_CMD_READ32)
    return -EINVAL;

  msg_len = MCDI_V2_HEADER_GET(hdr, ACTUAL_LEN);
  if ((MCDI_HEADER_LEN + msg_len) != bufsize)
    return -EINVAL;
  if (msg_len < MC_CMD_READ32_OUT_LENMIN || msg_len > MC_CMD_READ32_OUT_LENMAX)
    return -EINVAL;
  if (buffer) {
    if (buffer_size) {
      /* TODO: use buffer_size as maxlen before loop? */
      *buffer_size = MC_CMD_READ32_OUT_BUFFER_NUM(msg_len);
    }

    for (size_t i = 0; i < MC_CMD_READ32_OUT_BUFFER_NUM(msg_len); i++) {
      buffer[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_READ32_OUT_BUFFER, i);
    }
  }

  return 0;
}

int mc_cmd_write32_dec2(
  void *buf,
  size_t bufsize
)
{
  uint32_t *hdr = buf;
  size_t msg_len;
  if (bufsize < MCDI_HEADER_LEN ||
      MCDI_V1_HEADER_GET(hdr, CODE) != MC_CMD_V2_EXTN ||
      MCDI_V1_HEADER_GET(hdr, RESYNC) != 1 ||
      MCDI_V2_HEADER_GET(hdr, EXTENDED_CMD) != MC_CMD_WRITE32)
    return -EINVAL;

  msg_len = MCDI_V2_HEADER_GET(hdr, ACTUAL_LEN);
  if ((MCDI_HEADER_LEN + msg_len) != bufsize)
    return -EINVAL;
  if (msg_len != MC_CMD_WRITE32_OUT_LEN)
    return -EINVAL;
  return 0;
}

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
)
{
  uint32_t *hdr = buf;
  size_t msg_len;
  uint8_t *p = (uint8_t*)&hdr[2];

  if (bufsize < MCDI_HEADER_LEN ||
      MCDI_V1_HEADER_GET(hdr, CODE) != MC_CMD_V2_EXTN ||
      MCDI_V1_HEADER_GET(hdr, RESYNC) != 1 ||
      MCDI_V2_HEADER_GET(hdr, EXTENDED_CMD) != MC_CMD_GET_VERSION)
    return -EINVAL;

  msg_len = MCDI_V2_HEADER_GET(hdr, ACTUAL_LEN);
  if ((MCDI_HEADER_LEN + msg_len) != bufsize)
    return -EINVAL;
  if (msg_len != MC_CMD_GET_VERSION_V5_OUT_LEN)
    return -EINVAL;
  if (mc_cmd_get_version_out_firmware) {
    *mc_cmd_get_version_out_firmware = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_OUT_FIRMWARE);
  }

  if (pcol) {
    *pcol = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_PCOL);
  }

  if (supported_funcs) {
    for (size_t i = 0; i < (MC_CMD_GET_VERSION_V5_OUT_SUPPORTED_FUNCS_LEN / 4); i++) {
      supported_funcs[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SUPPORTED_FUNCS, i);
    }
  }

  if (version) {
    *version = MCDI_MEMBER_U64(p, MC_CMD_GET_VERSION_V5_OUT_VERSION);
  }

  if (extra) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_EXTRA_LEN; i++) {
      extra[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_EXTRA, i);
    }
  }

  if (flags) {
    *flags = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_FLAGS);
  }

  if (mcfw_build_id) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_ID_LEN; i++) {
      mcfw_build_id[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_ID, i);
    }
  }

  if (mcfw_security_level) {
    *mcfw_security_level = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_MCFW_SECURITY_LEVEL);
  }

  if (mcfw_build_name) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_NAME_LEN; i++) {
      mcfw_build_name[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_MCFW_BUILD_NAME, i);
    }
  }

  if (sucfw_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SUCFW_VERSION_NUM; i++) {
      sucfw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SUCFW_VERSION, i);
    }
  }

  if (sucfw_build_date) {
    *sucfw_build_date = MCDI_MEMBER_U64(p, MC_CMD_GET_VERSION_V5_OUT_SUCFW_BUILD_DATE);
  }

  if (sucfw_chip_id) {
    *sucfw_chip_id = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_SUCFW_CHIP_ID);
  }

  if (cmcfw_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_CMCFW_VERSION_NUM; i++) {
      cmcfw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_CMCFW_VERSION, i);
    }
  }

  if (cmcfw_build_date) {
    *cmcfw_build_date = MCDI_MEMBER_U64(p, MC_CMD_GET_VERSION_V5_OUT_CMCFW_BUILD_DATE);
  }

  if (fpga_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_FPGA_VERSION_NUM; i++) {
      fpga_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_FPGA_VERSION, i);
    }
  }

  if (fpga_extra) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_FPGA_EXTRA_LEN; i++) {
      fpga_extra[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_FPGA_EXTRA, i);
    }
  }

  if (board_name) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BOARD_NAME_LEN; i++) {
      board_name[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_NAME, i);
    }
  }

  if (board_revision) {
    *board_revision = MCDI_MEMBER_U32(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_REVISION);
  }

  if (board_serial) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BOARD_SERIAL_LEN; i++) {
      board_serial[i] = MCDI_MEMBER_U8_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_SERIAL, i);
    }
  }

  if (datapath_hw_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_DATAPATH_HW_VERSION_NUM; i++) {
      datapath_hw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_DATAPATH_HW_VERSION, i);
    }
  }

  if (datapath_fw_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_DATAPATH_FW_VERSION_NUM; i++) {
      datapath_fw_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_DATAPATH_FW_VERSION, i);
    }
  }

  if (soc_boot_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_BOOT_VERSION_NUM; i++) {
      soc_boot_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_BOOT_VERSION, i);
    }
  }

  if (soc_uboot_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_UBOOT_VERSION_NUM; i++) {
      soc_uboot_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_UBOOT_VERSION, i);
    }
  }

  if (soc_main_rootfs_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_MAIN_ROOTFS_VERSION_NUM; i++) {
      soc_main_rootfs_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_MAIN_ROOTFS_VERSION, i);
    }
  }

  if (soc_recovery_buildroot_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_SOC_RECOVERY_BUILDROOT_VERSION_NUM; i++) {
      soc_recovery_buildroot_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_SOC_RECOVERY_BUILDROOT_VERSION, i);
    }
  }

  if (board_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BOARD_VERSION_NUM; i++) {
      board_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BOARD_VERSION, i);
    }
  }

  if (bundle_version) {
    for (size_t i = 0; i < MC_CMD_GET_VERSION_V5_OUT_BUNDLE_VERSION_NUM; i++) {
      bundle_version[i] = MCDI_MEMBER_U32_IDX(p, MC_CMD_GET_VERSION_V5_OUT_BUNDLE_VERSION, i);
    }
  }

  return 0;
}
