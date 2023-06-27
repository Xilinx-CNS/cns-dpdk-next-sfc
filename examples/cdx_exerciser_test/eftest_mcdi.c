/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <mcdi_lib.h>
#include <mc_driver_pcol_private.h>

#define BUF_SIZE		1024

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

int get_msi_data(char *dev_name, uint32_t msi_vector,
		 uint64_t *msi_addr, uint32_t *msi_data);

static uint8_t mcdi_csum(const void *buf, int bufsize)
{
  const uint8_t *p = (const uint8_t*)buf;
  uint8_t csum = 0;

  while (bufsize--)
    csum += *p++;

  return ~csum;
}

static int mc_cmd_eftest_read_msi_msg_enc2(
	void *buf,
	size_t bufsize,
	uint8_t eftest_id,
	uint8_t eftest_op,
	uint16_t eftest_op_rsvd,
	uint32_t msi_vector
)
{
	uint32_t *hdr = buf;
	uint8_t *p = (uint8_t*)&hdr[2];
	size_t msg_len;

	msg_len = MC_CMD_EFTEST_READ_MSI_MSG_IN_LEN;
	if (bufsize < MCDI_HEADER_LEN + msg_len)
	return -ENOSPC;

	memset(p, 0, msg_len);

	MCDI_HEADER_BUILD(hdr, MC_CMD_EFTEST_OP, msg_len);

	MCDI_MEMBER_U8(p, MC_CMD_EFTEST_READ_MSI_MSG_IN_EFTEST_ID) = eftest_id;
	MCDI_MEMBER_U8(p, MC_CMD_EFTEST_READ_MSI_MSG_IN_EFTEST_OP) = eftest_op;
	MCDI_MEMBER_U16(p, MC_CMD_EFTEST_READ_MSI_MSG_IN_EFTEST_OP_RSVD) = eftest_op_rsvd;
	MCDI_MEMBER_U32(p, MC_CMD_EFTEST_READ_MSI_MSG_IN_MSI_VECTOR) = msi_vector;

	MCDI_HEADER_UPDATE_CSUM(hdr, MCDI_HEADER_LEN + msg_len);

	return MCDI_HEADER_LEN + msg_len;
}

static int mc_cmd_eftest_read_msi_msg_dec2(
	void *buf,
	size_t bufsize,
	uint64_t *msi_addr,
	uint32_t *msi_data
)
{
	uint32_t *hdr = buf;
	size_t msg_len;
	uint8_t *p = (uint8_t*)&hdr[2];

	if (bufsize < MCDI_HEADER_LEN ||
		MCDI_V1_HEADER_GET(hdr, CODE) != MC_CMD_V2_EXTN ||
		MCDI_V1_HEADER_GET(hdr, RESYNC) != 1 ||
		MCDI_V2_HEADER_GET(hdr, EXTENDED_CMD) != MC_CMD_EFTEST_OP)
		return -EINVAL;

	msg_len = MCDI_V2_HEADER_GET(hdr, ACTUAL_LEN);
	if ((MCDI_HEADER_LEN + msg_len) != bufsize)
		return -EINVAL;
	if (msg_len != MC_CMD_EFTEST_READ_MSI_MSG_OUT_LEN)
		return -EINVAL;
	if (msi_addr) {
		*msi_addr = MCDI_MEMBER_U64(p, MC_CMD_EFTEST_READ_MSI_MSG_OUT_MSI_ADDR);
	}

	if (msi_data) {
		*msi_data = MCDI_MEMBER_U32(p, MC_CMD_EFTEST_READ_MSI_MSG_OUT_MSI_DATA);
	}

	return 0;
}

int get_msi_data(char *dev_name, uint32_t msi_vector,
			uint64_t *msi_addr, uint32_t *msi_data)
{
	int fd, ret = 0;
	uint32_t mcdi_buf[BUF_SIZE] = {0};
	int buf_size = sizeof(mcdi_buf);
	int bus_id, dev_id;
	char *token1, *token2, buf[BUF_SIZE];

	strcpy(buf, dev_name);
	token1 = strtok(buf, ":");
	token2 = strtok(NULL, ":");
	bus_id = token1 ? strtoul(token1, NULL, 0) : 0;
	dev_id = token2 ? strtoul(token2, NULL, 0) : 0;

	fd = mcdi_create_device_ep(bus_id, dev_id);
	if (fd < 0) {
		fprintf(stderr, "Bus %d, Device %d is not found, error code: %d\n",
				bus_id, dev_id, fd);
		return fd;
	}
	buf_size =
	       mc_cmd_eftest_read_msi_msg_enc2(mcdi_buf, buf_size, MC_CMD_EFTEST_OP_IN_EFTEST_READ_MSI_MSG,\
			       MC_CMD_EFTEST_READ_MSI_MSG_IN_READ_MSI_MSG, 0, msi_vector);
	ret = write(fd, mcdi_buf, buf_size);
	if (ret < 0) {
		fprintf(stderr, "Write failed on device bus: %d, dev: %d\n", bus_id, dev_id);
		goto out;
	}
	memset(mcdi_buf, 0, sizeof(mcdi_buf));

	ret = read(fd, mcdi_buf, sizeof(mcdi_buf));
	if (ret < 0) {
		fprintf(stderr, "Read failed on bus: %d, dev: %d\n", bus_id, dev_id);
	} else if (ret == 0) {
		fprintf(stderr, "Read timed out on device bus: %d, dev: %d\n", bus_id, dev_id);
		ret = -ETIMEDOUT ;
	} else
		ret = mc_cmd_eftest_read_msi_msg_dec2(mcdi_buf, ret, msi_addr, msi_data);
out:
	mcdi_destroy_device_ep(fd);
	return ret;
}

