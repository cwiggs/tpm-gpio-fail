// SPDX-License-Identifier: GPL-2.0-only
/* Exercise the real audit path with synthetic register reads, never hardware. */
#include <stdlib.h>
#include <unistd.h>

static ssize_t mock_pread(int fd, void *buf, size_t count, off_t offset);

#define pread mock_pread
#define main detector_main
#include "../detect.c"
#undef main
#undef pread

static int fail_at;
static int read_count;
static int short_read;
static uint32_t register_value;

static ssize_t mock_pread(int fd, void *buf, size_t count, off_t offset)
{
	(void)fd;
	(void)offset;
	if (++read_count == fail_at) {
		if (short_read >= 0) {
			memset(buf, 0xff, short_read);
			return short_read;
		}
		errno = EPERM;
		return -1;
	}
	memcpy(buf, &register_value, count);
	return count;
}

int main(int argc, char **argv)
{
	if (argc != 4)
		return 1;
	fail_at = atoi(argv[1]);
	short_read = atoi(argv[2]);
	register_value = strtoul(argv[3], NULL, 0);

	struct pin global_pins[] = {
		{ "GPP_B13", "PLTRST#", 0xaf, 0x80, 1u << 13 },
		{0}
	};
	struct pin bus_pins[] = {
		{ "GPP_A1", "TEST_BUS", 0xaf, 0x88, 1u << 1 },
		{0}
	};
	struct platform platform = {
		.name = "Synthetic test platform",
		.global_pins = global_pins,
		.pad_cfg_base = 0x700,
		.pad_stride = 16,
		.espi_check_port = 0xc7,
		.espi_check_offset = 0x3418,
		.espi_check_bit = 1u << 1,
		.lpc_pins = bus_pins,
		.espi_pins = bus_pins,
		.tier = 1,
		.summary = "Synthetic registers only",
	};

	/* No iopl(), PCI access, or /dev/mem open: every read is mocked. */
	return audit_platform(&platform);
}
