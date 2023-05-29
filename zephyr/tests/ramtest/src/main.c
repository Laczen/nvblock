/*
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include "nvblock/nvblock.h"

uint8_t data[4096 * 4] = { 0xff };

static int my_read(const struct nvb_config *cfg, uint32_t p, void *buffer)
{
	const uint32_t bsize = cfg->bsize;
	const uint32_t off = p * bsize;
	uint8_t *buf = (uint8_t *)buffer;

	memcpy(buf, &data[off], bsize);
	return 0;
}

static int my_prog(const struct nvb_config *cfg, uint32_t p, const void *buffer)
{
	const uint32_t bsize = cfg->bsize;
	const uint32_t off = p * bsize;
	const uint8_t *buf = (const uint8_t *)buffer;

	memcpy(&data[off], buf, bsize);
	return 0;
}

static int my_comp(const struct nvb_config *cfg, uint32_t p, const void *buffer)
{
	const uint32_t bsize = cfg->bsize;
	const uint32_t off = p * bsize;
	const uint8_t *buf = (const uint8_t *)buffer;

	return memcmp(&data[off], buf, bsize);
}

static int my_move(const struct nvb_config *cfg, uint32_t pf, uint32_t pt)
{
	const uint32_t bsize = cfg->bsize;
	const uint32_t off_f = pf * bsize;
	const uint32_t off_t = pt * bsize;

	memcpy(&data[off_t], &data[off_f], bsize);
	return 0;
}

static bool my_is_free(const struct nvb_config *cfg, uint32_t p)
{
	const uint32_t bsize = cfg->bsize;
	uint8_t empty[bsize];
	const uint32_t off = p * bsize;

	memset(empty, 0xff, bsize);
	if (memcmp(&data[off], empty, bsize)) {
		return false;
	}
	return true;
}

static bool my_is_bad(const struct nvb_config *cfg, uint32_t p)
{
	return false;
}

static int my_sync(const struct nvb_config *cfg)
{
	return 0;
}

static int my_init(const struct nvb_config *cfg)
{
	return 0;
}

static void my_lock(const struct nvb_config *cfg)
{
	return;
}

static void my_unlock(const struct nvb_config *cfg)
{
	return;
}

uint8_t meta[64];

struct nvb_config testcfg = {
	.context = NULL,
	.meta = meta,
	.init = my_init,
	.read = my_read,
	.prog = my_prog,
	.comp = my_comp,
	.move = my_move,
	.sync = my_sync,
	.is_free = my_is_free,
	.is_bad = my_is_bad,
	.lock = my_lock,
	.unlock = my_unlock,
	.bsize = 64,
	.bpg = 8,
	.gcnt = 4,
	.spgcnt = 1,
};

struct nvb_info test;

static void small_report_nvb(struct nvb_info *info)
{
	printk("Head at block [%d], GCHead at block [%d]\n", info->head,
	       info->gc_head);
	printk("Root at block [%d], Status [%d], epoch [%d]\n", info->root,
	       nvb_status(info), info->epoch);
}
static void report_nvb(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	uint32_t bcnt;

	nvb_ioctl(&test, NVB_CMD_GET_BLK_COUNT, (void *)&bcnt);

	printk("-------------------------------------\n");
	printk("Non volatile block area\n");
	printk("-------------------------------------\n");
	printk("Block size: %d, bpg: %d\n", cfg->bsize, cfg->bpg);
	printk("Block count: %d, group count: %d\n", bcnt, cfg->gcnt);
	printk("Direct map entries: %d\n", info->meta_dmmsk + 1);
	small_report_nvb(info);
	printk("-------------------------------------\n");
}

static void test_init(void)
{
	struct nvb_info *tst = &test;
	struct nvb_config *cfg = &testcfg;
	int rc;

	rc = nvb_init(tst, cfg);
	zassert_equal(rc, 0, "init failed [%d]", rc);
	rc = nvb_status(tst);
	zassert_equal(rc, NVB_STATUS_OK, "status bad after init");
}

static void test_clear_storage(void)
{
	memset(data, 0xff, sizeof(data));
}

static void test_set_block(char *buf, char value, uint32_t size)
{
	memset(buf, value, size);
}

static void test_rw(void)
{
	test_clear_storage();
	test_init();

	struct nvb_info *tst = &test;
	struct nvb_config *cfg = &testcfg;
	const uint32_t bs = cfg->bsize;
	char wr_data1[bs], wr_data2[2 * bs], rd_data[bs];
	int rc;

	test_set_block(wr_data1, 'A', bs);
	test_set_block(wr_data2, 'A', bs);
	test_set_block(wr_data2 + bs, 'B', bs);

	rc = nvb_write(tst, wr_data1, 0, 1);
	zassert_equal(rc, 0, "write failed [%d]", rc);
	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");
	rc = nvb_write(tst, wr_data2, 0, 2);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");
	rc = nvb_read(tst, rd_data, 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2 + bs, rd_data, bs), 0, "data error");
	report_nvb(tst);
}

static void test_rwext(void)
{
	test.cfg = NULL;
	test_clear_storage();
	test_init();

	struct nvb_info *tst = &test;
	struct nvb_config *cfg = &testcfg;
	const uint32_t bs = cfg->bsize;
	char wr_data1[bs], wr_data2[bs], rd_data[bs];
	int rc;

	test_set_block(wr_data1, 'A', bs);
	test_set_block(wr_data2, 'B', bs);

	rc = nvb_write(tst, wr_data1, 0, 1);
	zassert_equal(rc, 0, "write failed [%d]", rc);
	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");
	rc = nvb_write(tst, wr_data2, tst->meta_dmmsk, 1);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, tst->meta_dmmsk, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");

	rc = nvb_write(tst, wr_data2, tst->meta_dmmsk + 1, 1);
	zassert_equal(rc, 0, "write failed [%d]", rc);
	rc = nvb_read(tst, rd_data, tst->meta_dmmsk + 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");
	rc = nvb_write(tst, wr_data1, 2 * tst->meta_dmmsk + 1, 1);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 2 * tst->meta_dmmsk + 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");

	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");
	rc = nvb_read(tst, rd_data, tst->meta_dmmsk, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");

	report_nvb(tst);
}

static void test_wrap(void)
{
	testcfg.comp = NULL;
	test.cfg = NULL;
	test_clear_storage();
	test_init();

	struct nvb_info *tst = &test;
	struct nvb_config *cfg = &testcfg;
	const uint32_t bs = cfg->bsize;
	char wr_data1[bs], wr_data2[bs], rd_data[bs];
	int rc;

	test_set_block(wr_data1, 'A', bs);
	test_set_block(wr_data2, 'B', bs);

	rc = nvb_write(tst, wr_data1, 0, 1);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");

	while (tst->epoch < 2U) {
		rc = nvb_write(tst, wr_data2, 1, 1);
		zassert_equal(rc, 0, "write failed");
		rc = nvb_read(tst, rd_data, 1, 1);
		zassert_equal(rc, 0, "read failed");
		zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");
	}
	report_nvb(tst);

	rc = nvb_read(&test, &rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "cmp error");
}

void test_unfinished_write(void)
{
	testcfg.comp = NULL;
	test.cfg = NULL;
	test_clear_storage();
	test_init();

	struct nvb_info *tst = &test;
	struct nvb_config *cfg = &testcfg;
	const uint32_t bs = cfg->bsize;
	char wr_data1[bs], wr_data2[bs], rd_data[bs];
	int rc;

	test_set_block(wr_data1, 'A', bs);
	test_set_block(wr_data2, 'B', bs);

	rc = nvb_write(tst, wr_data1, 0, 1);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");

	rc = nvb_write(tst, wr_data1, 1, 1);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");

	rc = nvb_write(tst, wr_data2, 1, 1);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");
	small_report_nvb(tst);

	/* invalidate last write */
	printk("Invalidating written block [%d]\n", tst->root);
	rc = my_prog(cfg, tst->root, wr_data2);

	/* initialize again */
	test.cfg = NULL;
	test_init();
	small_report_nvb(tst);

	rc = nvb_read(&test, &rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "cmp error");
	rc = nvb_read(&test, &rd_data, 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "cmp error");

	rc = nvb_write(tst, wr_data2, 1, 1);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");
	small_report_nvb(tst);
}

static bool my_is_bad2(const struct nvb_config *cfg, uint32_t p)
{
	const uint32_t bsize = cfg->bsize;
	const uint32_t gsize = cfg->bsize * cfg->bpg;
	const char marker[4]= {'!','B','A','D'};
	const uint32_t off = (p * bsize) / gsize + gsize - bsize;
	if (memcmp(&data[off], marker, sizeof(marker)) == 0) {
		return true;
	}
	return false;
}

static void my_mark_bad(const struct nvb_config *cfg, uint32_t p)
{
	const uint32_t bsize = cfg->bsize;
	const uint32_t gsize = cfg->bsize * cfg->bpg;
	const char marker[4]= {'!','B','A','D'};
	const uint32_t off = (p * bsize) / gsize + gsize - bsize;
	memcpy(&data[off], marker, sizeof(marker));
}

static int my_prog_bad(const struct nvb_config *cfg, uint32_t p,
		       const void *buffer)
{
	const uint32_t bsize = cfg->bsize;
	const uint32_t off = p * bsize;
	const uint8_t *buf = (const uint8_t *)buffer;

	if (p == 3) {
		return -NVB_EFAULT;
	}
	memcpy(&data[off], buf, bsize);
	return 0;
}

static void test_badblock(void)
{
	test.cfg = NULL;
	test_clear_storage();

	testcfg.spgcnt = 2;
	testcfg.prog = my_prog_bad;
	testcfg.is_bad = my_is_bad2;
	testcfg.mark_bad = my_mark_bad;
	test_init();

	struct nvb_info *tst = &test;
	struct nvb_config *cfg = &testcfg;
	const uint32_t bs = cfg->bsize;
	char wr_data1[bs], wr_data2[2 * bs], rd_data[bs];
	int rc;

	report_nvb(tst);
	test_set_block(wr_data1, 'A', bs);
	test_set_block(wr_data2, 'B', bs);
	test_set_block(wr_data2 + bs, 'C', bs);

	rc = nvb_write(tst, wr_data1, 0, 1);
	zassert_equal(rc, 0, "write failed [%d]", rc);
	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");
	rc = nvb_write(tst, wr_data2, 0, 2);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_write(tst, wr_data2, 1, 2);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_write(tst, wr_data2, 3, 2);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_write(tst, wr_data2, 5, 2);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_write(tst, wr_data2, 7, 2);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_write(tst, wr_data2, 9, 2);
	zassert_equal(rc, 0, "write failed");
	rc = nvb_read(tst, rd_data, 0, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data1, rd_data, bs), 0, "data error");
	rc = nvb_read(tst, rd_data, 1, 1);
	zassert_equal(rc, 0, "read failed");
	zassert_equal(memcmp(wr_data2, rd_data, bs), 0, "data error");
	report_nvb(tst);
}

void test_finish(void)
{

}

void test_main(void)
{
	ztest_test_suite(nvb_test,
		ztest_unit_test(test_rw),
		ztest_unit_test(test_rwext),
		ztest_unit_test(test_wrap),
		ztest_unit_test(test_unfinished_write),
		ztest_unit_test(test_badblock),
		ztest_unit_test(test_finish)
	);

	ztest_run_test_suite(nvb_test);
}
