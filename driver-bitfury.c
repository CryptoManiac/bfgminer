/*
 * device-bitfury.c - device functions for Bitfury chip/board library
 *
 * Copyright (c) 2013 luke-jr
 * Copyright (c) 2013 bitfury
 * Copyright (c) 2013 legkodymov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
*/

#include "miner.h"
#include <unistd.h>
#include <sha2.h>
#include "libbitfury.h"
#include "util.h"
#include "config.h"

#define GOLDEN_BACKLOG 5

struct device_drv bitfury_drv;

// Forward declarations
static void bitfury_disable(struct thr_info* thr);
static bool bitfury_prepare(struct thr_info *thr);
int calc_stat(time_t * stat_ts, time_t stat, struct timeval now);
static void get_options(struct cgpu_info *cgpu);

static void bitfury_detect(void)
{
	int chip_n;
	int i;
	struct cgpu_info *bitfury_info;

	bitfury_info = calloc(1, sizeof(struct cgpu_info));
	bitfury_info->drv = &bitfury_drv;
	bitfury_info->threads = 1;

	applog(LOG_INFO, "INFO: bitfury_detect");
	chip_n = libbitfury_detectChips(bitfury_info->devices);
	if (!chip_n) {
		applog(LOG_WARNING, "No Bitfury chips detected!");
		return;
	} else {
		applog(LOG_WARNING, "BFY: %d chips detected!", chip_n);
	}

	bitfury_info->chip_n = chip_n;
	add_cgpu(bitfury_info);
}

static uint32_t bitfury_checkNonce(struct work *work, uint32_t nonce)
{
	applog(LOG_INFO, "INFO: bitfury_checkNonce");
}

static int bitfury_submitNonce(struct thr_info *thr, struct bitfury_device *device, struct timeval *now, struct work *owork, uint32_t nonce)
{
	int i;
	int is_dupe = 0;

	for(i=0; i<32; i++) {
		if(device->nonces[i] == nonce) {
		    is_dupe = 1;
		    break;
		}
	}

	if(!is_dupe) {
		submit_nonce(thr, owork, nonce);
		device->nonces[device->current_nonce++] = nonce;
		if(device->current_nonce > 32)
			device->current_nonce = 0;
		device->stat_ts[device->stat_counter++] = now->tv_sec;
		if (device->stat_counter == BITFURY_STAT_N)
			device->stat_counter = 0;
	}

	return(!is_dupe);
}

static int64_t bitfury_scanHash(struct thr_info *thr)
{
	static struct bitfury_device *devices, *dev; // TODO Move somewhere to appropriate place
	int chip_n;
	int chip;
	uint64_t hashes = 0;
	struct timeval now;
	unsigned char line[2048];
	int short_stat = 10;
	static time_t short_out_t;
	int long_stat = 600;
	static time_t long_out_t;
	int long_long_stat = 60 * 30;
	static time_t long_long_out_t;
	static int first = 0; //TODO Move to detect()
	int i;
	int nonces_cnt;

	devices = thr->cgpu->devices;
	chip_n = thr->cgpu->chip_n;

	if (!first) {
		for (i = 0; i < chip_n; i++) {
			devices[i].osc6_bits = devices[i].osc6_bits_setpoint;
			devices[i].osc6_req = devices[i].osc6_bits_setpoint;
		}
		for (i = 0; i < chip_n; i++) {
			send_reinit(devices[i].slot, devices[i].fasync, devices[i].osc6_bits);
		}
	}
	first = 1;

	for (chip = 0; chip < chip_n; chip++) {
		dev = &devices[chip];
		dev->job_switched = 0;
		if(!dev->work) {
			dev->work = get_queued(thr->cgpu);
			if (dev->work == NULL) {
				return 0;
			}
			work_to_payload(&(dev->payload), dev->work);
		}
	}

	libbitfury_sendHashData(thr, devices, chip_n);

	cgtime(&now);
	chip = 0;
	for (;chip < chip_n; chip++) {
		nonces_cnt = 0;
		dev = &devices[chip];
		if (dev->job_switched) {
			int j;
			int *res = dev->results;
			struct work *work = dev->work;
			struct work *owork = dev->owork;
			struct work *o2work = dev->o2work;
			for (j = dev->results_n-1; j >= 0; j--) {
				if (owork) {
					nonces_cnt += bitfury_submitNonce(thr, dev, &now, owork, bswap_32(res[j]));
				}
				if (o2work) {
					// TEST
					//submit_nonce(thr, owork, bswap_32(res[j]));
				}
			}
			dev->results_n = 0;
			dev->job_switched = 0;
			if (dev->old_nonce && o2work)
				nonces_cnt += bitfury_submitNonce(thr, dev, &now, o2work, bswap_32(dev->old_nonce));

			if (dev->future_nonce)
				nonces_cnt += bitfury_submitNonce(thr, dev, &now, work, bswap_32(dev->future_nonce));

			if (o2work)
				work_completed(thr->cgpu, o2work);

			dev->o2work = dev->owork;
			dev->owork = dev->work;
			dev->work = NULL;
			hashes += 0xffffffffull * nonces_cnt;
			dev->matching_work += nonces_cnt;
		}
	}
	cgsleep_ms(100);

	return hashes;
}

int calc_stat(time_t * stat_ts, time_t stat, struct timeval now) {
	int j;
	int shares_found = 0;
	for(j = 0; j < BITFURY_STAT_N; j++) {
		if (now.tv_sec - stat_ts[j] < stat) {
			shares_found++;
		}
	}
	return shares_found;
}

static void bitfury_statline_before(char *buf, struct cgpu_info *cgpu)
{
	applog(LOG_INFO, "INFO bitfury_statline_before");
}

static bool bitfury_prepare(struct thr_info *thr)
{
	struct timeval now;
	struct cgpu_info *cgpu = thr->cgpu;

	cgtime(&now);
	get_datestamp(cgpu->init, sizeof(cgpu->init), now.tv_sec);

	get_options(cgpu);

	applog(LOG_INFO, "INFO bitfury_prepare");
	return true;
}

static void bitfury_shutdown(struct thr_info *thr)
{
	int chip_n;
	int i;

	chip_n = thr->cgpu->chip_n;

	applog(LOG_INFO, "INFO bitfury_shutdown");
	libbitfury_shutdownChips(thr->cgpu->devices, chip_n);
}

static void bitfury_disable(struct thr_info *thr)
{
	applog(LOG_INFO, "INFO bitfury_disable");
}

static int bitfury_findChip(struct bitfury_device *devices, int chip_n, int slot, int fs) {
	int n;
	for (n = 0; n < chip_n; n++) {
		if ( (devices[n].slot == slot) && (devices[n].fasync == fs) )
			return n;
	}
	return -1;
}

static void get_options(struct cgpu_info *cgpu)
{
	char buf[BUFSIZ+1];
	char *ptr, *comma, *colon, *colon2;
	size_t max = 0;
	int i, slot, fs, bits, chip, def_bits;

	for(i=0; i<cgpu->chip_n; i++)
		cgpu->devices[i].osc6_bits_setpoint = 54; // this is default value

	if (opt_bitfury_clockbits == NULL) {
		buf[0] = '\0';
		return;
	}

	ptr = opt_bitfury_clockbits;

	do {
		comma = strchr(ptr, ',');
		if (comma == NULL)
			max = strlen(ptr);
		else
			max = comma - ptr;
		if (max > BUFSIZ)
			max = BUFSIZ;
		strncpy(buf, ptr, max);
		buf[max] = '\0';

		if (*buf) {
			colon = strchr(buf, ':');
			if (colon) {
				*(colon++) = '\0';
				colon2 = strchr(colon, ':');
				if (colon2)
					*(colon2++) = '\0';
				if (*buf && *colon && *colon2) {
					slot = atoi(buf);
					fs = atoi(colon);
					bits = atoi(colon2);
					chip = bitfury_findChip(cgpu->devices, cgpu->chip_n, slot, fs);
					if(chip > 0 && chip < cgpu->chip_n && bits >= 48 && bits <= 56) {
						cgpu->devices[chip].osc6_bits_setpoint = bits;
						applog(LOG_INFO, "Set clockbits: slot=%d chip=%d bits=%d", slot, fs, bits);
					}
				}
			} else {
				def_bits = atoi(buf);
				if(def_bits >= 48 && def_bits <= 56) {
					for(i=0; i<cgpu->chip_n; i++)
						cgpu->devices[i].osc6_bits_setpoint = def_bits;
				}
			}
		}
		if(comma != NULL)
			ptr = ++comma;
	} while (comma != NULL);
}


static
bool bitfury_init(struct thr_info *thr)
{
	return true;
}

struct device_drv bitfury_drv = {
	.dname = "bitfury_gpio",
	.name = "BFY",
	.drv_detect = bitfury_detect,
	.thread_prepare = bitfury_prepare,
	.thread_init = bitfury_init,
	.scanwork = bitfury_scanHash,
	.thread_shutdown = bitfury_shutdown,
	.minerloop = hash_queued_work,
};

