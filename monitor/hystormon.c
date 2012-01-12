/*
 * Hystor user-level monitor daemon.
 *
 * This program is based on blkiomon in blktrace package.
 *
 * Author(s): Hyogi Sim <sandrain@gmail.com>
 *
 * TODO:
 * - Block Table.
 * - Generate the remapped-list for reorganization.
 * - Sending the remapped-list to our kernel module.
 * - Daemonize the program.
 *
 * =========================================================================
 * From the original author:
 * I/O monitor based on block queue trace data
 *
 * Copyright IBM Corp. 2008
 *
 * Author(s): Martin Peschke <mp3@de.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <locale.h>
#include <libgen.h>
#include <sys/msg.h>
#include <pthread.h>
#include <time.h>

#include "blktrace.h"
#include "rbtree.h"
#include "jhash.h"
#include "blkiomon.h"

struct trace {
	struct blk_io_trace bit;
	struct trace *next;
	long sequence;
};

static FILE *ifp;
static int interval = -1;

#define	VACANT_LIST_SIZE		1024
static struct trace *vacant_traces_list = NULL;
static int vacant_traces = 0;

static struct trace *thash[2] = { NULL, NULL };
static struct trace *thash_tail = NULL;	/* For quick appending */
static int thash_curr = 0;
static int thash_size = 0;

static pthread_t interval_thread;
static pthread_mutex_t thash_mutex = PTHREAD_MUTEX_INITIALIZER;

int data_is_native = -1;
static int up = 1;
static long sequence = 0;

/* debug */
#ifdef __DEBUG__
#	define	dprintf(s, arg...)	fprintf(stderr, s, ##arg)
#else
#	define	dprintf(s, arg...)
#endif

static struct trace *blkiomon_alloc_trace(void)
{
	struct trace *t = vacant_traces_list;
	if (t) {
		vacant_traces_list = t->next;
		vacant_traces--;
	} else
		t = malloc(sizeof(*t));
	memset(t, 0, sizeof(*t));
	return t;
}

static void blkiomon_free_trace(struct trace *t)
{
	if (vacant_traces < VACANT_LIST_SIZE) {
		t->next = vacant_traces_list;
		vacant_traces_list = t;
		vacant_traces++;
	} else
		free(t);
}

static inline void blkiomon_free_thash(struct trace *thash)
{
	struct trace *tmp = thash;

	while (tmp) {
		struct trace *t = tmp;
		tmp = tmp->next;
		blkiomon_free_trace(t);
	}
}

static void hystor_do_monitor(struct trace *tlist, int size)
{
	struct trace *tmp;

	dprintf("== Monitor [list=%d (%d entries)] ==\n", thash_curr, size);

	for (tmp = tlist; tmp; tmp = tmp->next) {
		char dir = tmp->bit.action & BLK_TC_ACT(BLK_TC_READ) ? 'R' : 'W';
		dprintf("[%c] %llu, %u\n", dir, tmp->bit.sector, tmp->bit.bytes >> 9);
	}
}

static void *blkiomon_interval(void *data)
{
	struct timespec wake, r;
	int finished;
	int old_size;

	clock_gettime(CLOCK_REALTIME, &wake);

	while (1) {
		wake.tv_sec += interval;
		if (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &wake, &r)) {
			fprintf(stderr, "blkiomon: interrupted sleep");
			continue;
		}

		/* grab list and make data gatherer build up another list */
		pthread_mutex_lock(&thash_mutex);
		finished = thash_curr;
		thash_curr = thash_curr ? 0 : 1;
		thash_tail = NULL;
		old_size = thash_size;
		thash_size = 0;
		pthread_mutex_unlock(&thash_mutex);

		/* process with trace data. */
		hystor_do_monitor(thash[finished], old_size);
		if (thash[finished]) {
			blkiomon_free_thash(thash[finished]);
			thash[finished] = NULL;
		}
	}
	return data;
}

static inline void blkiomon_store_trace(struct trace *t)
{
	if (thash[thash_curr] == NULL) {
		thash[thash_curr] = t;
	}
	else {
		thash_tail->next = t;
	}

	thash_tail = t;
	t->next = NULL;
	thash_size++;
}

/* If we have a consecutive request, we update the previous request
 * and don't append the request to the list. */
static struct trace *blkiomon_do_trace(struct trace *t)
{
	int act = t->bit.action & 0xffff;

	if ((t->bit.action & BLK_TC_ACT(BLK_TC_QUEUE)) && act == __BLK_TA_QUEUE) {
		if (t->bit.sector == 0 && t->bit.bytes == 0)
			return t;

		if (thash_tail) {
			/* Check if we have consecutive request */
			struct blk_io_trace *previous = &thash_tail->bit;
			struct blk_io_trace *current = &t->bit;

			if ((current->action == previous->action) &&
			    (current->sector == previous->sector + (previous->bytes >> 9))) {
				previous->bytes += current->bytes;
				return t;
			}
		}

		blkiomon_store_trace(t);
		return blkiomon_alloc_trace();
	}

	return t;
}

static int blkiomon_do_fifo(void)
{
	struct trace *t;
	struct blk_io_trace *bit;
	void *pdu_buf = NULL;

	t = blkiomon_alloc_trace();
	if (!t)
		return 1;
	bit = &t->bit;

	while (up) {
		if (fread(bit, sizeof(*bit), 1, ifp) != 1) {
			if (!feof(ifp))
				fprintf(stderr,
					"blkiomon: could not read trace");
			break;
		}
		if (ferror(ifp)) {
			clearerr(ifp);
			fprintf(stderr, "blkiomon: error while reading trace");
			break;
		}

		if (data_is_native == -1 && check_data_endianness(bit->magic)) {
			fprintf(stderr, "blkiomon: endianess problem\n");
			break;
		}

		/* endianess */
		trace_to_cpu(bit);
		if (verify_trace(bit)) {
			fprintf(stderr, "blkiomon: bad trace\n");
			break;
		}

		/* read additional trace payload */
		if (bit->pdu_len) {
			pdu_buf = realloc(pdu_buf, bit->pdu_len);
			if (fread(pdu_buf, bit->pdu_len, 1, ifp) != 1) {
				clearerr(ifp);
				fprintf(stderr, "blkiomon: could not read payload\n");
				break;
			}
		}

		t->sequence = sequence++;

		/* try to find matching trace and update statistics */
		t = blkiomon_do_trace(t);
		if (!t) {
			fprintf(stderr, "blkiomon: could not alloc trace\n");
			break;
		}
		bit = &t->bit;
		/* t and bit will be recycled for next incoming trace */
	}
	blkiomon_free_trace(t);
	free(pdu_buf);
	return 0;
}

static char usage_str[] = "\n\nblkiomon " \
	"-I <interval>       | --interval=<interval>\n\n";

static void blkiomon_signal(int signal)
{
	fprintf(stderr, "blkiomon: terminated by signal\n");
	up = signal & 0;
}

int main(int argc, char *argv[])
{
	int c;

	signal(SIGALRM, blkiomon_signal);
	signal(SIGINT, blkiomon_signal);
	signal(SIGTERM, blkiomon_signal);
	signal(SIGQUIT, blkiomon_signal);

	while ((c = getopt(argc, argv, "I:")) != -1) {
		switch (c) {
		case 'I':
			interval = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Usage: %s", usage_str);
			return 1;
		}
	}

	if (interval <= 0) {
		fprintf(stderr, "Usage: %s", usage_str);
		return 1;
	}

	ifp = fdopen(STDIN_FILENO, "r");
	if (!ifp) {
		perror("blkiomon: could not open stdin for reading");
		return 1;
	}

	if (pthread_create(&interval_thread, NULL, blkiomon_interval, NULL)) {
		fprintf(stderr, "blkiomon: could not create thread");
		return 1;
	}

	blkiomon_do_fifo();

	return 0;
}

