/* This file is part of BPFS. BPFS is copyright 2009-2010 The Regents of the
 * University of California. It is distributed under the terms of version 2
 * of the GNU GPL. See the file LICENSE for details. */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdbool.h>
#include <stdint.h>

// Allow caching the checksum values of blocks.
// This optimization uses a weaker checksum algorithm.
#define ENABLE_CHECKSUM_BLOCK_CACHE 1

uint64_t checksum_fs(void);

#if ENABLE_CHECKSUM_BLOCK_CACHE
// Caller must provide these functions
bool checksum_block_cache_get(uint64_t blockno, uint64_t *sum);
void checksum_block_cache_put(uint64_t blockno, uint64_t sum);
#endif

#endif
