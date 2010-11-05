/* This file is part of BPFS. BPFS is copyright 2009-2010 The Regents of the
 * University of California. It is distributed under the terms of version 2
 * of the GNU GPL. See the file LICENSE for details. */

#include "checksum.h"
#include "bpfs.h"
#include "crawler.h"

#define CHECKSUM_INITIAL 0x5AFEB9F538229AB7


static uint64_t checksum_byte(uint64_t sum, const uint8_t *x, size_t len)
{
	while (len-- > 0)
	{
		// ROL 3
		sum = (sum << 3) | (sum >> 61);
		sum ^= *(x++);
	}
	return sum;
}


static int callback_checksum_block(uint64_t blockoff, char *block,
                                   unsigned off, unsigned size, unsigned valid,
                                   uint64_t crawl_start, enum commit commit,
                                   void *sum_void, uint64_t *new_blockno)
{
	uint64_t *sum = (uint64_t*) sum_void;
	*sum = checksum_byte(*sum, (const uint8_t*) block + off, size);
	return 0;
}

static uint64_t checksum_ino(uint64_t sum, uint64_t ino);

static int read_dir_callback_checksum(uint64_t blockoff, unsigned off,
                                      const struct bpfs_dirent *dirent,
                                      void *sum_void)
{
	uint64_t *sum = (uint64_t*) sum_void;

	*sum = checksum_byte(*sum, (const uint8_t*) dirent->name,
	                     dirent->name_len);
	*sum = checksum_byte(*sum, (const uint8_t*) &dirent->ino,
	                     sizeof(dirent->ino));
	*sum = checksum_ino(*sum, dirent->ino);

	return 0;
}

static uint64_t checksum_ino(uint64_t sum, uint64_t ino)
{
	const struct bpfs_inode *inode = get_inode(ino);

	// ignore generation?
	sum = checksum_byte(sum, (const uint8_t*) &inode->uid,
	                    sizeof(inode->uid));
	sum = checksum_byte(sum, (const uint8_t*) &inode->gid,
	                    sizeof(inode->gid));
	sum = checksum_byte(sum, (const uint8_t*) &inode->mode,
	                    sizeof(inode->mode));
	// ignore nlinks (not persistent)
	sum = checksum_byte(sum, (const uint8_t*) &inode->flags,
	                    sizeof(inode->flags));
	sum = checksum_byte(sum, (const uint8_t*) &inode->root.nbytes,
	                    sizeof(inode->root.nbytes));
	// ignore [acm]time
	sum = checksum_byte(sum, (const uint8_t*) &inode->mode,
	                    sizeof(inode->mode));

	if (BPFS_S_ISREG(inode->mode))
	{
		xcall(crawl_data(ino, 0, BPFS_EOF, COMMIT_NONE,
		                 callback_checksum_block, &sum));
	}
	else if (BPFS_S_ISDIR(inode->mode))
	{
		struct read_dir_data rdd = {read_dir_callback_checksum, &sum};
		xcall(read_dir(ino, 0, &rdd));
	}

	return sum;
}


uint64_t checksum_fs(void)
{
#if COMMIT_MODE == MODE_BPFS
	return checksum_ino(CHECKSUM_INITIAL, BPFS_INO_ROOT);
#else
	// FIXME: get_inode(), crawl_data(), and read_dir() use an implicit super*
	xassert(0);
#endif
}
