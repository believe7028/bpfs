/* This file is part of BPFS. BPFS is copyright 2009-2010 The Regents of the
 * University of California. It is distributed under the terms of version 2.1
 * of the GNU LGPL. See the file LICENSE for details. */

// This file contains an ISA-portable PIN tool for tracing BPFS writes to BPRAM
// and checking that the file system is always equivalent to its state
// before or after the current system call.

// TODO: see source/tools/ManualExamples/proccount.cpp for obtaining fn names

#define __STDC_FORMAT_MACROS

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>
#include "pin.H"


// Why doesn't stdint.h define this?
#ifndef UINT64_MAX
# define UINT64_MAX 18446744073709551615UL
#endif

extern "C" {
#include "bpfs.h"
#include "crawler.h"
#include "checksum.h"
#include "util.h"
}

#define BPRAM_INFO "inform_pin_of_bpram"
#define BPFS_COMMIT_START "random_checksum_start_op"
#define BPFS_COMMIT_END "random_checksum_stop_op"


const void *bpram_start;
const void *bpram_end;
UINT64 bpram_nbytes;

UINT64 nbytes;

KNOB<bool> KnobQuiet(KNOB_MODE_WRITEONCE, "pintool",
	"q", "0", "Quiet (t/f)");

KNOB<UINT64> KnobOpMax(KNOB_MODE_WRITEONCE, "pintool",
	"o", "1000", "Max number of file system operations between tests");

KNOB<UINT64> KnobWriteMax(KNOB_MODE_WRITEONCE, "pintool",
	"w", "50", "Max number of write insructions between tests");


//
// Backtrace

// Max backtrace depth
#define NBSTEPS 20

#ifdef __i386__
# define REG_BP_ARCH REG_EBP
#elif defined(__x86_64__)
# define REG_BP_ARCH REG_RBP
#endif

struct stack_frame
{
	struct stack_frame *next;
	void *ret;
};

VOID LogBacktrace(CONTEXT *ctxt, VOID *rip, ADDRINT size)
{
	const char *btopt = "(Might this be because you are trying to backtrace optimized code?)";
	struct stack_frame *fp = reinterpret_cast<struct stack_frame*>(PIN_GetContextReg(ctxt, REG_BP_ARCH));
	struct stack_frame *last_fp = NULL;
	int i = 0;

	printf("backtrace:\n");

	printf("%p\n", reinterpret_cast<void*>(PIN_GetContextReg(ctxt, REG_INST_PTR)));

	// Normally rip contains numbers that are small and not in a function.
	// But sometimes REG_INST_PTR (aka EIP) is bogus and rip is not.
	if (rip)
		printf("%p\n", rip);

	while (fp >= last_fp && i < NBSTEPS)
	{
		void *ret;
		size_t n;
		EXCEPTION_INFO ei;

		n = PIN_SafeCopyEx(&ret, &fp->ret, sizeof(ret), &ei);
		if (!n)
		{
			printf("pin: stack trace failed at depth %d (read ret)\n", i);
			printf("%s\n", btopt);
			printf("EI: \"%s\"\n", PIN_ExceptionToString(&ei).c_str());
			break;
		}
		if (!ret)
			break;
		printf("%p\n", ret);
		last_fp = fp;

		n = PIN_SafeCopyEx(&fp, &last_fp->next, sizeof(fp), &ei);
		if (!n)
		{
			printf("pin: stack trace failed at depth %d (read next)\n", i);
			printf("%s\n", btopt);
			printf("EI: \"%s\"\n", PIN_ExceptionToString(&ei).c_str());
			break;
		}
	}
}


//
// Reimplementation of the bpfs.h and indirect_cow.h API

static struct {
   char *bpram;
} bpfs_mirror;

extern "C" {

uint64_t tree_root_height(const struct bpfs_tree_root *root)
{
	if (!root->nbytes)
		return BPFS_BLOCKNO_INVALID;
	return root->ha.height;
}

uint64_t tree_root_addr(const struct bpfs_tree_root *root)
{
	if (!root->nbytes)
		return BPFS_BLOCKNO_INVALID;
	return root->ha.addr;
}

uint64_t get_super_blockno(void)
{
	return BPFS_BLOCKNO_SUPER;
}

struct bpfs_super* get_super(void)
{
	// FIXME for SP: SP switches between super blocks
	return (bpfs_super*) bpfs_mirror.bpram;
}

char* get_block(uint64_t blockno)
{
	if (blockno == BPFS_BLOCKNO_INVALID)
	{
		assert(0);
		return NULL;
	}
	static_assert(BPFS_BLOCKNO_INVALID == 0);
	if (blockno > get_super()->nblocks)
	{
		assert(0);
		return NULL;
	}

	return bpfs_mirror.bpram + (blockno - 1) * BPFS_BLOCK_SIZE;
}

struct bpfs_tree_root* get_inode_root(void)
{
	struct bpfs_super *super = get_super();
	return (struct bpfs_tree_root*) get_block(super->inode_root_addr);
}

uint64_t tree_max_nblocks(uint64_t height)
{
	uint64_t max_nblocks = 1;
	while (height--)
		max_nblocks *= BPFS_BLOCKNOS_PER_INDIR;
	return max_nblocks;
}

int indirect_cow_parent_push(uint64_t blkno)
{
	return 0;
}
void indirect_cow_parent_pop(uint64_t blkno)
{
}

uint64_t tree_height(uint64_t nblocks)
{
	uint64_t height = 0;
	uint64_t max_nblocks = 1;
	while (nblocks > max_nblocks)
	{
		max_nblocks *= BPFS_BLOCKNOS_PER_INDIR;
		height++;
	}
	return height;
}

int get_inode_offset(uint64_t ino, uint64_t *poffset)
{
	uint64_t no;
	uint64_t offset;

	if (ino == BPFS_INO_INVALID)
	{
		assert(0);
		return -EINVAL;
	}

	static_assert(BPFS_INO_INVALID == 0);
	no = ino - 1;

	// XXX: need to know inode count
	/*
	if (no >= inode_alloc.bitmap.ntotal)
	{
		assert(0);
		return -EINVAL;
	}
	*/

	offset = no * sizeof(struct bpfs_inode);
	if (offset + sizeof(struct bpfs_inode) > get_inode_root()->nbytes)
	{
		assert(0);
		return -EINVAL;
	}
	*poffset = offset;
	return 0;
}

int truncate_block_zero(struct bpfs_tree_root *root,
                        uint64_t begin, uint64_t end, uint64_t valid,
                        uint64_t *blockno)
{
   assert(0);
   return -1;
}

static int callback_read_dir(uint64_t blockoff, char *block,
                             unsigned off, unsigned size,
                             unsigned valid, uint64_t crawl_start,
                             enum commit commit, void *rdd_void,
                             uint64_t *blockno)
{
	const struct read_dir_data *rdd = (const struct read_dir_data*) rdd_void;
	unsigned end = off + size;

	while (off + BPFS_DIRENT_MIN_LEN <= end)
	{
		struct bpfs_dirent *dirent = (struct bpfs_dirent*) (block + off);

		assert(!(off % BPFS_DIRENT_ALIGN));

		if (!dirent->rec_len)
		{
			// end of directory entries in this block
			break;
		}
		off += dirent->rec_len;
		xassert(off <= BPFS_BLOCK_SIZE); // x in assert for discover_inodes

		if (dirent->ino != BPFS_INO_INVALID)
		{
			int r;

			assert(dirent->rec_len >= BPFS_DIRENT_LEN(dirent->name_len));

			r = rdd->callback(blockoff, off, dirent, rdd->user);
			if (r)
				return r;
		}
	}
	return 0;
}

int read_dir(uint64_t ino, uint64_t off, struct read_dir_data *rdd)
{
	return crawl_data(ino, off, BPFS_EOF, COMMIT_NONE, callback_read_dir, rdd);
}

uint64_t cow_block_hole(unsigned off, unsigned size, unsigned valid)
{
	assert(0);
	return BPFS_BLOCKNO_INVALID;
}

void ha_set_addr(struct height_addr *pha, uint64_t addr)
{
	struct height_addr ha = { height: pha->height, addr: addr };
	assert(addr <= BPFS_TREE_ROOT_MAX_ADDR);
	*pha = ha;
}

void ha_set(struct height_addr *pha, uint64_t height, uint64_t addr)
{
	struct height_addr ha = { height: height, addr: addr };
	assert(height <= BPFS_TREE_MAX_HEIGHT);
	assert(addr <= BPFS_TREE_ROOT_MAX_ADDR);
	*pha = ha;
}

int tree_change_height(struct bpfs_tree_root *root,
                       unsigned new_height,
                       enum commit commit, uint64_t *blockno)
{
	assert(0);
	return -1;
}

void indirect_cow_block_required(uint64_t blkno)
{
}

uint64_t cow_block_entire(uint64_t old_blockno)
{
	assert(0);
	return BPFS_BLOCKNO_INVALID;
}

static int callback_get_inode(char *block, unsigned off,
                              struct bpfs_inode *inode, enum commit commit,
                              void *pinode_void, uint64_t *blockno)
{
	struct bpfs_inode **pinode = (struct bpfs_inode**) pinode_void;
	*pinode = inode;
	return 0;
}

struct bpfs_inode* get_inode(uint64_t ino)
{
	struct bpfs_inode *inode;
	xcall(crawl_inode(ino, COMMIT_NONE, callback_get_inode, &inode));
	return inode;
}

}


//
// Checksum

class freq_fire
{
public:
	freq_fire(uint64_t max_period)
	   : ntotalevents(0), max_period(max_period)
	{
		assert(max_period);
		assert(max_period <= RAND_MAX);
		reset();
	}

	void reset()
	{
		nremaining = rand() % max_period;
	}

	bool event(bool trueevent)
	{
		ntotalevents++;
		assert(ntotalevents);
		if (trueevent && !nremaining--)
		{
			nfires++;
			reset();
			return true;
		}
		return false;
	}

	uint64_t ntotalevents;
	uint64_t nfires;

	const uint64_t max_period;
	uint64_t nremaining;
};

class bpfs_checksum
{
public:
	bpfs_checksum(uint64_t op_max, uint64_t write_max)
	  : fire_ops(op_max),
	    fire_writes(write_max),
	    in_op(false),
	    op_fire_writes_te_start(0), op_fire_writes_f_start(0),
	    prev(0), hope_next_set(false), hope_next(0)
	{
		printf("pin: op_max = %" PRIu64 ", write_max = %" PRIu64 "\n",
		       fire_ops.max_period, fire_writes.max_period);
	}

	void op_start()
	{
		assert(!in_op);
		in_op = true;

		checking_op = fire_ops.event(true);
		if (checking_op)
		{
			if (!KnobQuiet.Value())
			{
				printf("pin: ");
				fflush(stdout);
			}
			prev = timed_checksum_fs(NULL);
			fire_writes.reset();
			op_fire_writes_te_start = fire_writes.ntotalevents;
			op_fire_writes_f_start = fire_writes.nfires;
		}
	}

   	bool op_check()
	{
		uint64_t sum;

		if (!in_op)
			return true; // TODO: why is this possible?

		if (!fire_writes.event(checking_op))
			return true;

		sum = timed_checksum_fs(NULL);
		if (sum != prev)
		{
		   if (!hope_next_set)
		   {
			  hope_next_set = true;
			  hope_next = sum;
		   }
		   else if (sum != hope_next)
		   {
			   return false;
		   }
		}
		return true;
	}

	void op_stop(const char *fn)
	{
		struct timeval len;
		memset(&len, 0, sizeof(len)); // appease gcc

		if (!in_op)
		{
			printf("Not in an op? Function \"%s\".", fn);
			assert(in_op);
		}
		in_op = false;

		if (!checking_op)
			return;

		if (hope_next_set)
		{
			uint64_t sum = timed_checksum_fs(&len);
			if (hope_next != sum)
			{
				printf("pin: Non-atomic write. Detect at end of op \"%s\".\n",
				       fn);
				xassert(hope_next == sum);
			}
		}

		if (!KnobQuiet.Value())
		{
			printf("op time %ld.%.06lds", time_op.tv_sec, time_op.tv_usec);
			if (hope_next_set)
				printf(" (last check %ld.%.06lds)", len.tv_sec, len.tv_usec);
			printf(". %" PRIu64 "/%" PRIu64 " writes. next op in %" PRIu64 ".\n",
			       fire_writes.nfires - op_fire_writes_f_start,
			       fire_writes.ntotalevents - op_fire_writes_te_start,
			       fire_ops.nremaining);
		}
		timerclear(&time_op);

		hope_next_set = false;
		hope_next = 0;
	}

	freq_fire fire_ops;
	freq_fire fire_writes;

private:
   	uint64_t timed_checksum_fs(struct timeval *len)
	{
		uint64_t sum;
		struct timeval start, end;
		gettimeofday(&start, NULL);
		sum = checksum_fs();
		gettimeofday(&end, NULL);
		timersub(&end, &start, &end);
		if (len)
			*len = end;
		timeradd(&time_op, &end, &time_op);
		return sum;
	}

	bool in_op;
	bool checking_op;
	struct timeval time_op;
	uint64_t op_fire_writes_te_start;
   	uint64_t op_fire_writes_f_start;

   	uint64_t prev;
	bool hope_next_set;
	uint64_t hope_next;
};

bpfs_checksum *checksum;


//
// Check that writes to BPRAM do not break file system operation atomicity

static bool PTRMW_addr_set;
static VOID *PTRMW_addr;

VOID PrepareToRecordMemWrite(VOID *addr, ADDRINT size)
{
	if (bpram_start <= addr && addr < bpram_end)
	{
		// TODO: pass addr through a G0 register instead?
		PTRMW_addr = addr;
		PTRMW_addr_set = true;
	}
}

VOID RecordMemWrite(ADDRINT size, CONTEXT *ctxt, VOID *rip)
{
	VOID *addr = PTRMW_addr;
	if (PTRMW_addr_set && bpram_start <= addr && addr < bpram_end)
	{
		uint64_t off = (uint64_t)addr - (uint64_t)bpram_start;
		EXCEPTION_INFO ei;
		size_t n;
		assert(off + size <= bpram_nbytes);
		n = PIN_SafeCopyEx(bpfs_mirror.bpram + off, addr, size, &ei);
		if (n != size)
		{
			static bool warned = false;
			if (!KnobQuiet.Value() || !warned)
			{
				fprintf(stderr, "pin: %s: %lu != %lu\n", __FUNCTION__, n, size);
				if (KnobQuiet.Value())
				   fprintf(stderr, "(not notifying of additional copy errors)\n");
				warned = true;
			}
		}
		//xassert(n == size); // fails at end. why? OK?
		nbytes += size;

		// Useful if checksum_fs() hits an error:
		// LogBacktrace(ctxt, rip, size);
		bool p = checksum->op_check();
		if (!p)
		{
			printf("pin: Non-atomic write. Detected within the op.\n");
			LogBacktrace(ctxt, rip, size);
			xassert(0);
		}
	}
	PTRMW_addr_set = false;
}

VOID Instruction(INS ins, VOID *v)
{
    // Would checking !INS_IsIpRelWrite() improve performance?
    if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
    {
        // The Pin manual suggests dividing this into If and Then pieces
        // to permit inlining of the If case, but I've found for bpramcount
		// that If-Then is slower. Maybe if RecordMemWrite() is more
        //  expensive here and this tradeoff is different?
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR) PrepareToRecordMemWrite,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_END);
		INS_InsertPredicatedCall(
            ins, IPOINT_AFTER, (AFUNPTR) RecordMemWrite,
            IARG_MEMORYWRITE_SIZE,
			IARG_CONTEXT,
			IARG_RETURN_IP,
            IARG_END);
    }
}

ADDRINT BpramWriteIf(VOID *addr)
{
	return (bpram_start <= addr && addr < bpram_end);
}


//
// General

VOID Fini(INT32 code, VOID *v)
{
	printf("pin: %" PRIu64 " bytes written to BPRAM\n", nbytes);
	printf("pin: saw %" PRIu64 " writes in %" PRIu64 " BPFS operations\n",
	       checksum->fire_writes.ntotalevents, checksum->fire_ops.ntotalevents);
	printf("pin: checked %" PRIu64 " writes in %" PRIu64 " BPFS operations\n",
	       checksum->fire_writes.nfires, checksum->fire_ops.nfires);
}

static void init_ephemeral_bpram()
{
	void *bpram_void = bpfs_mirror.bpram; // convert &bpram to a void** without alias warn
	int r;
	assert(!bpfs_mirror.bpram);
	// some code assumes block memory address are block aligned
	r = posix_memalign(&bpram_void, BPFS_BLOCK_SIZE, bpram_nbytes);
	xassert(!r); // note: posix_memalign() returns positives on error
	bpfs_mirror.bpram = (char*) bpram_void;

	EXCEPTION_INFO ei;
	size_t n;
	n = PIN_SafeCopyEx(bpfs_mirror.bpram, bpram_start, bpram_nbytes, &ei);
	xassert(n == bpram_nbytes);
}

VOID InformPinBpramBefore(ADDRINT addr, ADDRINT size)
{
	printf("pin: detected %zu MiB (%zu bytes) of BPRAM\n",
	       size / (1024 * 1024), size);
	bpram_start = (void*) addr;
	bpram_end = (void*) (addr + size);
	bpram_nbytes = size;

	init_ephemeral_bpram();
}

VOID InformPinCommitStart()
{
	checksum->op_start();
}

VOID InformPinCommitStop(ADDRINT fn_addr)
{
	//char fn[64];
	//EXCEPTION_INFO ei;
	//size_t n;

	/*
	n = PIN_SafeCopyEx(fn, fn_addr, size, &ei);
	if (n != size)
	{
		static bool warned = false;
		if (!KnobQuiet.Value() || !warned)
		{
			fprintf(stderr, "pin: %s: %lu != %lu\n", __FUNCTION__, n, size);
			if (KnobQuiet.Value())
			   fprintf(stderr, "(not notifying of additional copy errors)\n");
			warned = true;
		}
	}
	*/

	// XXX: should PIN_SafeCopy fn_addr:
	checksum->op_stop((const char *) fn_addr);
}


VOID Image(IMG img, VOID *v)
{
	// Detect the address and size of BPRAM by inspecting a call to
	// BPRAM_INFO().
	// Alternatively, we could require debug symbols and lookup 'bpram' and
	// 'bpram_size' and either detect when their contents change, to get
	// their post-init values, or watch for a known function call made
	// after bpram is inited but before fuse starts (eg fuse_mount()).
	RTN rtn = RTN_FindByName(img, BPRAM_INFO);
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) InformPinBpramBefore,
		               IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		               IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		               IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, BPFS_COMMIT_START);
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) InformPinCommitStart,
		               IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, BPFS_COMMIT_END);
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) InformPinCommitStop,
		               IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		               IARG_END);
		RTN_Close(rtn);
	}
}

int main(int argc, char **argv)
{
	PIN_InitSymbols();
    PIN_Init(argc, argv);

	crawler_init();
	srand(time(NULL));
	checksum = new bpfs_checksum(KnobOpMax.Value(), KnobWriteMax.Value());

	IMG_AddInstrumentFunction(Image, 0);
	INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); // does not return
    return 0;
}
