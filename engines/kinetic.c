/**
 * Copyright 2020-2021 Seagate Technology LLC.
 *
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * https://mozilla.org/MP:/2.0/.
 *
 * This program is distributed in the hope that it will be useful,
 * but is provided AS-IS, WITHOUT ANY WARRANTY; including without
 * the implied warranty of MERCHANTABILITY, NON-INFRINGEMENT or
 * FITNESS FOR A PARTICULAR PURPOSE. See the Mozilla Public
 * License for more details.
 *
 */
#include <pthread.h>
#include <time.h>
#include <math.h>
#include "fio.h"
#include "verify.h"
#include "../optgroup.h"

#include <kinetic/kinetic.h>

/*
 * Kinetic IO Sync and Async Engines
 *
 * IO engines to perform Kinetic sync and async GET/PUT/DEL requests.
 *
 * This file defines two engines: 'kinetic' and 'kinetic-aio'.
 * These engines uses the various kinetic client libraries to do IO,
 * using KV GET/PUT/DEL in place of block IO R/W/T. It uses a network
 * connection to talk to a kinetic server.  The 'kinetic' engine is a
 * strictly synchronous engine and the 'kinetic-aio' is an asynchronous engine.
 *
 * Mapping a block io generator to KV has some caveats. Key values, unlike
 * LBAs, do not exist until they are "put" or written, therefore, you cannot
 * run read or trim tests until the key values are written.  So read or
 * trim tests require that a write test be run first to prep the key values.
 * Furthermore, since keys must be generated from block IO requests, two
 * test's parameters (bs, jobs, io pattern, etc) could generate a different
 * set of keys. So read test params should match the write test's params
 * that was used to create key values. In the case of random read tests, the
 * write prep must create all the possible keys needed. So a complete
 * sequential write test should be run to create the entire offset space.
 *
 * Key Generation
 * The KV IO this engine generates keys from the IO request in the form of:
 *		"F:JJJBBBBOOOOOOOOOOO[....]"
 * Where,
 *		F:	is literally "F:"
 *		JJJ	is a 3 char 0 padded ascii-hex representation of
 *			the job number, 4KiB jobs are supported,
 * 			can be forced to 0 by using kinetic_jobinkey=0
 *		BBBB	is a 4 char 0 padded ascii-hex representation of
 *			the block size in KiB, e.g 1MiB block size = 0400
 *			(64MiB - 1024) 1 KiB aligned block sizes supported
 * 			but are further restricted to value size limitations
 *			received from the kinetic server, usally 1MiB.
 *		OO..OO	is a 11 char 0 padded ascii-hex representation of
 *			the io offset. (16TiB - 1) file size is supported.
 *		[....]  Optional padding. The '.' character is appended as
 * 			needed to get the key length to equal kinetic_keylen.
 * 			The minimum key is currently 20 bytes with no pad.
 *
 * Usage Notes
 * Currently using processes for threading is not supported in both engines
 * due to limitations in the kinetic library, so thread=1 is required.
 *
 * The AIO engine can only support 1 job this is due to using a single
 * connection to the kinetic server -- there is no way to differentiate
 * events arising from different jobs on one connection. This means an
 * actual completion for a job 0 IO will cause a competion event for both
 * Job 0 and job 1, the latter will cause an error/segv.  A connection
 * per job could get around this issue. Until then the AIO engine requires
 * numjobs=1.
 * 
 * Because keys are block size dependent, block sizes must be uniform in a
 * given test. So R/W/T blocks are checked to be the same. Blocks sizes
 * also must be a multiple of 1KiB and no bigger than the maximum value size.
 *
 * Example invocation: ./fio --thread --numjobs=1 --ioengine=kinetic-aio --name=seq-writer --iodepth=32 --rw=write --bs=32k --size=64m --kinetic_host=localhost --verify=crc32c [--verify_only] --verify_fatal=1 --exitall_on_error --group_reporting
 *
 * Implementations Notes
 * engines/skeleton_external.c  has the only documentation for FIO ioengines.
 * It is weak.
 *
 * Common code
 * This implementation of two io engines leverages probably 75% of the code
 * across both engines. The options are used in both engines. For the most
 * part ->setup and ->cleanup are common.  The key generation and KV
 * setup code in ->queue are common. The KV stats is common.
 *
 * The engine design is probably not optimal, but given the lack of good docs
 * at least it works somewhat. Here are some notes/questions:
 *	o Code uses ->setup instead of ->init to validate parms, create
 *	  thread/engine specific structures and connect to server.
 *	o Matching threads, counted in ->setup and decremented in ->cleanup,
 * 	  probably demonstrates a lack of understanding about the model.
 *	o Could use ->prep instead of ->queue to create the KV and hang on io_u
 *	o Should probably have a common complete routine that can be  used
 * 	  by both engines.
 *	o Should move to a connection per job to enable jobs in async engine.
 *	o Should allow multiple connections per job to permit multipath tests.
 * 	  Server interfaces can be determined by retrieving the kinetic
 *	  servers configuration log.
 *
 * Sync Engine
 * This engine really only uses ->setup, ->cleanup and ->queue.  It uses the
 * standard sync calls in libkinetic ki_get, ki_put, and ki_del. Because
 * the entire IO lifecycle is contained in ->queue there is no need for
 * ->getevents, ->events, or per io_u engine data (->io_u_init or ->io_u_free)
 *
 * Async Engine
 * IOs are setup and started in ->queue using libkinetics aio calls:
 * ki_aio_get, ki_aio_put, and ki_aio_del. No contexts are used but the kv
 * and resulting kio are hung on the io_u engine data structure. This
 * structure is created in ->io_u_init and destroyed in ->io_u_free.
 * Events are determined in ->getevents by calls to ki_poll and require a
 * libkinetic in which ki_poll returns the number of ready KIOs (this is
 * libkinetic with a hash later than 5a2eff19b912afb1ce723d5ff80ca015ebd984a9).
 * KIOs are actually completed in ->event. By waiting to ->event to call
 * ki_aio_complete, any io engine management of events is avoided, simplifying
 * the code.  ->cancel is not supported.
 */

/*
 * To reduce resource pressure on the kinetic server these engines will use
 * a single connection. Each thread can send concurrently on that connection.
 */
static int 		ktd = -1;		/* Global kinetic descriptor */
static klimits_t	kt_limits;		/* Recvd kinetic limits */
static int		kt_jobs = 0;		/* Job counter */

/*
 * Since kinetic stats are per connection and one connection is being used
 * for an fio run, meaningful Kinetic stats can only be done on group_reporting
 * basis. So no matter if group_reporting is set or not the kinetic stats
 * will be displayed and reset per group.  To do this we need to keep a count
 * of the threads in a group. When the last thread leaves, we display and
 * reset the kinetic stats. To simplify this engine only supports a fixed
 * number of groups.
 */
#define KT_MAX_GID 1024
static uint32_t		kt_gid_threads[KT_MAX_GID];

#define KT_ENGINE "kinetic"
#define KT_ENGINE_AIO "kinetic-aio"
static int32_t kt_aio = -1; 		/* set in ->setup based on engine */

/* Serialize cleanup with this mutex */
static pthread_mutex_t	kt_lock = PTHREAD_MUTEX_INITIALIZER;

/* 
 * per Job data structure
 */
struct kinetic_data {
	char		*kd_prefix;	/* Key Prefix buffer */
	size_t		kd_prefixlen;	/* Key Prefix length */

	size_t		kd_offsetlen;	/* Key Offset length */

	char		*kd_pad;	/* Key padding buffer */
	size_t		kd_padlen;	/* Key padding length */

	kcachepolicy_t	kd_cpolicy;	/* Cache policy */
	kstats_t 	*kd_kst;	/* Kinetic stats */
};

/*
 * per IO data structure
 */
struct kinetic_io {
	struct io_u	*ki_io_u;	/* FIO IO management structure */
	kio_t		*ki_kio;	/* Kinetic IO structure */
	kv_t		*ki_kv;		/* KV used in the IO */
	int		ki_completed;	/* Completed flag */
};

/* Key Generation Limits that can impact FIO job definition */
#define KINETIC_FIO_PREFIX	"F:"		/*    2 bytes */
#define KINETIC_FIO_KEYJOBLEN	3		/*    3 bytes */
#define KINETIC_FIO_KEYBSLEN	4		/*    4 bytes */
#define KINETIC_FIO_KEYOFFLEN	11		/* + 11 bytes */
						/* ---------- */
#define KINETIC_FIO_MINKEY	20		/*   20 bytes */

#define KINETIC_FIO_MAXJOBS	0x1000		/* 4,096		 4KiB */
#define KINETIC_FIO_MAXBS	0x10000		/* 65,536KiB		64MiB */
#define KINETIC_FIO_MAXOFFSET	0x100000000000	/* 17,592,186,044,416	16TiB */
#define KiB 1024

//#define KINETIC_DBG_IO		1

struct kinetic_options {
	void		*pad;   /* Required for fio */
	char		*host;		/* Kinetic Server host or IP */
	char		*port;		/* Kinetic Server port */
	uint32_t	tls;
	uint64_t	id;
	char		*pass;
	size_t		keylen;
	uint32_t	jobinkey;
	char 		*cversion;
	char		*cpolicy;
	int 		verbose;
};

static struct fio_option options[] = {
	{
		.name     = "kinetic_host",
		.lname    = "kinetic_host",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic Drive hostname or IP",
		.off1     = offsetof(struct kinetic_options, host),
		.def	  = "localhost",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_port",
		.lname    = "kinetic_port",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic Drive port",
		.off1     = offsetof(struct kinetic_options, port),
		.def	  = "8123",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_tls",
		.lname    = "kinetic_tls",
		.type	  = FIO_OPT_BOOL,
		.off1     = offsetof(struct kinetic_options, tls),
		.def      = "0",
		.help     = "Enable/disable a secure connection",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_id",
		.lname    = "kinetic_id",
		.type     = FIO_OPT_ULL,
		.help     = "Kinetic User ID",
		.off1     = offsetof(struct kinetic_options, id),
		.def      = "1",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_pass",
		.lname    = "kinetic_pass",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic User ID Password",
		.off1     = offsetof(struct kinetic_options, pass),
		.def      = "asdfasdf",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name	  = "kinetic_keylen",
		.lname	  = "kinetic_keylen",
		.type	  = FIO_OPT_ULL,
		.off1	  = offsetof(struct kinetic_options, keylen),
		.def      = "20",
		.minval	  = 20,
		.help	  = "Set Kinetic key length, min 20",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name	  = "kinetic_jobinkey",
		.lname	  = "kinetic_jobinkey",
		.type	  = FIO_OPT_BOOL,
		.off1	  = offsetof(struct kinetic_options, jobinkey),
		.def      = "1",
		.help	  = "Enable/disable setting the job # in the key",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_cversion",
		.lname    = "kinetic_cluster_version",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic cluster version",
		.off1     = offsetof(struct kinetic_options, cversion),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_cpolicy",
		.lname    = "kinetic_cache_policy",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Set Kinetic cache policy [wt,wb,flush]",
		.off1     = offsetof(struct kinetic_options, cpolicy),
		.def	  = "wt",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_verbose",
		.lname    = "Kinetic_verbosity_level",
		.type     = FIO_OPT_INT,
		.help     = "Set Kinetic engine verbosity",
		.off1     = offsetof(struct kinetic_options, verbose),
		.def	  = "0",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = NULL,
	},
};


static int
fio_kinetic_io_create(struct thread_data *td, struct io_u *io_u)
{
	struct kinetic_io *ki;

	ki = calloc(1, sizeof(struct kinetic_io));
	if (!ki)
		return(-1);
	ki->ki_io_u = io_u;

	io_u->engine_data = ki;
	return(0);
}


static void
fio_kinetic_io_destroy(struct thread_data *td, struct io_u *io_u)
{
	struct kinetic_io *ki = io_u->engine_data;

	if (ki) {
		io_u->engine_data = NULL;
		free(ki);
	}
}


static enum fio_q_status
fio_kinetic_queue(struct thread_data *td, struct io_u *io_u)
{
	char 			*key_offset;
	struct kinetic_data	*kd = td->io_ops_data;
	struct kinetic_io	*ki = io_u->engine_data;
	kv_t			*kv = NULL;
	struct kiovec		*kv_key;
	struct kiovec		*kv_val;
	kstatus_t 		kstatus;
	kio_t 			*kio;
#ifdef KINETIC_DBG_IO
	static int 		wrq = 0;
#endif
	/*
	 * Because ->queue is used by both sync and aio engines,
	 * can't use the stack for kv_key, kv_val and key_offset,
	 * as they need to live beyond ->queue in the aio case.
	 * So allocate them here.
	 */
	kv_key = calloc(3, sizeof(struct kiovec));
	kv_val = calloc(1, sizeof(struct kiovec));
	key_offset = calloc(1, KINETIC_FIO_KEYOFFLEN + 1);
	if (!kv_val || !kv_key || !key_offset) {
		log_err("kv_key or kv_val alloc failed");
		io_u->error = ENOMEM;
		goto q_done;
	}

	/* Setup the offset portion of the key */
	sprintf(key_offset, "%0*llx", (int)kd->kd_offsetlen, io_u->offset);

	/* Setup the key kiovecs */
	kv_key[0].kiov_len  = kd->kd_prefixlen;
	kv_key[0].kiov_base = kd->kd_prefix;

	kv_key[1].kiov_len  = kd->kd_offsetlen;
	kv_key[1].kiov_base = key_offset;

	kv_key[2].kiov_len  = kd->kd_padlen;
	kv_key[2].kiov_base = kd->kd_pad;

	/* Create the kv then hang the key, all ddirs require this */
	kv = ki_create(ktd, KV_T);
	if (!kv) {
		log_err("kv create failed");
		io_u->error = ENOMEM;
		goto q_done;
	}

	kv->kv_key    = kv_key;
	kv->kv_keycnt = 3;
	kv->kv_val    = kv_val;
	kv->kv_valcnt = 1;

	io_u->error = 0;

	switch (io_u->ddir) {
	case DDIR_READ:
#ifdef KINETIC_DBG_IO
		printf("Get(\"%s%s%s\", %llx)\n",
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif
		if (kt_aio)
			kstatus = ki_aio_get(ktd, kv, NULL, &kio);
		else
			kstatus = ki_get(ktd, kv);

		if (kstatus != K_OK) {
			/* Common AIO and Sync error check */
			printf("Get Failed(\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);
			io_u->error = EIO;
			perror("ki_get");
			log_err("ki_get: failed: status code %d: %s\n",
				kstatus, ki_error(kstatus));

		} else if (kt_aio) {
			/* if K_OK, AIO needs to set engine_data and bail */
			ki->ki_kio = kio;
			ki->ki_kv = kv;
			ki->ki_completed = 0;

		} else if (io_u->xfer_buflen != kv->kv_val[0].kiov_len) {
			/* SYNC only partial value size mismatch */
			io_u->error = EIO;
			log_err("ki_get: failed: vallen != fio buffer len\n");

		} else {
			/*
			 * SYNC only
			 * No need to copy the value to the FIO structures
			 * unless this is a verify.
			 * Note this is a case where passing a buffer
			 * down into a get would be beneficial.
			 */
			if (td->o.do_verify) {
				memcpy(io_u->xfer_buf, kv->kv_val[0].kiov_base,
				       io_u->xfer_buflen);
			}

			free(kv->kv_val[0].kiov_base);
		}

#if 0
		This should be above in the else case
		hdr = (struct verify_header *)io_u->xfer_buf;
		log_err("kinetic:%08lx: job    : %x\n", id, td->subjob_number);
		log_err("kinetic:%08lx: kv_val : %p\n", id, kv.kv_val[0].kiov_base);
		log_err("kinetic:%08lx: hdr    : %p\n", id, hdr);
		log_err("kinetic:%08lx: Magic  : %04x\n", id, hdr->magic);
		log_err("kinetic:%08lx: Type   : %04x\n", id, hdr->verify_type);
		log_err("kinetic:%08lx: Offset : %016lx\n", id, hdr->offset);

		if (io_u->offset != hdr->offset) {
			log_err("kinetic FAIL:%08lx: HDROff %016lx: IOUOff: %016llx\n",
				id, hdr->offset, io_u->offset);
		}
#endif
		break;

	case DDIR_WRITE:
#ifdef KINETIC_DBG_IO
		printf("%d: Put(\"%s%s%s\", %llx)\n", wrq++,
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif
		kv_val[0].kiov_len  = io_u->xfer_buflen;
		kv_val[0].kiov_base = io_u->xfer_buf;
		kv->kv_cpolicy      = kd->kd_cpolicy;

		if (kt_aio)
			kstatus = ki_aio_put(ktd, NULL, kv, NULL, &kio);
		else
			kstatus = ki_put(ktd, NULL, kv);

		if (kstatus != K_OK) {
			printf("Put failed (\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);
			io_u->error = EIO;
			perror("ki_put");
			log_err("ki_put: failed: status code %d: %s\n",
				kstatus, ki_error(kstatus));
		} else if (kt_aio) {
			/* if K_OK, AIO needs to set engine_data and bail */
			ki->ki_kio = kio;
			ki->ki_kv = kv;
			ki->ki_completed = 0;
		}

		break;

	case DDIR_TRIM:
#ifdef KINETIC_DBG_IO
		printf("Del(\"%s%s%s\", %llx)\n",
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif
		kv_val[0].kiov_len = io_u->xfer_buflen;
		kv_val[0].kiov_base = io_u->xfer_buf;
		kv->kv_cpolicy = kd->kd_cpolicy;
		
		if (kt_aio)
			kstatus = ki_aio_del(ktd, NULL, kv, NULL, &kio);
		else
			kstatus = ki_del(ktd, NULL, kv);

		if (kstatus != K_OK) {
			printf("Del failed (\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);

			io_u->error = EIO;
			log_err("ki_del: failed: status code %d %s\n",
				kstatus, ki_error(kstatus));
		}  else if (kt_aio) {
			/* if K_OK, AIO needs to set engine_data and bail */
			ki->ki_kio = kio;
			ki->ki_kv = kv;
			ki->ki_completed = 0;
		}

		break;

	default:
		//ret = do_io_u_sync(td, io_u);
		printf("Queue: Why am I Here? \n");
	}

 q_done:
	if (kt_aio && !io_u->error) {
		return FIO_Q_QUEUED;
	}

	/* sync or error case, either way the kv is no longer needed */
	if (key_offset) free(key_offset);
	if (kv_key) free(kv_key);
	if (kv_val) free(kv_val);
	if (kv) ki_destroy(kv);
	
	return FIO_Q_COMPLETED;
}


static struct io_u *
fio_kinetic_event(struct thread_data *td, int event)
{
	struct io_u 		*io_u;
	struct kinetic_io	*ki = NULL;
	kstatus_t		kstatus;
	kv_t			*kv;
	int			i, found;
#ifdef KINETIC_DBG_IO
	static int		wrc = 0;
#endif
	if (!kt_aio) {
		/* sync IO engine - never any outstanding events */
		printf("Event %d\n", event);
		return NULL;
	}

	/*
	 * Poll in ->getevents found a ready KIO. could be good or failed
	 * either way call complete. In the case of error, the complete will
	 * try to retrieve the failed KIO. Never look at passed in event as
	 * the search for the io_u occurs here.
	 */
	found = 0;
	io_u_qiter(&td->io_u_all, io_u, i) {
		ki = io_u->engine_data;
		if (!ki) {
			printf("ERROR: No engine data before aio complete\n");
			continue;
		}

		if (!(io_u->flags & IO_U_F_FLIGHT))
			continue;

		if (ki->ki_completed)
			continue;

		kstatus = ki_aio_complete(ktd, ki->ki_kio, NULL);
		if (kstatus == K_EAGAIN) continue;

		/* got one */
		found=1;
		break;
	}

	if (!found) {
		printf("ERROR: No event\n");
		return NULL;
	}

	/* Just checking.... should never get here */
	if (!ki) {
		printf("ERROR: No engine data\n");
		return NULL;
	}

	/* Mark as completed */
	ki->ki_completed = 1;

	/* Grab a shorthand kv var */
	kv =  ki->ki_kv;

	/*
	 *Process the completion, really on READ has something
	 * meaningful todo
	 */
	switch (io_u->ddir) {
	case DDIR_READ:
#ifdef KINETIC_DBG_IO
		printf("Get Complete(\"%s%s%s\", %llx)\n",
		       (char *)kv->kv_key[0].kiov_base,
		       (char *)kv->kv_key[1].kiov_base,
		       (char *)kv->kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif

		if (kstatus != K_OK) {
			printf("Get Failed(\"%s%s%s\")\n",
			       (char *)kv->kv_key[0].kiov_base,
			       (char *)kv->kv_key[1].kiov_base,
			       (char *)kv->kv_key[2].kiov_base);
			io_u->error = EIO;
			perror("ki_get");
			log_err("ki_get: failed: status code %d: %s\n",
				kstatus, ki_error(kstatus));

		} else if (io_u->xfer_buflen != kv->kv_val[0].kiov_len) {
			/* SYNC only partial value size mismatch */
			io_u->error = EIO;
			log_err("ki_get: failed: vallen != fio buffer len\n");

		} else {
			/*
			 * No need to copy the value to the FIO structures
			 * unless this is a verify.
			 * Note this is a case where passing a buffer
			 * down into a get would be beneficial.
			 */
			if (td->o.do_verify) {
				memcpy(io_u->xfer_buf, kv->kv_val[0].kiov_base,
				       io_u->xfer_buflen);
			}

			free(kv->kv_val[0].kiov_base);
		}

#if 0
		This verify debugging code should be above in the else case
		hdr = (struct verify_header *)io_u->xfer_buf;
		log_err("kinetic:%08lx: job    : %x\n", id, td->subjob_number);
		log_err("kinetic:%08lx: kv_val : %p\n", id, kv.kv_val[0].kiov_base);
		log_err("kinetic:%08lx: hdr    : %p\n", id, hdr);
		log_err("kinetic:%08lx: Magic  : %04x\n", id, hdr->magic);
		log_err("kinetic:%08lx: Type   : %04x\n", id, hdr->verify_type);
		log_err("kinetic:%08lx: Offset : %016lx\n", id, hdr->offset);

		if (io_u->offset != hdr->offset) {
			log_err("kinetic FAIL:%08lx: HDROff %016lx: IOUOff: %016llx\n",
				id, hdr->offset, io_u->offset);
		}
#endif
		break;

	case DDIR_WRITE:
#ifdef KINETIC_DBG_IO
		printf("%d: Complete(\"%s%s%s\", %llx)\n", wrc++,
		       (char *)kv->kv_key[0].kiov_base,
		       (char *)kv->kv_key[1].kiov_base,
		       (char *)kv->kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif

		if (kstatus != K_OK) {
			printf("Put failed (\"%s%s%s\")\n",
			       (char *)kv->kv_key[0].kiov_base,
			       (char *)kv->kv_key[1].kiov_base,
			       (char *)kv->kv_key[2].kiov_base);
			io_u->error = EIO;
			perror("ki_put");
			log_err("ki_put: failed: status code %d: %s\n",
				kstatus, ki_error(kstatus));
		}

		break;

	case DDIR_TRIM:
#ifdef KINETIC_DBG_IO
		printf("Del Complete(\"%s%s%s\", %llx)\n",
		       (char *)kv->kv_key[0].kiov_base,
		       (char *)kv->kv_key[1].kiov_base,
		       (char *)kv->kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif

		if (kstatus != K_OK) {
			printf("Del failed (\"%s%s%s\")\n",
			       (char *)kv->kv_key[0].kiov_base,
			       (char *)kv->kv_key[1].kiov_base,
			       (char *)kv->kv_key[2].kiov_base);

			io_u->error = EIO;
			log_err("ki_del: failed: status code %d %s\n",
				kstatus, ki_error(kstatus));
		}

		break;

	default:
		//ret = do_io_u_sync(td, io_u);
		printf("Event: Why am I Here? \n");
	}

	/*
	 * Done with kv, so clean it up.  The KIO is managed by libkinetic
	 * and is no longer valid, after ki_aio_complete.
	 *
	 * kv->kv_key[1].kiov_base is key_offset in ->queue
	 */
	if (kv->kv_key[1].kiov_base) free(kv->kv_key[1].kiov_base);
	if (kv->kv_key) free(kv->kv_key);
	if (kv->kv_val) free(kv->kv_val);
	ki_destroy(kv);
	ki->ki_kv = NULL;
	ki->ki_kio = NULL;

	return(io_u);
}


static int
fio_kinetic_getevents(struct thread_data *td, unsigned int min,
	unsigned int max, const struct timespec *t)
{
	int ci;

	if (!kt_aio) {
		/* sync IO engine - never any outstanding events */
		return 0;
	}

#ifdef KINETIC_DBG_IO
	printf("GE: min=%u max=%u: ", min, max);
#endif

	/*
	 * Want to do the completions in ->event, but to satisfy >=min
	 * ki_poll should really return the number of ready kios. Until
	 * then, iodepth_batch_complete_min will be treated as 1.
	 * This routine will only find 1 event per call.
	 */
	do {
		if ((ci = ki_poll(ktd, 100)) < 0)  {
			/* Poll timed out, poll again */
			if (errno == ETIMEDOUT)
				continue;
			if (errno == ECONNABORTED)
				perror("fio_kinetic_getevents");
		}

		if (ci < min) {
			/* this will be a tight loop waiting for the events */
			continue;
		}

		/* got at least min events */
		break;
	} while (1);

	/* Don't return too much */
	ci = ((ci > max) ? max : ci);

#ifdef KINETIC_DBG_IO
	printf("ret=%d\n", ci);
#endif

	return (ci);
}


static void
fio_kinetic_prstats(struct thread_data *td,
		    kopstat_t *kop, const char *statname)
{
	uint32_t tops;  /* Total Ops */
	double	st;

	tops = kop->kop_ok + kop->kop_err + kop->kop_dropped;

	/* If nothing to print bail */
	if (!tops)
		return;

	printf("KS [%s]: ", statname); /* grep-able prefix */
	printf("%d, %7u, %3.4g%%, %7u, %3.4g%%, %7u, %3.4g%%, %7u , ",
	       /* BS */
	       (int)kop->kop_vlen,
	       /* OK */
	       kop->kop_ok,
	       /* OK % */
	       ((kop->kop_ok == 0)? (double)0.0 : (double)
		kop->kop_ok / tops * 100.0),
	       /* Err */
	       kop->kop_err,
	       /* Err % */
	       ((kop->kop_ok == 0)? (double)0.0 : (double)
		kop->kop_err / tops * 100.0),
	       /* Dropped */
	       kop->kop_dropped,
	       /* Dropped % */
	       ((kop->kop_ok == 0)? (double)0.0 : (double)
		kop->kop_dropped / tops * 100.0),
	       /* Total */
	       tops);

	/* Throughput MiB/s - no data here, preserve a column */
	printf(" , ");

	/* Send Size, % BS, Receive Size, % BE */
	printf("%10.010g, %10.010g%%, %10.010g, %10.010g%%, ",
	       kop->kop_ssize, kop->kop_ssize/td->o.bs[DDIR_WRITE]*100,
	       kop->kop_rsize, kop->kop_rsize/td->o.bs[DDIR_WRITE]*100);

	/* Key Length, Value Size */
	printf("%10.010g, %10.010g, ",
	       kop->kop_klen, kop->kop_vlen);

	/* Total RPC Time, stddev */
	printf("%10.010g, %g, ",
	       kop->kop_tot[KOP_TMEAN],
	       kop->kop_tot[KOP_TSTDDEV]);

	/* Send Time, stddev, % of RPC */
	printf("%10.010g, %g, %10.10g%%, ",
	       kop->kop_req[KOP_TMEAN],
	       kop->kop_req[KOP_TSTDDEV],
	       kop->kop_req[KOP_TMEAN] / kop->kop_tot[KOP_TMEAN] * 100);

	/* Recv Time, stddev, % of RPC */
	printf("%10.010g, %g, %10.10g%%, ",
	       kop->kop_resp[KOP_TMEAN],
	       kop->kop_resp[KOP_TSTDDEV],
	       kop->kop_resp[KOP_TMEAN]/kop->kop_tot[KOP_TMEAN] * 100);

	/* Server Time, % of RPC */
	st = kop->kop_tot[KOP_TMEAN] -
		(kop->kop_req[KOP_TMEAN] + kop->kop_resp[KOP_TMEAN]);
	printf("%10.010g, %10.10g%%\n",
	       st, st / kop->kop_tot[KOP_TMEAN] * 100);

#if 0
	printf("\tSuccessful: %7u (%3.4g%%)\n", kop->kop_ok,
	       ((kop->kop_ok == 0)? (double)0.0 : (double)
		kop->kop_ok /
		(kop->kop_ok + kop->kop_err + kop->kop_dropped)*100.0));
	printf("\t    Failed: %7u (%3.4g%%)\n", kop->kop_err,
	       ((kop->kop_ok == 0)? (double)0.0 : (double)
		kop->kop_err /
		(kop->kop_ok + kop->kop_err + kop->kop_dropped)*100.0));
	printf("\t   Dropped: %7u (%3.4g%%)\n", kop->kop_dropped,
	       ((kop->kop_ok == 0)? (double)0.0 : (double)
		kop->kop_dropped /
		(kop->kop_ok + kop->kop_err + kop->kop_dropped)*100.0));
	printf("\n");

	printf("\tSend size, mean: %10.010g B\n", kop->kop_ssize);
	printf("\tRecv size, mean: %10.010g B\n", kop->kop_rsize);
	printf("\tKey len,   mean: %10.010g B\n", kop->kop_klen);
	printf("\tValue len, mean: %10.010g B\n", kop->kop_vlen);
	printf("\n");
	if (KIOP_ISSET(&kd->kd_kst->kst_puts, KOPF_TSTAT)) {
		printf("\tRPC time,  mean: %10.010g \xC2\xB5S (stddev=%g)\n",
		       kop->kop_tot[KOP_TMEAN],
		       kop->kop_tot[KOP_TSTDDEV]);
		printf("\tReq time,  mean: %10.010g \xC2\xB5S (stddev=%g)\n",
		       kop->kop_req[KOP_TMEAN],
		       kop->kop_req[KOP_TSTDDEV]);
		printf("\tResp time, mean: %10.010g \xC2\xB5S (stddev=%g)\n",
		       kop->kop_resp[KOP_TMEAN],
		       kop->kop_resp[KOP_TSTDDEV]);
	}
#endif
	return;
}


static void
fio_kinetic_cleanup(struct thread_data *td)
{
	struct kinetic_data	*kd  = td->io_ops_data;
	static int 		prhdr = 1;

	if (!kd)
		return;

	pthread_mutex_lock(&kt_lock);

	/* Decrement the totals jobs */
	kt_jobs--;

	/* dec the thread count for the gid */
	kt_gid_threads[td->groupid]--;

	if (!kt_gid_threads[td->groupid]) {
		/* Last thread in a group */
		if (ki_getstats(ktd, kd->kd_kst) != K_OK) {
			printf("Statistics failed\n");
		}

		if (prhdr) {
			printf("N nQSize, Mean QSize, StdDev QSize, \n");
		}
		printf("%lu, %g, %g\n",	
			kd->kd_kst->kst_qsn, 
			kd->kd_kst->kst_qsm, 
			sqrt(kd->kd_kst->kst_qsms/(kd->kd_kst->kst_qsn -1)));

		if (prhdr) {
			printf("Job, BS, OK, %%, ");
			printf("Failed, %%, Dropped, %%, Total,");
			printf("Throughput(MiB/s), ");
			printf("Mean Send Size(B), %% BS, ");
			printf("Mean Recv Size B), %% BS, ");
			printf("Mean Key Length(B), Mean Value Length(B), ");
			printf("Mean RPC Time \xC2\xB5S, stddev, ");
			printf("Mean Send Time \xC2\xB5S, stddev, %% of RPC, ");
			printf("Mean Recv Time \xC2\xB5S, stddev, %% of RPC, ");
			printf("Mean Server Time \xC2\xB5S, %% of RPC, \n");
			prhdr = 0;
		}

		fio_kinetic_prstats(td, &kd->kd_kst->kst_puts, "put");
		fio_kinetic_prstats(td, &kd->kd_kst->kst_gets, "get");
		fio_kinetic_prstats(td, &kd->kd_kst->kst_dels, "del");

		/* Clear the stats for the next group */
		memset(kd->kd_kst, 0, sizeof(*kd->kd_kst));

		KIOP_SET((&kd->kd_kst->kst_puts), KOPF_TSTAT);
		KIOP_SET((&kd->kd_kst->kst_gets), KOPF_TSTAT);
		KIOP_SET((&kd->kd_kst->kst_dels), KOPF_TSTAT);

		if (ki_putstats(ktd, kd->kd_kst) != K_OK) {
			printf("Failed to enable Time Statistics\n");
		}
	}

	/* Last job, kill the connection */
	if ((kt_jobs == 0) && (ktd != -1)) {
		ki_close(ktd);
	}

	/* Free up the per job kinetic structures */
	if (kd) {
		/*
		 * kst is per job but is only used by last group member
		 * to cleanup. No matter what we need to destroy
		 * it on every job completion.
		 */
		ki_destroy(kd->kd_kst);

		if (kd->kd_prefix)	free(kd->kd_prefix);
		if (kd->kd_pad)		free(kd->kd_pad);
		free(kd);
	}
	pthread_mutex_unlock(&kt_lock);
}


static int
fio_kinetic_setup(struct thread_data *td)
{
	int len, i, show_params=0;
	struct kinetic_data *kd = NULL;
	struct kinetic_options *o = td->eo;
	kstats_t *kst = NULL;

	if (!td)
		return(-1);

	if (td->groupid > KT_MAX_GID) {
		log_err("too many groups (<%d)\n", KT_MAX_GID);
		return(-1);
	}

	/* Are we an AIO engine? initial -1 value means we only check once */
	if (kt_aio < 0) {
		kt_aio = (strcmp(KT_ENGINE_AIO, td->o.ioengine) == 0);
	}

	/* Bump the number of jobs */
	kt_jobs++;

	/* bump the thread count for the gid */
	kt_gid_threads[td->groupid]++;

	if (o->verbose)
		printf("Job [%u, %u, %u]: Setup\n",
		       td->thread_number,
		       td->subjob_number,
		       td->groupid);

	td->io_ops_data = NULL;

	if (!td->o.use_thread) {
		/* have a fork issue with the library, force threads for now */
		log_err("--thread not set.\n");
		goto cleanup;
	}

	/* Open the global kinetic connection if not open already */
	if (ktd < 0) {
		printf("Opening Kinetic %u\n", td->subjob_number); 
		ktd = ki_open(o->host, o->port, o->tls, o->id, o->pass);
		if (ktd < 0) {
			log_err("Kinetic connection failed");
			goto cleanup;
		}

		/* Check limits against params */
		kt_limits = ki_limits(ktd);

		show_params=1; /* Only show the params once */
	}

	/* Make sure keylen > MINKEY and < the max key length */
	if (o->keylen < KINETIC_FIO_MINKEY) {
		log_err("kinetic_keylen too small (<%d)\n", KINETIC_FIO_MINKEY);
		goto cleanup;
	}

	if (o->keylen > kt_limits.kl_keylen) {
		log_err("kinetic_keylen too big (>%d)\n", kt_limits.kl_keylen);
		goto cleanup;
	}

	/* All KV value sizes need to be uniform  */
	if (td->o.bs[DDIR_READ] != td->o.bs[DDIR_WRITE] ||
	    td->o.bs[DDIR_READ] != td->o.bs[DDIR_TRIM]    ) {
		log_err("RWT block sizes must be the same\n");
		goto cleanup;
	}

	/* Make sure block size is less than max value length */
	if ((td->o.bs[DDIR_READ] > kt_limits.kl_vallen) ||
	    (td->o.bs[DDIR_READ] >= KINETIC_FIO_MAXBS*KiB )) {
		log_err("blocksize too big (>=%d)\n",
			kt_limits.kl_vallen);
		goto cleanup;
	}

	/* Make sure bs is aligned, see the key generation notes for why */
	if (td->o.bs[DDIR_READ] % KiB) {
		log_err("blocksize must be a multiple of 1024\n");
		goto cleanup;
	}

	/* Check the number of jobs */
	if (kt_aio) {
		/* async engine */
		if (td->o.numjobs != 1) {
			log_err("numjobs too big (>%d) for aio", 1);
			goto cleanup;
		}
	} else {
		/* sync engine */
		if (td->o.numjobs > KINETIC_FIO_MAXJOBS) {
			log_err("numjobs too big (>%d)", KINETIC_FIO_MAXJOBS);
			goto cleanup;
		}
	}

	/* check size and filesize < KINETIC_FIO_MAXOFFSET */
	if ((td->o.size >= KINETIC_FIO_MAXOFFSET) ||
	    (td->o.file_size_high >= KINETIC_FIO_MAXOFFSET)) {
		log_err("size too big (>=%ld)\n", KINETIC_FIO_MAXOFFSET);
		goto cleanup;
	}

	/* allocate engine specific structure and key prefix */
	kd = calloc(1, sizeof(struct kinetic_data));
	if (!kd) {
		log_err("calloc failed.\n");
		goto cleanup;
	}
	memset(kd, 0, sizeof(struct kinetic_data));

	/* Check and set the cache policy */
	kd->kd_cpolicy = (kcachepolicy_t)KC_INVALID;
	if (strcmp(o->cpolicy, "wt")    == 0) kd->kd_cpolicy = KC_WT;
	if (strcmp(o->cpolicy, "wb")    == 0) kd->kd_cpolicy = KC_WB;
	if (strcmp(o->cpolicy, "flush") == 0) kd->kd_cpolicy = KC_FLUSH;

	if (kd->kd_cpolicy == (kcachepolicy_t)KC_INVALID) {
		log_err("Invalid cpolicy");
		goto cleanup;
	}

	/* Create the per job key prefix */
	len = strlen(KINETIC_FIO_PREFIX) +
		KINETIC_FIO_KEYJOBLEN +
		KINETIC_FIO_KEYBSLEN + 1;
	kd->kd_prefix = (char *)malloc(len);
	if (!kd->kd_prefix) {
		log_err("prefix malloc failed.\n");
		goto cleanup;

	}

	/*
	 * write the key prefix which is static across the test run
	 * use the read bs cause we have alreay guaranteed the bs is uniform
	 * blocksize stored in prefix is in KiB.  May contain the job number
	 * but may not dpending on jobinkey boolean.
	 */
	kd->kd_prefixlen = sprintf(kd->kd_prefix, "%s%0*x%0*llx",
				   KINETIC_FIO_PREFIX,
				   KINETIC_FIO_KEYJOBLEN,
				   ((o->jobinkey)?td->thread_number:0),
				   KINETIC_FIO_KEYBSLEN,
				   td->o.bs[DDIR_READ]/KiB);

	if (kd->kd_prefixlen != (len - 1)) {
		log_err("key prefix len wrong size");
		goto cleanup;
	}
	
	/* Set the offset length */
	kd->kd_offsetlen = KINETIC_FIO_KEYOFFLEN;

	/*
	 * Create per job pad suffix for the key.  The pad is the extra
	 * space after the key prefix and offset up to keylen.  Keylen
	 * usually equals the prefix and offset and thus pad is 0 length,
	 * but for the case where keylen is larger we need to create the
	 * pad portion of they key.
	 */
	kd->kd_padlen = o->keylen - (kd->kd_prefixlen + kd->kd_offsetlen);

	if (kd->kd_padlen < 0) {
		/* Should never happen */
		log_err("key pad generation overflow");
		goto cleanup;
	}

	kd->kd_pad = (char *)malloc(kd->kd_padlen + 1);
	if (!kd->kd_pad) {
		log_err("key pad malloc failed");
		goto cleanup;
	}

	/* Fill it in and terminate it */
	for(i=0; i<kd->kd_padlen; i++)
		kd->kd_pad[i] = '.';

	kd->kd_pad[kd->kd_padlen] = '\0';

	/* Setup Stats */
	if (!(kst = ki_create(ktd, KSTATS_T))) {
		fprintf(stderr, "*** Memory Failure\n");
		return (-1);
	}

	KIOP_SET((&kst->kst_puts), KOPF_TSTAT);
	KIOP_SET((&kst->kst_gets), KOPF_TSTAT);
	KIOP_SET((&kst->kst_dels), KOPF_TSTAT);

	if (ki_putstats(ktd, kst) != K_OK) {
		printf("Failed to enable Time Statistics\n");
	}

	kd->kd_kst = kst;
#if 0
	printf("PrefixLen: %lu\n", kd->kd_prefixlen);
	printf("OffsetLen: %lu\n", kd->kd_offsetlen);
	printf("PadLen:    %lu\n", kd->kd_padlen);
#endif

	/* hang the kinetic structure */
	td->io_ops_data = kd;

	if (show_params) {
		kversion_t *kver;

		kver = ki_create(-1, KVERSION_T);
		ki_version(kver);

		printf("Kinetic: LibVers=%s; Host=%s; Port=%s; ",
		       kver->kvn_ki_vers, o->host, o->port);
		printf("KeyLen=%lu; ", o->keylen);
		if (strcmp(o->cpolicy, "wt")    == 0)
			printf("CachePolicy=WT; ");
		if (strcmp(o->cpolicy, "wb")    == 0)
			printf("CachePolicy=WB; ");
		if (strcmp(o->cpolicy, "flush") == 0)
			printf("CachePolicy=Flush; ");
		printf("LibGitHash=%s; ", kver->kvn_ki_githash);
		printf("\n");
		ki_destroy(kver);

	}

	return 0;

 cleanup:
	fio_kinetic_cleanup(td);
	return 1;
}


static int
fio_kinetic_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}


static int
fio_kinetic_close(struct thread_data *td, struct fio_file *f)
{
	return 0;
}


static int
fio_kinetic_invalidate(struct thread_data *td, struct fio_file *f)
{
	return 0;
}


FIO_STATIC struct ioengine_ops ioengine = {
	.name			= KT_ENGINE,
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_DISKLESSIO | FIO_SYNCIO,
	.queue			= fio_kinetic_queue,
	.getevents		= fio_kinetic_getevents,
	.event			= fio_kinetic_event,
	.setup			= fio_kinetic_setup,
	.cleanup		= fio_kinetic_cleanup,
	.open_file		= fio_kinetic_open,
	.close_file		= fio_kinetic_close,
	.invalidate		= fio_kinetic_invalidate,
	.options		= options,
	.option_struct_size	= sizeof(struct kinetic_options),
};


static void fio_init fio_kinetic_register(void)
{
	memset(kt_gid_threads, 0, sizeof(*kt_gid_threads));
	register_ioengine(&ioengine);
}


static void fio_exit fio_kinetic_unregister(void)
{
	unregister_ioengine(&ioengine);
}


FIO_STATIC struct ioengine_ops aio_ioengine = {
	.name			= KT_ENGINE_AIO,
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_DISKLESSIO,
	.queue			= fio_kinetic_queue,
	.getevents		= fio_kinetic_getevents,
	.event			= fio_kinetic_event,
	.setup			= fio_kinetic_setup,
	.cleanup		= fio_kinetic_cleanup,
	.open_file		= fio_kinetic_open,
	.close_file		= fio_kinetic_close,
	.invalidate		= fio_kinetic_invalidate,
	.io_u_init		= fio_kinetic_io_create,
	.io_u_free		= fio_kinetic_io_destroy,
	.options		= options,
	.option_struct_size	= sizeof(struct kinetic_options),
};


static void fio_init fio_kinetic_aio_register(void)
{
	memset(kt_gid_threads, 0, sizeof(*kt_gid_threads));
	register_ioengine(&aio_ioengine);
}


static void fio_exit fio_kinetic_aio_unregister(void)
{
	unregister_ioengine(&aio_ioengine);
}
