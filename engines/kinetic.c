/*
 * Kinetic IO Engine
 *
 * IO engine to perform Kinetic GET/PUT/DEL requests.
 */
#include <pthread.h>
#include <time.h>
#include "fio.h"
#include "verify.h"
#include "../optgroup.h"

#include <kinetic/kinetic.h>

/*
 * Kinetic KV IO Engine.  This engine uses the various kinetic client libraries
 * to do IO, in the form of GET/PUT/DEL in place of R/W/T. It uses a network
 * connection to talk to a kinetic server. 
 *
 * The KV IO this engine generates keys from the IO request in the form of:
 *		"F:JJJBBBBOOOOOOOOOOO[....]"
 * Where,
 *		JJJ	is a 3 char 0 padded ascii-hex representation of
 *			the job number, 4KiB jobs supported, can be forced to 0
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
 * Example invocation: ./fio --thread --ioengine=kinetic --name=seq-writer --iodepth=1 --rw=write --bs=32k --size=64m --numjobs=16 --kinetic_host=localhost --verify=crc32c [--verify_only] --verify_fatal=1 --exitall_on_error --group_reporting
*/

/* 
 * Start out with a single connection for this Sync engine. Each thread can
 * send concurrently on that connection. Eventually when async support is 
 * added a connection per thread/job can be added. 
 * Might want a boolean param kinetic_gcon (global connection) to control.
 */
static int 		ktd = -1;		/* Global kinetic descriptor */
static klimits_t	kt_limits;		/* Recvd kinetic limits */
static int		kt_jobs = 0;		/* Job counter */
static int		kt_statprnted = 0;	/* Only print stats once */

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

struct kinetic_options {
	void		*pad;   /* Required for fio */
	char		*host;
	char		*port;
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

#if 0
static int
fio_syncio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	if (!ddir_rw(io_u->ddir))
		return 0;

	if (LAST_POS(f) != -1ULL && LAST_POS(f) == io_u->offset)
		return 0;

	if (lseek(f->fd, io_u->offset, SEEK_SET) == -1) {
		td_verror(td, errno, "lseek");
		return 1;
	}

	return 0;
}

static int
fio_io_end(struct thread_data *td, struct io_u *io_u, int ret)
{
	if (io_u->file && ret >= 0 && ddir_rw(io_u->ddir))
		LAST_POS(io_u->file) = io_u->offset + ret;

	if (ret != (int) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error) {
		io_u_log_error(td, io_u);
		td_verror(td, io_u->error, "xfer");
	}

	return FIO_Q_COMPLETED;
}
#endif

static enum fio_q_status
fio_kinetic_queue(struct thread_data *td, struct io_u *io_u)
{
	char key_offset[KINETIC_FIO_KEYOFFLEN + 1];
 
	//struct kinetic_options	*o  = td->eo;
	struct kinetic_data	*kd = td->io_ops_data;
	kv_t		*kv = NULL;
	struct kiovec	kv_key[3];
	struct kiovec	kv_val[1]  = {{0, 0}};
	kstatus_t 	kstatus;
	
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

	switch (io_u->ddir) {
	case DDIR_READ:
#if 0
		printf("Get(\"%s%s%s\", %llx)\n",
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif
		
		kstatus = ki_get(ktd, kv);
		if (kstatus != K_OK) {
			printf("Get Failed(\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);
			io_u->error = EIO;
			perror("ki_get");
			log_err("ki_get: failed: status code %d: %s\n",
				kstatus, ki_error(kstatus));
		} else if (io_u->xfer_buflen != kv->kv_val[0].kiov_len) {
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
#if 0
		printf("Put(\"%s%s%s\", %llx)\n",
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif
		kv_val[0].kiov_len  = io_u->xfer_buflen;
		kv_val[0].kiov_base = io_u->xfer_buf;
		kv->kv_cpolicy      = kd->kd_cpolicy;

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
		}

		break;

	case DDIR_TRIM:
#if 0
		printf("Del(\"%s%s%s\", %llx)\n",
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif
		kv_val[0].kiov_len = io_u->xfer_buflen;
		kv_val[0].kiov_base = io_u->xfer_buf;
		kv->kv_cpolicy = kd->kd_cpolicy;
		
		kstatus = ki_del(ktd, NULL, kv);
		if (kstatus != K_OK) {
			printf("Del failed (\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);

			io_u->error = EIO;
			log_err("ki_del: failed: status code %d %s\n",
				kstatus, ki_error(kstatus));
		}

		break;

	default:
		//ret = do_io_u_sync(td, io_u);
		printf("Why am I Here? \n");
	}

 q_done:
	if (kv) ki_destroy(kv);
	return FIO_Q_COMPLETED;
	
}

static struct io_u *
fio_kinetic_event(struct thread_data *td, int event)
{
	/* sync IO engine - never any outstanding events */
	printf("Events %d\n", event);
	return NULL;
}

static int
fio_kinetic_getevents(struct thread_data *td, unsigned int min,
	unsigned int max, const struct timespec *t)
{
	/* sync IO engine - never any outstanding events */
	return 0;
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
	printf("%llu, %7u, %3.4g%%, %7u, %3.4g%%, %7u, %3.4g%%, %7u , ",
	       /* BS */
	       td->o.bs[DDIR_WRITE],
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

	if (!kd)
		return;

	pthread_mutex_lock(&kt_lock);
	if (!kt_statprnted) {
		if (ki_getstats(ktd, kd->kd_kst) != K_OK) {
			printf("Statistics failed\n");
		}

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

		fio_kinetic_prstats(td, &kd->kd_kst->kst_puts, "put");
		fio_kinetic_prstats(td, &kd->kd_kst->kst_gets, "get");
		fio_kinetic_prstats(td, &kd->kd_kst->kst_dels, "del");

		/* Clear the stats */
		memset(kd->kd_kst, 0, sizeof(*kd->kd_kst));
		KIOP_SET((&kd->kd_kst->kst_puts), KOPF_TSTAT);
		if (ki_putstats(ktd, kd->kd_kst) != K_OK) {
			printf("Failed to enable Time Statistics\n");
		}

		ki_destroy(kd->kd_kst);
		kt_statprnted=1;
	}

	if (kt_jobs == 1) {
		ki_close(ktd);
	}

	kt_jobs--;

	if (kd) {
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

	kt_jobs++;

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

	if (td->o.bs[DDIR_READ] % KiB) {
		log_err("blocksize must be a multiple of 1024\n");
		goto cleanup;
	}

	/* Make sure the number of jobs is less than max jobs */
	if (td->o.numjobs > KINETIC_FIO_MAXJOBS) {
		log_err("numjobs too big (>%d)", KINETIC_FIO_MAXJOBS);
		goto cleanup;
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
				   ((o->jobinkey)?td->subjob_number:0),
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
	.name			= "kinetic",
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

static void fio_init fio_http_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_http_unregister(void)
{
	unregister_ioengine(&ioengine);
}
