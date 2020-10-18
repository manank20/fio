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
 * Todo the KV IO this engine generates keys from the IO request in the form of:
 *		"F:JJJJOOOOOOOOOOOO"
 * Where,
 *		minkey	is 16 characters
 *		JJJJ	is a 4 char 0 padded ascii-hex representation of 
 *			the job number, 64k jobs supported
 *		OO..OO	is a 12+ char 0 padded ascii-hex representation of 
 *			the io offset.	it is padded to make the 
 *			strlen(key) = kinetic_keylen. 281TB offset supported.
 */

/* 
 * Start out with a single connection for this Sync engine. Each thread can
 * send concurrently on that connection. Eventually when async support is 
 * added a connection per thread/job can be added. 
 * Might want a boolean param kinetic_gcon (global connection) to control.
 */
static int 		ktd = -1;
static klimits_t	kt_limits;
static kcachepolicy_t	kt_cpolicy = KC_INVALID;	

/* 
 * per Job data structure
 */
struct kinetic_data {
	char		*kd_prefix;
	size_t		kd_prefixlen;
};

/* Key Generation Limits that can impact FIO job definition */
#define KINETIC_FIO_PREFIX	"F:"
#define KINETIC_FIO_KEYJOBLEN	4
#define KINETIC_FIO_KEYOFFLEN	10
#define KINETIC_FIO_MAXJOBS	0xFFFF		/* 65,535 jobs */
#define KINETIC_FIO_MAXOFFSET	0xFFFFFFFFFF	/* 1,099,511,627,775 offset */
#define KINETIC_FIO_MINKEY	16


struct kinetic_options {
	void		*pad;
	char		*host;
	char		*port;
	unsigned int	tls;
	uint64_t	id;
	char		*hkey;
	size_t		keylen;
	char 		*cversion;
	char		*cpolicy;
	int 		verbose;
};

static struct fio_option options[] = {
	{
		.name     = "kinetic-host",
		.lname    = "kinetic-host",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic Drive hostname or IP",
		.off1     = offsetof(struct kinetic_options, host),
		.def	  = "localhost",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic-port",
		.lname    = "kinetic-port",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic Drive port",
		.off1     = offsetof(struct kinetic_options, port),
		.def	  = "8123",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic-tls",
		.lname    = "kinetic-tls",
		.type	  = FIO_OPT_BOOL,
		.off1     = offsetof(struct kinetic_options, tls),
		.def      = "0",
		.help     = "Enable/Disable a secure connection",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic-id",
		.lname    = "kinetic-id",
		.type     = FIO_OPT_ULL,
		.help     = "Kinetic User ID",
		.off1     = offsetof(struct kinetic_options, id),
		.def      = "1",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic-hkey",
		.lname    = "kinetic-hmac-key",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic HMAC Key",
		.off1     = offsetof(struct kinetic_options, hkey),
		.def      = "asdfasdf",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name	  = "kinetic-keylen",
		.lname	  = "kinetic-keylen",
		.type	  = FIO_OPT_ULL,
		.off1	  = offsetof(struct kinetic_options, keylen),
		.def      = "16",
		.minval	  = 16,
		.help	  = "Set Kinetic key length, min 16",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic-cversion",
		.lname    = "kinetic-cluster-version",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Kinetic Cluster Version",
		.off1     = offsetof(struct kinetic_options, cversion),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic_cpolicy",
		.lname    = "kinetic-cache-policy",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Set Kinetic cache policy [wt,wb,flush]",
		.off1     = offsetof(struct kinetic_options, cpolicy),
		.def	  = "wt",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_KINETIC,
	},
	{
		.name     = "kinetic-verbose",
		.lname    = "Kinetic-verbosity-level",
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
	int offlen, padlen, i;
	char key_offset[KINETIC_FIO_KEYOFFLEN + 1];
	char *key_pad;
 
	struct kinetic_options *o = td->eo;
	struct kinetic_data *kinetic = td->io_ops_data;
	
	kv_t		kv;
	struct kiovec	kv_key[3];
	struct kiovec	kv_val[1]  = {{0, 0}};
	kstatus_t 	kstatus;
	
	fio_ro_check(td, io_u);

	offlen = sprintf(key_offset, "%0*llx",
			 KINETIC_FIO_KEYOFFLEN, io_u->offset);
	padlen = o->keylen - (kinetic->kd_prefixlen + offlen);
	//printf("\nMaxKeyLen: %lu\nPrefixKeyLen: %lu\nOffsetLen: %d\nPadLen: %d\n",
	//       o->keylen, kinetic->kd_prefixlen, offlen, padlen);

	if (padlen < 0) {
		/* Should never happen */
		log_err("key generation overflow");
		io_u->error = EINVAL;
		goto q_done;
	}

	key_pad = (char *)malloc(padlen + 1);
	if (!key_pad) {
		log_err("pad malloc failed");
		io_u->error = ENOMEM;
		goto q_done;
	}

	for(i=0; i<padlen; i++) key_pad[i] = '.';
	key_pad[padlen] = '\0';

	kv_key[0].kiov_len  = kinetic->kd_prefixlen;
	kv_key[0].kiov_base = (void *)kinetic->kd_prefix;
	kv_key[1].kiov_len  = (size_t)padlen;
	kv_key[1].kiov_base = (void *)key_pad;
	kv_key[2].kiov_len  = (size_t)offlen;
	kv_key[2].kiov_base = (void *)key_offset;

	/* Init kv and return kv */
	memset(&kv, 0, sizeof(kv_t));
	kv.kv_key    = kv_key;
	kv.kv_keycnt = 3;
	kv.kv_val    = kv_val;
	kv.kv_valcnt = 1;

	if (io_u->ddir == DDIR_READ) {
#if 0
		printf("kinetic:%08lx: Get(\"%s%s%s\", %llx)\n", id, 
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);
#endif
		
		//printf("Get('%s%s%s')\n",
		//       kinetic->kd_prefix, key_pad, key_offset);
		kstatus = ki_get(ktd, &kv);
		//printf("Get Returned\n");
		if (kstatus.ks_code != K_OK) {
			printf("Get(\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);

			io_u->error = EIO;
			log_err("ki_get: failed: status code %d %s\n",
				kstatus.ks_code, kstatus.ks_message);
		} else if (io_u->xfer_buflen != kv.kv_val[0].kiov_len) {
			io_u->error = EIO;
			log_err("ki_get: failed: value len != fio buffer len\n");
		} else {
			memcpy(io_u->xfer_buf,
			       kv.kv_val[0].kiov_base, io_u->xfer_buflen);
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
	} else if (io_u->ddir == DDIR_WRITE) {
		printf("Put(\"%s%s%s\", %llx)\n",
		       (char *)kv_key[0].kiov_base,
		       (char *)kv_key[1].kiov_base,
		       (char *)kv_key[2].kiov_base,
		       io_u->xfer_buflen);

		kv_val[0].kiov_len = io_u->xfer_buflen;
		kv_val[0].kiov_base = io_u->xfer_buf;
		kv.kv_cpolicy = kt_cpolicy;
		
		kstatus = ki_put(ktd, NULL, &kv);
		//printf("Put Returned\n");
		if (kstatus.ks_code != K_OK) {
			printf("Put(\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);
			io_u->error = EIO;
			log_err("ki_put: failed: status code %d %s\n",
				kstatus.ks_code, kstatus.ks_message);
		}
	} else if (io_u->ddir == DDIR_TRIM) {
		kv_val[0].kiov_len = io_u->xfer_buflen;
		kv_val[0].kiov_base = io_u->xfer_buf;
		kv.kv_cpolicy = kt_cpolicy;
		
		kstatus = ki_del(ktd, NULL,&kv);
		//printf("Put Returned\n");
		if (kstatus.ks_code != K_OK) {
			printf("Del(\"%s%s%s\")\n",
			       (char *)kv_key[0].kiov_base,
			       (char *)kv_key[1].kiov_base,
			       (char *)kv_key[2].kiov_base);

			io_u->error = EIO;
			log_err("ki_put: failed: status code %d %s\n",
				kstatus.ks_code, kstatus.ks_message);
		}

		return FIO_Q_COMPLETED;
	} else {
		//ret = do_io_u_sync(td, io_u);
	}

 q_done:	
	return FIO_Q_COMPLETED;
	
}

static struct io_u *
fio_kinetic_event(struct thread_data *td, int event)
{
	/* sync IO engine - never any outstanding events */
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
fio_kinetic_cleanup(struct thread_data *td)
{
	struct kinetic_data *kinetic = td->io_ops_data;

	ki_close(ktd);
	if (kinetic) {
		if (kinetic->kd_prefix) free(kinetic->kd_prefix);
		free(kinetic);
	}
}

static int
fio_kinetic_setup(struct thread_data *td)
{
	int len;
	struct kinetic_data *kinetic = NULL;
	struct kinetic_options *o = td->eo;


	if (!td->o.use_thread) {
		/* have a fork issue with the library, force threads for now */
		log_err("--thread not set.\n");
		goto cleanup;
	}

	
	/* Open the global kinetic connection if not open already */
	if (ktd < 0) {
		printf("Opening Kinetic %u\n", td->subjob_number); 
		ktd = ki_open(o->host, o->port, o->tls, o->id, o->hkey);
		if (ktd < 0) {
			log_err("Kinetic connection failed");
			goto cleanup;
		}
	}

	/* Check limits against params */
	kt_limits = ki_limits(ktd);

	/* Make sure keylen is less than the max key length */
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
	if (td->o.bs[DDIR_READ] > kt_limits.kl_vallen) {
		log_err("blocksize too big (>%d)\n",
			kt_limits.kl_vallen);
		goto cleanup;
	}

	/* Make sure the number of jobs is less than max jobs */
	if (td->o.numjobs > KINETIC_FIO_MAXJOBS) {
		log_err("numjobs too big (>%d)", KINETIC_FIO_MAXJOBS);
		goto cleanup;
	}

	/* check size and filesize < KINETIC_FIO_MAXOFFSET */
	if ((td->o.size > KINETIC_FIO_MAXOFFSET) ||
	    (td->o.file_size_high > KINETIC_FIO_MAXOFFSET)) {
		log_err("size too big (>%ld)\n", KINETIC_FIO_MAXOFFSET);
		goto cleanup;
	}

	if (kt_cpolicy == KC_INVALID) {
		if (strcmp(o->cpolicy, "wt")    == 0) kt_cpolicy = KC_WT;
		if (strcmp(o->cpolicy, "wb")    == 0) kt_cpolicy = KC_WB;
		if (strcmp(o->cpolicy, "flush") == 0) kt_cpolicy = KC_FLUSH;

		if (kt_cpolicy == KC_INVALID) {
			log_err("Invalid cpolicy");
			goto cleanup;
		}
	}
	
	/* allocate engine specific structure and key prefix */
	kinetic = calloc(1, sizeof(*kinetic));
	if (!kinetic) {
		log_err("calloc failed.\n");
		goto cleanup;
	}

	/* Create the per job key prefix */
	len = strlen(KINETIC_FIO_PREFIX) + KINETIC_FIO_KEYJOBLEN + 1;
	kinetic->kd_prefix = (char *)malloc(len);
	if (!kinetic->kd_prefix) {
		log_err("prefix malloc failed.\n");
		goto cleanup;

	}

	len = sprintf(kinetic->kd_prefix, "%s%0*x", KINETIC_FIO_PREFIX,
		      KINETIC_FIO_KEYJOBLEN, td->subjob_number);
	
	kinetic->kd_prefixlen = len;
	
	/* hang the kinetic structure */
	td->io_ops_data = kinetic;

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
