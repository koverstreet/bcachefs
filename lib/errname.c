// SPDX-License-Identifier: GPL-2.0
#include <linux/build_bug.h>
#include <linux/codetag.h>
#include <linux/errno.h>
#include <linux/errname.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/math.h>
#include <linux/module.h>
#include <linux/xarray.h>

#define DYNAMIC_ERRCODE_START	4096

static DEFINE_IDR(dynamic_error_strings);
static DEFINE_XARRAY(error_classes);

static struct codetag_type *cttype;

/*
 * Ensure these tables do not accidentally become gigantic if some
 * huge errno makes it in. On most architectures, the first table will
 * only have about 140 entries, but mips and parisc have more sparsely
 * allocated errnos (with EHWPOISON = 257 on parisc, and EDQUOT = 1133
 * on mips), so this wastes a bit of space on those - though we
 * special case the EDQUOT case.
 */
#define E(err) [err + BUILD_BUG_ON_ZERO(err <= 0 || err > 300)] = "-" #err
static const char *names_0[] = {
	E(E2BIG),
	E(EACCES),
	E(EADDRINUSE),
	E(EADDRNOTAVAIL),
	E(EADV),
	E(EAFNOSUPPORT),
	E(EALREADY),
	E(EBADE),
	E(EBADF),
	E(EBADFD),
	E(EBADMSG),
	E(EBADR),
	E(EBADRQC),
	E(EBADSLT),
	E(EBFONT),
	E(EBUSY),
#ifdef ECANCELLED
	E(ECANCELLED),
#endif
	E(ECHILD),
	E(ECHRNG),
	E(ECOMM),
	E(ECONNABORTED),
	E(ECONNRESET),
	E(EDEADLOCK),
	E(EDESTADDRREQ),
	E(EDOM),
	E(EDOTDOT),
#ifndef CONFIG_MIPS
	E(EDQUOT),
#endif
	E(EEXIST),
	E(EFAULT),
	E(EFBIG),
	E(EHOSTDOWN),
	E(EHOSTUNREACH),
	E(EHWPOISON),
	E(EIDRM),
	E(EILSEQ),
#ifdef EINIT
	E(EINIT),
#endif
	E(EINPROGRESS),
	E(EINTR),
	E(EINVAL),
	E(EIO),
	E(EISCONN),
	E(EISDIR),
	E(EISNAM),
	E(EKEYEXPIRED),
	E(EKEYREJECTED),
	E(EKEYREVOKED),
	E(EL2HLT),
	E(EL2NSYNC),
	E(EL3HLT),
	E(EL3RST),
	E(ELIBACC),
	E(ELIBBAD),
	E(ELIBEXEC),
	E(ELIBMAX),
	E(ELIBSCN),
	E(ELNRNG),
	E(ELOOP),
	E(EMEDIUMTYPE),
	E(EMFILE),
	E(EMLINK),
	E(EMSGSIZE),
	E(EMULTIHOP),
	E(ENAMETOOLONG),
	E(ENAVAIL),
	E(ENETDOWN),
	E(ENETRESET),
	E(ENETUNREACH),
	E(ENFILE),
	E(ENOANO),
	E(ENOBUFS),
	E(ENOCSI),
	E(ENODATA),
	E(ENODEV),
	E(ENOENT),
	E(ENOEXEC),
	E(ENOKEY),
	E(ENOLCK),
	E(ENOLINK),
	E(ENOMEDIUM),
	E(ENOMEM),
	E(ENOMSG),
	E(ENONET),
	E(ENOPKG),
	E(ENOPROTOOPT),
	E(ENOSPC),
	E(ENOSR),
	E(ENOSTR),
#ifdef ENOSYM
	E(ENOSYM),
#endif
	E(ENOSYS),
	E(ENOTBLK),
	E(ENOTCONN),
	E(ENOTDIR),
	E(ENOTEMPTY),
	E(ENOTNAM),
	E(ENOTRECOVERABLE),
	E(ENOTSOCK),
	E(ENOTTY),
	E(ENOTUNIQ),
	E(ENXIO),
	E(EOPNOTSUPP),
	E(EOVERFLOW),
	E(EOWNERDEAD),
	E(EPERM),
	E(EPFNOSUPPORT),
	E(EPIPE),
#ifdef EPROCLIM
	E(EPROCLIM),
#endif
	E(EPROTO),
	E(EPROTONOSUPPORT),
	E(EPROTOTYPE),
	E(ERANGE),
	E(EREMCHG),
#ifdef EREMDEV
	E(EREMDEV),
#endif
	E(EREMOTE),
	E(EREMOTEIO),
#ifdef EREMOTERELEASE
	E(EREMOTERELEASE),
#endif
	E(ERESTART),
	E(ERFKILL),
	E(EROFS),
#ifdef ERREMOTE
	E(ERREMOTE),
#endif
	E(ESHUTDOWN),
	E(ESOCKTNOSUPPORT),
	E(ESPIPE),
	E(ESRCH),
	E(ESRMNT),
	E(ESTALE),
	E(ESTRPIPE),
	E(ETIME),
	E(ETIMEDOUT),
	E(ETOOMANYREFS),
	E(ETXTBSY),
	E(EUCLEAN),
	E(EUNATCH),
	E(EUSERS),
	E(EXDEV),
	E(EXFULL),

	E(ECANCELED), /* ECANCELLED */
	E(EAGAIN), /* EWOULDBLOCK */
	E(ECONNREFUSED), /* EREFUSED */
	E(EDEADLK), /* EDEADLOCK */
};
#undef E

#define E(err) [err - 512 + BUILD_BUG_ON_ZERO(err < 512 || err > 550)] = "-" #err
static const char *names_512[] = {
	E(ERESTARTSYS),
	E(ERESTARTNOINTR),
	E(ERESTARTNOHAND),
	E(ENOIOCTLCMD),
	E(ERESTART_RESTARTBLOCK),
	E(EPROBE_DEFER),
	E(EOPENSTALE),
	E(ENOPARAM),

	E(EBADHANDLE),
	E(ENOTSYNC),
	E(EBADCOOKIE),
	E(ENOTSUPP),
	E(ETOOSMALL),
	E(ESERVERFAULT),
	E(EBADTYPE),
	E(EJUKEBOX),
	E(EIOCBQUEUED),
	E(ERECALLCONFLICT),
};
#undef E

static const char *__errname(unsigned err)
{
	if (err >= DYNAMIC_ERRCODE_START)
		return idr_find(&dynamic_error_strings, err);

	if (err < ARRAY_SIZE(names_0))
		return names_0[err];
	if (err >= 512 && err - 512 < ARRAY_SIZE(names_512))
		return names_512[err - 512];
	/* But why? */
	if (IS_ENABLED(CONFIG_MIPS) && err == EDQUOT) /* 1133 */
		return "-EDQUOT";
	return NULL;
}

/*
 * errname(EIO) -> "EIO"
 * errname(-EIO) -> "-EIO"
 */
const char *errname(int err)
{
	const char *name = __errname(abs(err));
	if (!name)
		return NULL;

	return err > 0 ? name + 1 : name;
}

/**
 * error_class - return standard/parent error (of a dynamic error code)
 *
 * When using dynamic error codes returned by ERR(), error_class() will return
 * the original errorcode that was passed to ERR().
 */
int error_class(int err)
{
	int class = abs(err);

	if (class > DYNAMIC_ERRCODE_START)
		class = (unsigned long) xa_load(&error_classes,
					      class - DYNAMIC_ERRCODE_START);
	if (err < 0)
		class = -class;
	return class;
}
EXPORT_SYMBOL(error_class);

/**
 * error_matches - test if error is of some type
 *
 * When using dynamic error codes, instead of checking for errors with e.g.
 *   if (err == -ENOMEM)
 * Instead use
 *   if (error_matches(err, ENOMEM))
 */
bool error_matches(int err, int class)
{
	err	= abs(err);
	class	= abs(class);

	BUG_ON(err	>= MAX_ERRNO);
	BUG_ON(class	>= MAX_ERRNO);

	if (err != class)
		err = error_class(err);

	return err == class;
}
EXPORT_SYMBOL(error_matches);

static void errcode_module_load(struct codetag_type *cttype, struct codetag_module *mod)
{
	struct codetag_error_code *i, *start = (void *) mod->range.start;
	struct codetag_error_code *end = (void *) mod->range.stop;

	for (i = start; i != end; i++) {
		int err = idr_alloc(&dynamic_error_strings,
				    (char *) i->str,
				    DYNAMIC_ERRCODE_START,
				    MAX_ERRNO,
				    GFP_KERNEL);
		if (err < 0)
			continue;

		xa_store(&error_classes,
			 err - DYNAMIC_ERRCODE_START,
			 (void *)(unsigned long) abs(i->err),
			 GFP_KERNEL);

		i->err = i->err < 0 ? -err : err;
	}
}

static void errcode_module_unload(struct codetag_type *cttype, struct codetag_module *mod)
{
	struct codetag_error_code *i, *start = (void *) mod->range.start;
	struct codetag_error_code *end = (void *) mod->range.stop;

	for (i = start; i != end; i++)
		idr_remove(&dynamic_error_strings, abs(i->err));
}

static int __init errname_init(void)
{
	const struct codetag_type_desc desc = {
		.section	= "error_code_tags",
		.tag_size	= sizeof(struct codetag_error_code),
		.module_load	= errcode_module_load,
		.module_unload	= errcode_module_unload,
	};

	cttype = codetag_register_type(&desc);

	return PTR_ERR_OR_ZERO(cttype);
}
module_init(errname_init);
