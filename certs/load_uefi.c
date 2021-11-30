#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/efi.h>
#include <linux/slab.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include "internal.h"

static __initdata efi_guid_t efi_cert_x509_guid = EFI_CERT_X509_GUID;
static __initdata efi_guid_t efi_cert_x509_sha256_guid = EFI_CERT_X509_SHA256_GUID;
static __initdata efi_guid_t efi_cert_sha256_guid = EFI_CERT_SHA256_GUID;

/*
 * Look to see if a UEFI variable called MokIgnoreDB exists and return true if
 * it does.
 *
 * This UEFI variable is set by the shim if a user tells the shim to not use
 * the certs/hashes in the UEFI db variable for verification purposes.  If it
 * is set, we should ignore the db variable also and the true return indicates
 * this.
 */
static __init bool uefi_check_ignore_db(void)
{
	efi_status_t status;
	unsigned int db = 0;
	unsigned long size = sizeof(db);
	efi_guid_t guid = EFI_SHIM_LOCK_GUID;

	status = efi.get_variable(L"MokIgnoreDB", &guid, NULL, &size, &db);
	return status == EFI_SUCCESS;
}

/*
 * Get a certificate list blob from the named EFI variable.
 */
static __init void *get_cert_list(efi_char16_t *name, efi_guid_t *guid,
				  unsigned long *size)
{
	efi_status_t status;
	unsigned long lsize = 4;
	unsigned long tmpdb[4];
	void *db;

	status = efi.get_variable(name, guid, NULL, &lsize, &tmpdb);
	if (status != EFI_BUFFER_TOO_SMALL) {
		pr_err("Couldn't get size: 0x%lx\n", status);
		return NULL;
	}

	db = kmalloc(lsize, GFP_KERNEL);
	if (!db) {
		pr_err("Couldn't allocate memory for uefi cert list\n");
		return NULL;
	}

	status = efi.get_variable(name, guid, NULL, &lsize, db);
	if (status != EFI_SUCCESS) {
		kfree(db);
		pr_err("Error reading db var: 0x%lx\n", status);
		return NULL;
	}

	*size = lsize;
	return db;
}

/*
 * Blacklist an X509 TBS hash.
 */
static __init void uefi_blacklist_x509_tbs(const char *source,
					   const void *data, size_t len)
{
	char *hash, *p;

	hash = kmalloc(4 + len * 2 + 1, GFP_KERNEL);
	if (!hash)
		return;
	p = memcpy(hash, "tbs:", 4);
	p += 4;
	bin2hex(p, data, len);
	p += len * 2;
	*p = 0;

	mark_hash_blacklisted(hash);
	kfree(hash);
}

/*
 * Blacklist the hash of an executable.
 */
static __init void uefi_blacklist_binary(const char *source,
					 const void *data, size_t len)
{
	char *hash, *p;

	hash = kmalloc(4 + len * 2 + 1, GFP_KERNEL);
	if (!hash)
		return;
	p = memcpy(hash, "bin:", 4);
	p += 4;
	bin2hex(p, data, len);
	p += len * 2;
	*p = 0;

	mark_hash_blacklisted(hash);
	kfree(hash);
}

/*
 * Add an X509 cert to the revocation list.
 */
static __init void uefi_revocation_list_x509(const char *source,
					     const void *data, size_t len)
{
	pr_info("Revoking X.509 certificate: %s\n", source);
	add_key_to_revocation_list(data, len);
}

/*
 * Return the appropriate handler for particular signature list types found in
 * the UEFI db and MokListRT tables.
 */
static __init efi_element_handler_t get_handler_for_db(const efi_guid_t *sig_type)
{
	if (efi_guidcmp(*sig_type, efi_cert_x509_guid) == 0)
		return add_trusted_secondary_key;
	return 0;
}

/*
 * Return the appropriate handler for particular signature list types found in
 * the UEFI dbx and MokListXRT tables.
 */
static __init efi_element_handler_t get_handler_for_dbx(const efi_guid_t *sig_type)
{
	if (efi_guidcmp(*sig_type, efi_cert_x509_sha256_guid) == 0)
		return uefi_blacklist_x509_tbs;
	if (efi_guidcmp(*sig_type, efi_cert_sha256_guid) == 0)
		return uefi_blacklist_binary;
	if (efi_guidcmp(*sig_type, efi_cert_x509_guid) == 0)
		return uefi_revocation_list_x509;
	return 0;
}

/*
 * load_moklist_certs() - Load Mok(X)List certs
 * @load_db: Load MokListRT into db when true; MokListXRT into dbx when false
 *
 * Load the certs contained in the UEFI MokList(X)RT database into the
 * platform trusted/denied keyring.
 *
 * This routine checks the EFI MOK config table first. If and only if
 * that fails, this routine uses the MokList(X)RT ordinary UEFI variable.
 *
 * Return:	Status
 */
static int __init load_moklist_certs(const bool load_db)
{
	struct efi_mokvar_table_entry *mokvar_entry;
	efi_guid_t mok_var = EFI_SHIM_LOCK_GUID;
	void *mok;
	unsigned long moksize;
	int rc;
	const char *mokvar_name = "MokListRT";
	/* Should be const, but get_cert_list() doesn't have it as const yet */
	efi_char16_t *efivar_name = L"MokListRT";
	const char *parse_mokvar_name = "UEFI:MokListRT (MOKvar table)";
	const char *parse_efivar_name = "UEFI:MokListRT";
	efi_element_handler_t (*get_handler_for_guid)(const efi_guid_t *) = get_handler_for_db;

	if (!load_db) {
		mokvar_name = "MokListXRT";
		efivar_name = L"MokListXRT";
		parse_mokvar_name = "UEFI:MokListXRT (MOKvar table)";
		parse_efivar_name = "UEFI:MokListXRT";
		get_handler_for_guid = get_handler_for_dbx;
	}

	/* First try to load certs from the EFI MOKvar config table.
	 * It's not an error if the MOKvar config table doesn't exist
	 * or the MokListRT entry is not found in it.
	 */
	mokvar_entry = efi_mokvar_entry_find(mokvar_name);
	if (mokvar_entry) {
		rc = parse_efi_signature_list(parse_mokvar_name,
					      mokvar_entry->data,
					      mokvar_entry->data_size,
					      get_handler_for_guid);
		/* All done if that worked. */
		if (!rc)
			return rc;

		pr_err("Couldn't parse %s signatures from EFI MOKvar config table: %d\n",
		       mokvar_name, rc);
	}

	/* Get MokListRT. It might not exist, so it isn't an error
	 * if we can't get it.
	 */
	mok = get_cert_list(efivar_name, &mok_var, &moksize);
	if (mok) {
		rc = parse_efi_signature_list(parse_efivar_name,
					      mok, moksize, get_handler_for_guid);
		kfree(mok);
		if (rc)
			pr_err("Couldn't parse %s signatures: %d\n", mokvar_name, rc);
		return rc;
	} else
		pr_info("Couldn't get UEFI %s\n", mokvar_name);
	return 0;
}

/*
 * load_uefi_certs() - Load certs from UEFI sources
 *
 *
 * Load the certs contained in the UEFI databases into the secondary trusted
 * keyring and the UEFI blacklisted X.509 cert SHA256 hashes into the blacklist
 * keyring.
 */
static int __init load_uefi_certs(void)
{
	efi_guid_t secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	void *db = NULL, *dbx = NULL;
	unsigned long dbsize = 0, dbxsize = 0;
	int rc = 0;

	if (!efi.get_variable)
		return false;

	/* Get db, MokListRT, and dbx.  They might not exist, so it isn't
	 * an error if we can't get them.
	 */
	if (!uefi_check_ignore_db()) {
		db = get_cert_list(L"db", &secure_var, &dbsize);
		if (!db) {
			pr_err("MODSIGN: Couldn't get UEFI db list\n");
		} else {
			rc = parse_efi_signature_list("UEFI:db",
						      db, dbsize, get_handler_for_db);
			if (rc)
				pr_err("Couldn't parse db signatures: %d\n", rc);
			kfree(db);
		}
	}

	dbx = get_cert_list(L"dbx", &secure_var, &dbxsize);
	if (!dbx) {
		pr_info("MODSIGN: Couldn't get UEFI dbx list\n");
	} else {
		rc = parse_efi_signature_list("UEFI:dbx",
					      dbx, dbxsize,
					      get_handler_for_dbx);
		if (rc)
			pr_err("Couldn't parse dbx signatures: %d\n", rc);
		kfree(dbx);
	}

	/* Load the MokListXRT certs */
	rc = load_moklist_certs(false);
	if (rc)
		pr_err("Couldn't parse mokx signatures: %d\n", rc);

	/* Load the MokListRT certs */
	rc = load_moklist_certs(true);
	if (rc)
		pr_err("Couldn't parse mok signatures: %d\n", rc);

	return rc;
}
late_initcall(load_uefi_certs);
