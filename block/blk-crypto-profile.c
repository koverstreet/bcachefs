// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */

/**
 * DOC: blk-crypto profiles
 *
 * 'struct blk_crypto_profile' contains all generic inline encryption-related
 * state for a particular inline encryption device.  blk_crypto_profile serves
 * as the way that drivers for inline encryption hardware expose their crypto
 * capabilities and certain functions (e.g., functions to program and evict
 * keys) to upper layers.  Device drivers that want to support inline encryption
 * construct a crypto profile, then associate it with the disk's request_queue.
 *
 * If the device has keyslots, then its blk_crypto_profile also handles managing
 * these keyslots in a device-independent way, using the driver-provided
 * functions to program and evict keys as needed.  This includes keeping track
 * of which key and how many I/O requests are using each keyslot, getting
 * keyslots for I/O requests, and handling key eviction requests.
 *
 * For more information, see Documentation/block/inline-encryption.rst.
 */

#define pr_fmt(fmt) "blk-crypto: " fmt

#include <linux/blk-crypto-profile.h>
#include <linux/device.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/pm_runtime.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>

struct blk_crypto_keyslot {
	atomic_t slot_refs;
	struct list_head idle_slot_node;
	struct hlist_node hash_node;
	const struct blk_crypto_key *key;
	struct blk_crypto_profile *profile;
};

static inline void blk_crypto_hw_enter(struct blk_crypto_profile *profile)
{
	/*
	 * Calling into the driver requires profile->lock held and the device
	 * resumed.  But we must resume the device first, since that can acquire
	 * and release profile->lock via blk_crypto_reprogram_all_keys().
	 */
	if (profile->dev)
		pm_runtime_get_sync(profile->dev);
	down_write(&profile->lock);
}

static inline void blk_crypto_hw_exit(struct blk_crypto_profile *profile)
{
	up_write(&profile->lock);
	if (profile->dev)
		pm_runtime_put_sync(profile->dev);
}

/**
 * blk_crypto_profile_init() - Initialize a blk_crypto_profile
 * @profile: the blk_crypto_profile to initialize
 * @num_slots: the number of keyslots
 *
 * Storage drivers must call this when starting to set up a blk_crypto_profile,
 * before filling in additional fields.
 *
 * Return: 0 on success, or else a negative error code.
 */
int blk_crypto_profile_init(struct blk_crypto_profile *profile,
			    unsigned int num_slots)
{
	unsigned int slot;
	unsigned int i;
	unsigned int slot_hashtable_size;

	memset(profile, 0, sizeof(*profile));
	init_rwsem(&profile->lock);

	if (num_slots == 0)
		return 0;

	/* Initialize keyslot management data. */

	profile->slots = kvcalloc(num_slots, sizeof(profile->slots[0]),
				  GFP_KERNEL);
	if (!profile->slots)
		return -ENOMEM;

	profile->num_slots = num_slots;

	init_waitqueue_head(&profile->idle_slots_wait_queue);
	INIT_LIST_HEAD(&profile->idle_slots);

	for (slot = 0; slot < num_slots; slot++) {
		profile->slots[slot].profile = profile;
		list_add_tail(&profile->slots[slot].idle_slot_node,
			      &profile->idle_slots);
	}

	spin_lock_init(&profile->idle_slots_lock);

	slot_hashtable_size = roundup_pow_of_two(num_slots);
	/*
	 * hash_ptr() assumes bits != 0, so ensure the hash table has at least 2
	 * buckets.  This only makes a difference when there is only 1 keyslot.
	 */
	if (slot_hashtable_size < 2)
		slot_hashtable_size = 2;

	profile->log_slot_ht_size = ilog2(slot_hashtable_size);
	profile->slot_hashtable =
		kvmalloc_array(slot_hashtable_size,
			       sizeof(profile->slot_hashtable[0]), GFP_KERNEL);
	if (!profile->slot_hashtable)
		goto err_destroy;
	for (i = 0; i < slot_hashtable_size; i++)
		INIT_HLIST_HEAD(&profile->slot_hashtable[i]);

	return 0;

err_destroy:
	blk_crypto_profile_destroy(profile);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(blk_crypto_profile_init);

static void blk_crypto_profile_destroy_callback(void *profile)
{
	blk_crypto_profile_destroy(profile);
}

/**
 * devm_blk_crypto_profile_init() - Resource-managed blk_crypto_profile_init()
 * @dev: the device which owns the blk_crypto_profile
 * @profile: the blk_crypto_profile to initialize
 * @num_slots: the number of keyslots
 *
 * Like blk_crypto_profile_init(), but causes blk_crypto_profile_destroy() to be
 * called automatically on driver detach.
 *
 * Return: 0 on success, or else a negative error code.
 */
int devm_blk_crypto_profile_init(struct device *dev,
				 struct blk_crypto_profile *profile,
				 unsigned int num_slots)
{
	int err = blk_crypto_profile_init(profile, num_slots);

	if (err)
		return err;

	return devm_add_action_or_reset(dev,
					blk_crypto_profile_destroy_callback,
					profile);
}
EXPORT_SYMBOL_GPL(devm_blk_crypto_profile_init);

static inline struct hlist_head *
blk_crypto_hash_bucket_for_key(struct blk_crypto_profile *profile,
			       const struct blk_crypto_key *key)
{
	return &profile->slot_hashtable[
			hash_ptr(key, profile->log_slot_ht_size)];
}

static void
blk_crypto_remove_slot_from_lru_list(struct blk_crypto_keyslot *slot)
{
	struct blk_crypto_profile *profile = slot->profile;
	unsigned long flags;

	spin_lock_irqsave(&profile->idle_slots_lock, flags);
	list_del(&slot->idle_slot_node);
	spin_unlock_irqrestore(&profile->idle_slots_lock, flags);
}

static struct blk_crypto_keyslot *
blk_crypto_find_keyslot(struct blk_crypto_profile *profile,
			const struct blk_crypto_key *key)
{
	const struct hlist_head *head =
		blk_crypto_hash_bucket_for_key(profile, key);
	struct blk_crypto_keyslot *slotp;

	hlist_for_each_entry(slotp, head, hash_node) {
		if (slotp->key == key)
			return slotp;
	}
	return NULL;
}

static struct blk_crypto_keyslot *
blk_crypto_find_and_grab_keyslot(struct blk_crypto_profile *profile,
				 const struct blk_crypto_key *key)
{
	struct blk_crypto_keyslot *slot;

	slot = blk_crypto_find_keyslot(profile, key);
	if (!slot)
		return NULL;
	if (atomic_inc_return(&slot->slot_refs) == 1) {
		/* Took first reference to this slot; remove it from LRU list */
		blk_crypto_remove_slot_from_lru_list(slot);
	}
	return slot;
}

/**
 * blk_crypto_keyslot_index() - Get the index of a keyslot
 * @slot: a keyslot that blk_crypto_get_keyslot() returned
 *
 * Return: the 0-based index of the keyslot within the device's keyslots.
 */
unsigned int blk_crypto_keyslot_index(struct blk_crypto_keyslot *slot)
{
	return slot - slot->profile->slots;
}
EXPORT_SYMBOL_GPL(blk_crypto_keyslot_index);

/**
 * blk_crypto_get_keyslot() - Get a keyslot for a key, if needed.
 * @profile: the crypto profile of the device the key will be used on
 * @key: the key that will be used
 * @slot_ptr: If a keyslot is allocated, an opaque pointer to the keyslot struct
 *	      will be stored here; otherwise NULL will be stored here.
 *
 * If the device has keyslots, this gets a keyslot that's been programmed with
 * the specified key.  If the key is already in a slot, this reuses it;
 * otherwise this waits for a slot to become idle and programs the key into it.
 *
 * This must be paired with a call to blk_crypto_put_keyslot().
 *
 * Context: Process context. Takes and releases profile->lock.
 * Return: BLK_STS_OK on success, meaning that either a keyslot was allocated or
 *	   one wasn't needed; or a blk_status_t error on failure.
 */
blk_status_t blk_crypto_get_keyslot(struct blk_crypto_profile *profile,
				    const struct blk_crypto_key *key,
				    struct blk_crypto_keyslot **slot_ptr)
{
	struct blk_crypto_keyslot *slot;
	int slot_idx;
	int err;

	*slot_ptr = NULL;

	/*
	 * If the device has no concept of "keyslots", then there is no need to
	 * get one.
	 */
	if (profile->num_slots == 0)
		return BLK_STS_OK;

	down_read(&profile->lock);
	slot = blk_crypto_find_and_grab_keyslot(profile, key);
	up_read(&profile->lock);
	if (slot)
		goto success;

	for (;;) {
		blk_crypto_hw_enter(profile);
		slot = blk_crypto_find_and_grab_keyslot(profile, key);
		if (slot) {
			blk_crypto_hw_exit(profile);
			goto success;
		}

		/*
		 * If we're here, that means there wasn't a slot that was
		 * already programmed with the key. So try to program it.
		 */
		if (!list_empty(&profile->idle_slots))
			break;

		blk_crypto_hw_exit(profile);
		wait_event(profile->idle_slots_wait_queue,
			   !list_empty(&profile->idle_slots));
	}

	slot = list_first_entry(&profile->idle_slots, struct blk_crypto_keyslot,
				idle_slot_node);
	slot_idx = blk_crypto_keyslot_index(slot);

	err = profile->ll_ops.keyslot_program(profile, key, slot_idx);
	if (err) {
		wake_up(&profile->idle_slots_wait_queue);
		blk_crypto_hw_exit(profile);
		return errno_to_blk_status(err);
	}

	/* Move this slot to the hash list for the new key. */
	if (slot->key)
		hlist_del(&slot->hash_node);
	slot->key = key;
	hlist_add_head(&slot->hash_node,
		       blk_crypto_hash_bucket_for_key(profile, key));

	atomic_set(&slot->slot_refs, 1);

	blk_crypto_remove_slot_from_lru_list(slot);

	blk_crypto_hw_exit(profile);
success:
	*slot_ptr = slot;
	return BLK_STS_OK;
}

/**
 * blk_crypto_put_keyslot() - Release a reference to a keyslot
 * @slot: The keyslot to release the reference of (may be NULL).
 *
 * Context: Any context.
 */
void blk_crypto_put_keyslot(struct blk_crypto_keyslot *slot)
{
	struct blk_crypto_profile *profile;
	unsigned long flags;

	if (!slot)
		return;

	profile = slot->profile;

	if (atomic_dec_and_lock_irqsave(&slot->slot_refs,
					&profile->idle_slots_lock, flags)) {
		list_add_tail(&slot->idle_slot_node, &profile->idle_slots);
		spin_unlock_irqrestore(&profile->idle_slots_lock, flags);
		wake_up(&profile->idle_slots_wait_queue);
	}
}

/**
 * __blk_crypto_cfg_supported() - Check whether the given crypto profile
 *				  supports the given crypto configuration.
 * @profile: the crypto profile to check
 * @cfg: the crypto configuration to check for
 *
 * Return: %true if @profile supports the given @cfg.
 */
bool __blk_crypto_cfg_supported(struct blk_crypto_profile *profile,
				const struct blk_crypto_config *cfg)
{
	if (!profile)
		return false;
	if (!(profile->modes_supported[cfg->crypto_mode] & cfg->data_unit_size))
		return false;
	if (profile->max_dun_bytes_supported < cfg->dun_bytes)
		return false;
	return true;
}

/**
 * __blk_crypto_evict_key() - Evict a key from a device.
 * @profile: the crypto profile of the device
 * @key: the key to evict.  It must not still be used in any I/O.
 *
 * If the device has keyslots, this finds the keyslot (if any) that contains the
 * specified key and calls the driver's keyslot_evict function to evict it.
 *
 * Otherwise, this just calls the driver's keyslot_evict function if it is
 * implemented, passing just the key (without any particular keyslot).  This
 * allows layered devices to evict the key from their underlying devices.
 *
 * Context: Process context. Takes and releases profile->lock.
 * Return: 0 on success or if there's no keyslot with the specified key, -EBUSY
 *	   if the keyslot is still in use, or another -errno value on other
 *	   error.
 */
int __blk_crypto_evict_key(struct blk_crypto_profile *profile,
			   const struct blk_crypto_key *key)
{
	struct blk_crypto_keyslot *slot;
	int err = 0;

	if (profile->num_slots == 0) {
		if (profile->ll_ops.keyslot_evict) {
			blk_crypto_hw_enter(profile);
			err = profile->ll_ops.keyslot_evict(profile, key, -1);
			blk_crypto_hw_exit(profile);
			return err;
		}
		return 0;
	}

	blk_crypto_hw_enter(profile);
	slot = blk_crypto_find_keyslot(profile, key);
	if (!slot)
		goto out_unlock;

	if (WARN_ON_ONCE(atomic_read(&slot->slot_refs) != 0)) {
		err = -EBUSY;
		goto out_unlock;
	}
	err = profile->ll_ops.keyslot_evict(profile, key,
					    blk_crypto_keyslot_index(slot));
	if (err)
		goto out_unlock;

	hlist_del(&slot->hash_node);
	slot->key = NULL;
	err = 0;
out_unlock:
	blk_crypto_hw_exit(profile);
	return err;
}

/**
 * blk_crypto_reprogram_all_keys() - Re-program all keyslots.
 * @profile: The crypto profile
 *
 * Re-program all keyslots that are supposed to have a key programmed.  This is
 * intended only for use by drivers for hardware that loses its keys on reset.
 *
 * Context: Process context. Takes and releases profile->lock.
 */
void blk_crypto_reprogram_all_keys(struct blk_crypto_profile *profile)
{
	unsigned int slot;

	if (profile->num_slots == 0)
		return;

	/* This is for device initialization, so don't resume the device */
	down_write(&profile->lock);
	for (slot = 0; slot < profile->num_slots; slot++) {
		const struct blk_crypto_key *key = profile->slots[slot].key;
		int err;

		if (!key)
			continue;

		err = profile->ll_ops.keyslot_program(profile, key, slot);
		WARN_ON(err);
	}
	up_write(&profile->lock);
}
EXPORT_SYMBOL_GPL(blk_crypto_reprogram_all_keys);

void blk_crypto_profile_destroy(struct blk_crypto_profile *profile)
{
	if (!profile)
		return;
	kvfree(profile->slot_hashtable);
	kvfree_sensitive(profile->slots,
			 sizeof(profile->slots[0]) * profile->num_slots);
	memzero_explicit(profile, sizeof(*profile));
}
EXPORT_SYMBOL_GPL(blk_crypto_profile_destroy);

bool blk_crypto_register(struct blk_crypto_profile *profile,
			 struct request_queue *q)
{
	if (blk_integrity_queue_supports_integrity(q)) {
		pr_warn("Integrity and hardware inline encryption are not supported together. Disabling hardware inline encryption.\n");
		return false;
	}
	q->crypto_profile = profile;
	return true;
}
EXPORT_SYMBOL_GPL(blk_crypto_register);

void blk_crypto_unregister(struct request_queue *q)
{
	q->crypto_profile = NULL;
}

/**
 * blk_crypto_intersect_capabilities() - restrict supported crypto capabilities
 *					 by child device
 * @parent: the crypto profile for the parent device
 * @child: the crypto profile for the child device, or NULL
 *
 * This clears all crypto capabilities in @parent that aren't set in @child.  If
 * @child is NULL, then this clears all parent capabilities.
 *
 * Only use this when setting up the crypto profile for a layered device, before
 * it's been exposed yet.
 */
void blk_crypto_intersect_capabilities(struct blk_crypto_profile *parent,
				       const struct blk_crypto_profile *child)
{
	if (child) {
		unsigned int i;

		parent->max_dun_bytes_supported =
			min(parent->max_dun_bytes_supported,
			    child->max_dun_bytes_supported);
		for (i = 0; i < ARRAY_SIZE(child->modes_supported); i++)
			parent->modes_supported[i] &= child->modes_supported[i];
	} else {
		parent->max_dun_bytes_supported = 0;
		memset(parent->modes_supported, 0,
		       sizeof(parent->modes_supported));
	}
}
EXPORT_SYMBOL_GPL(blk_crypto_intersect_capabilities);

/**
 * blk_crypto_has_capabilities() - Check whether @target supports at least all
 *				   the crypto capabilities that @reference does.
 * @target: the target profile
 * @reference: the reference profile
 *
 * Return: %true if @target supports all the crypto capabilities of @reference.
 */
bool blk_crypto_has_capabilities(const struct blk_crypto_profile *target,
				 const struct blk_crypto_profile *reference)
{
	int i;

	if (!reference)
		return true;

	if (!target)
		return false;

	for (i = 0; i < ARRAY_SIZE(target->modes_supported); i++) {
		if (reference->modes_supported[i] & ~target->modes_supported[i])
			return false;
	}

	if (reference->max_dun_bytes_supported >
	    target->max_dun_bytes_supported)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(blk_crypto_has_capabilities);

/**
 * blk_crypto_update_capabilities() - Update the capabilities of a crypto
 *				      profile to match those of another crypto
 *				      profile.
 * @dst: The crypto profile whose capabilities to update.
 * @src: The crypto profile whose capabilities this function will update @dst's
 *	 capabilities to.
 *
 * Blk-crypto requires that crypto capabilities that were
 * advertised when a bio was created continue to be supported by the
 * device until that bio is ended. This is turn means that a device cannot
 * shrink its advertised crypto capabilities without any explicit
 * synchronization with upper layers. So if there's no such explicit
 * synchronization, @src must support all the crypto capabilities that
 * @dst does (i.e. we need blk_crypto_has_capabilities(@src, @dst)).
 *
 * Note also that as long as the crypto capabilities are being expanded, the
 * order of updates becoming visible is not important because it's alright
 * for blk-crypto to see stale values - they only cause blk-crypto to
 * believe that a crypto capability isn't supported when it actually is (which
 * might result in blk-crypto-fallback being used if available, or the bio being
 * failed).
 */
void blk_crypto_update_capabilities(struct blk_crypto_profile *dst,
				    const struct blk_crypto_profile *src)
{
	memcpy(dst->modes_supported, src->modes_supported,
	       sizeof(dst->modes_supported));

	dst->max_dun_bytes_supported = src->max_dun_bytes_supported;
}
EXPORT_SYMBOL_GPL(blk_crypto_update_capabilities);
