/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2019-2020 The Linux Foundation. All rights reserved.
 */

#include "core.h"

struct ath11k_hif_ops {
	u32 (*read32)(struct ath11k_base *sc, u32 address);
	void (*write32)(struct ath11k_base *sc, u32 address, u32 data);
	void (*irq_enable)(struct ath11k_base *sc);
	void (*irq_disable)(struct ath11k_base *sc);
	int (*start)(struct ath11k_base *sc);
	void (*stop)(struct ath11k_base *sc);
	int (*power_up)(struct ath11k_base *sc);
	void (*power_down)(struct ath11k_base *sc);
	int (*map_service_to_pipe)(struct ath11k_base *sc, u16 service_id,
				   u8 *ul_pipe, u8 *dl_pipe);
};

static inline int ath11k_hif_start(struct ath11k_base *sc)
{
	return sc->hif.ops->start(sc);
}

static inline void ath11k_hif_stop(struct ath11k_base *sc)
{
	sc->hif.ops->stop(sc);
}

static inline void ath11k_hif_irq_enable(struct ath11k_base *sc)
{
	sc->hif.ops->irq_enable(sc);
}

static inline void ath11k_hif_irq_disable(struct ath11k_base *sc)
{
	sc->hif.ops->irq_disable(sc);
}

static inline int ath11k_hif_power_up(struct ath11k_base *sc)
{
	return sc->hif.ops->power_up(sc);
}

static inline void ath11k_hif_power_down(struct ath11k_base *sc)
{
	sc->hif.ops->power_down(sc);
}

static inline u32 ath11k_hif_read32(struct ath11k_base *sc, u32 address)
{
	return sc->hif.ops->read32(sc, address);
}

static inline void ath11k_hif_write32(struct ath11k_base *sc, u32 address, u32 data)
{
	sc->hif.ops->write32(sc, address, data);
}

static inline int ath11k_hif_map_service_to_pipe(struct ath11k_base *sc, u16 service_id,
						 u8 *ul_pipe, u8 *dl_pipe)
{
	return sc->hif.ops->map_service_to_pipe(sc, service_id, ul_pipe, dl_pipe);
}
