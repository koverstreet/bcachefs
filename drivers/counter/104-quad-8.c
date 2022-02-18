// SPDX-License-Identifier: GPL-2.0
/*
 * Counter driver for the ACCES 104-QUAD-8
 * Copyright (C) 2016 William Breathitt Gray
 *
 * This driver supports the ACCES 104-QUAD-8 and ACCES 104-QUAD-4.
 */
#include <linux/bitops.h>
#include <linux/counter.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/isa.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/spinlock.h>

#define QUAD8_EXTENT 32

static unsigned int base[max_num_isa_dev(QUAD8_EXTENT)];
static unsigned int num_quad8;
module_param_hw_array(base, uint, ioport, &num_quad8, 0);
MODULE_PARM_DESC(base, "ACCES 104-QUAD-8 base addresses");

static unsigned int irq[max_num_isa_dev(QUAD8_EXTENT)];
module_param_hw_array(irq, uint, irq, NULL, 0);
MODULE_PARM_DESC(irq, "ACCES 104-QUAD-8 interrupt line numbers");

#define QUAD8_NUM_COUNTERS 8

/**
 * struct quad8 - device private data structure
 * @lock:		lock to prevent clobbering device states during R/W ops
 * @counter:		instance of the counter_device
 * @fck_prescaler:	array of filter clock prescaler configurations
 * @preset:		array of preset values
 * @count_mode:		array of count mode configurations
 * @quadrature_mode:	array of quadrature mode configurations
 * @quadrature_scale:	array of quadrature mode scale configurations
 * @ab_enable:		array of A and B inputs enable configurations
 * @preset_enable:	array of set_to_preset_on_index attribute configurations
 * @irq_trigger:	array of current IRQ trigger function configurations
 * @synchronous_mode:	array of index function synchronous mode configurations
 * @index_polarity:	array of index function polarity configurations
 * @cable_fault_enable:	differential encoder cable status enable configurations
 * @base:		base port address of the device
 */
struct quad8 {
	spinlock_t lock;
	struct counter_device counter;
	unsigned int fck_prescaler[QUAD8_NUM_COUNTERS];
	unsigned int preset[QUAD8_NUM_COUNTERS];
	unsigned int count_mode[QUAD8_NUM_COUNTERS];
	unsigned int quadrature_mode[QUAD8_NUM_COUNTERS];
	unsigned int quadrature_scale[QUAD8_NUM_COUNTERS];
	unsigned int ab_enable[QUAD8_NUM_COUNTERS];
	unsigned int preset_enable[QUAD8_NUM_COUNTERS];
	unsigned int irq_trigger[QUAD8_NUM_COUNTERS];
	unsigned int synchronous_mode[QUAD8_NUM_COUNTERS];
	unsigned int index_polarity[QUAD8_NUM_COUNTERS];
	unsigned int cable_fault_enable;
	unsigned int base;
};

#define QUAD8_REG_INTERRUPT_STATUS 0x10
#define QUAD8_REG_CHAN_OP 0x11
#define QUAD8_REG_INDEX_INTERRUPT 0x12
#define QUAD8_REG_INDEX_INPUT_LEVELS 0x16
#define QUAD8_DIFF_ENCODER_CABLE_STATUS 0x17
/* Borrow Toggle flip-flop */
#define QUAD8_FLAG_BT BIT(0)
/* Carry Toggle flip-flop */
#define QUAD8_FLAG_CT BIT(1)
/* Error flag */
#define QUAD8_FLAG_E BIT(4)
/* Up/Down flag */
#define QUAD8_FLAG_UD BIT(5)
/* Reset and Load Signal Decoders */
#define QUAD8_CTR_RLD 0x00
/* Counter Mode Register */
#define QUAD8_CTR_CMR 0x20
/* Input / Output Control Register */
#define QUAD8_CTR_IOR 0x40
/* Index Control Register */
#define QUAD8_CTR_IDR 0x60
/* Reset Byte Pointer (three byte data pointer) */
#define QUAD8_RLD_RESET_BP 0x01
/* Reset Counter */
#define QUAD8_RLD_RESET_CNTR 0x02
/* Reset Borrow Toggle, Carry Toggle, Compare Toggle, and Sign flags */
#define QUAD8_RLD_RESET_FLAGS 0x04
/* Reset Error flag */
#define QUAD8_RLD_RESET_E 0x06
/* Preset Register to Counter */
#define QUAD8_RLD_PRESET_CNTR 0x08
/* Transfer Counter to Output Latch */
#define QUAD8_RLD_CNTR_OUT 0x10
/* Transfer Preset Register LSB to FCK Prescaler */
#define QUAD8_RLD_PRESET_PSC 0x18
#define QUAD8_CHAN_OP_RESET_COUNTERS 0x01
#define QUAD8_CHAN_OP_ENABLE_INTERRUPT_FUNC 0x04
#define QUAD8_CMR_QUADRATURE_X1 0x08
#define QUAD8_CMR_QUADRATURE_X2 0x10
#define QUAD8_CMR_QUADRATURE_X4 0x18

static int quad8_signal_read(struct counter_device *counter,
			     struct counter_signal *signal,
			     enum counter_signal_level *level)
{
	const struct quad8 *const priv = counter->priv;
	unsigned int state;

	/* Only Index signal levels can be read */
	if (signal->id < 16)
		return -EINVAL;

	state = inb(priv->base + QUAD8_REG_INDEX_INPUT_LEVELS)
		& BIT(signal->id - 16);

	*level = (state) ? COUNTER_SIGNAL_LEVEL_HIGH : COUNTER_SIGNAL_LEVEL_LOW;

	return 0;
}

static int quad8_count_read(struct counter_device *counter,
			    struct counter_count *count, u64 *val)
{
	struct quad8 *const priv = counter->priv;
	const int base_offset = priv->base + 2 * count->id;
	unsigned int flags;
	unsigned int borrow;
	unsigned int carry;
	unsigned long irqflags;
	int i;

	flags = inb(base_offset + 1);
	borrow = flags & QUAD8_FLAG_BT;
	carry = !!(flags & QUAD8_FLAG_CT);

	/* Borrow XOR Carry effectively doubles count range */
	*val = (unsigned long)(borrow ^ carry) << 24;

	spin_lock_irqsave(&priv->lock, irqflags);

	/* Reset Byte Pointer; transfer Counter to Output Latch */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP | QUAD8_RLD_CNTR_OUT,
	     base_offset + 1);

	for (i = 0; i < 3; i++)
		*val |= (unsigned long)inb(base_offset) << (8 * i);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_count_write(struct counter_device *counter,
			     struct counter_count *count, u64 val)
{
	struct quad8 *const priv = counter->priv;
	const int base_offset = priv->base + 2 * count->id;
	unsigned long irqflags;
	int i;

	/* Only 24-bit values are supported */
	if (val > 0xFFFFFF)
		return -ERANGE;

	spin_lock_irqsave(&priv->lock, irqflags);

	/* Reset Byte Pointer */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP, base_offset + 1);

	/* Counter can only be set via Preset Register */
	for (i = 0; i < 3; i++)
		outb(val >> (8 * i), base_offset);

	/* Transfer Preset Register to Counter */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_PRESET_CNTR, base_offset + 1);

	/* Reset Byte Pointer */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP, base_offset + 1);

	/* Set Preset Register back to original value */
	val = priv->preset[count->id];
	for (i = 0; i < 3; i++)
		outb(val >> (8 * i), base_offset);

	/* Reset Borrow, Carry, Compare, and Sign flags */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_FLAGS, base_offset + 1);
	/* Reset Error flag */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_E, base_offset + 1);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static const enum counter_function quad8_count_functions_list[] = {
	COUNTER_FUNCTION_PULSE_DIRECTION,
	COUNTER_FUNCTION_QUADRATURE_X1_A,
	COUNTER_FUNCTION_QUADRATURE_X2_A,
	COUNTER_FUNCTION_QUADRATURE_X4,
};

static int quad8_function_read(struct counter_device *counter,
			       struct counter_count *count,
			       enum counter_function *function)
{
	struct quad8 *const priv = counter->priv;
	const int id = count->id;
	unsigned long irqflags;

	spin_lock_irqsave(&priv->lock, irqflags);

	if (priv->quadrature_mode[id])
		switch (priv->quadrature_scale[id]) {
		case 0:
			*function = COUNTER_FUNCTION_QUADRATURE_X1_A;
			break;
		case 1:
			*function = COUNTER_FUNCTION_QUADRATURE_X2_A;
			break;
		case 2:
			*function = COUNTER_FUNCTION_QUADRATURE_X4;
			break;
		}
	else
		*function = COUNTER_FUNCTION_PULSE_DIRECTION;

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_function_write(struct counter_device *counter,
				struct counter_count *count,
				enum counter_function function)
{
	struct quad8 *const priv = counter->priv;
	const int id = count->id;
	unsigned int *const quadrature_mode = priv->quadrature_mode + id;
	unsigned int *const scale = priv->quadrature_scale + id;
	unsigned int *const synchronous_mode = priv->synchronous_mode + id;
	const int base_offset = priv->base + 2 * id + 1;
	unsigned long irqflags;
	unsigned int mode_cfg;
	unsigned int idr_cfg;

	spin_lock_irqsave(&priv->lock, irqflags);

	mode_cfg = priv->count_mode[id] << 1;
	idr_cfg = priv->index_polarity[id] << 1;

	if (function == COUNTER_FUNCTION_PULSE_DIRECTION) {
		*quadrature_mode = 0;

		/* Quadrature scaling only available in quadrature mode */
		*scale = 0;

		/* Synchronous function not supported in non-quadrature mode */
		if (*synchronous_mode) {
			*synchronous_mode = 0;
			/* Disable synchronous function mode */
			outb(QUAD8_CTR_IDR | idr_cfg, base_offset);
		}
	} else {
		*quadrature_mode = 1;

		switch (function) {
		case COUNTER_FUNCTION_QUADRATURE_X1_A:
			*scale = 0;
			mode_cfg |= QUAD8_CMR_QUADRATURE_X1;
			break;
		case COUNTER_FUNCTION_QUADRATURE_X2_A:
			*scale = 1;
			mode_cfg |= QUAD8_CMR_QUADRATURE_X2;
			break;
		case COUNTER_FUNCTION_QUADRATURE_X4:
			*scale = 2;
			mode_cfg |= QUAD8_CMR_QUADRATURE_X4;
			break;
		default:
			/* should never reach this path */
			spin_unlock_irqrestore(&priv->lock, irqflags);
			return -EINVAL;
		}
	}

	/* Load mode configuration to Counter Mode Register */
	outb(QUAD8_CTR_CMR | mode_cfg, base_offset);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_direction_read(struct counter_device *counter,
				struct counter_count *count,
				enum counter_count_direction *direction)
{
	const struct quad8 *const priv = counter->priv;
	unsigned int ud_flag;
	const unsigned int flag_addr = priv->base + 2 * count->id + 1;

	/* U/D flag: nonzero = up, zero = down */
	ud_flag = inb(flag_addr) & QUAD8_FLAG_UD;

	*direction = (ud_flag) ? COUNTER_COUNT_DIRECTION_FORWARD :
		COUNTER_COUNT_DIRECTION_BACKWARD;

	return 0;
}

static const enum counter_synapse_action quad8_index_actions_list[] = {
	COUNTER_SYNAPSE_ACTION_NONE,
	COUNTER_SYNAPSE_ACTION_RISING_EDGE,
};

static const enum counter_synapse_action quad8_synapse_actions_list[] = {
	COUNTER_SYNAPSE_ACTION_NONE,
	COUNTER_SYNAPSE_ACTION_RISING_EDGE,
	COUNTER_SYNAPSE_ACTION_FALLING_EDGE,
	COUNTER_SYNAPSE_ACTION_BOTH_EDGES,
};

static int quad8_action_read(struct counter_device *counter,
			     struct counter_count *count,
			     struct counter_synapse *synapse,
			     enum counter_synapse_action *action)
{
	struct quad8 *const priv = counter->priv;
	int err;
	enum counter_function function;
	const size_t signal_a_id = count->synapses[0].signal->id;
	enum counter_count_direction direction;

	/* Handle Index signals */
	if (synapse->signal->id >= 16) {
		if (priv->preset_enable[count->id])
			*action = COUNTER_SYNAPSE_ACTION_RISING_EDGE;
		else
			*action = COUNTER_SYNAPSE_ACTION_NONE;

		return 0;
	}

	err = quad8_function_read(counter, count, &function);
	if (err)
		return err;

	/* Default action mode */
	*action = COUNTER_SYNAPSE_ACTION_NONE;

	/* Determine action mode based on current count function mode */
	switch (function) {
	case COUNTER_FUNCTION_PULSE_DIRECTION:
		if (synapse->signal->id == signal_a_id)
			*action = COUNTER_SYNAPSE_ACTION_RISING_EDGE;
		return 0;
	case COUNTER_FUNCTION_QUADRATURE_X1_A:
		if (synapse->signal->id == signal_a_id) {
			err = quad8_direction_read(counter, count, &direction);
			if (err)
				return err;

			if (direction == COUNTER_COUNT_DIRECTION_FORWARD)
				*action = COUNTER_SYNAPSE_ACTION_RISING_EDGE;
			else
				*action = COUNTER_SYNAPSE_ACTION_FALLING_EDGE;
		}
		return 0;
	case COUNTER_FUNCTION_QUADRATURE_X2_A:
		if (synapse->signal->id == signal_a_id)
			*action = COUNTER_SYNAPSE_ACTION_BOTH_EDGES;
		return 0;
	case COUNTER_FUNCTION_QUADRATURE_X4:
		*action = COUNTER_SYNAPSE_ACTION_BOTH_EDGES;
		return 0;
	default:
		/* should never reach this path */
		return -EINVAL;
	}
}

enum {
	QUAD8_EVENT_CARRY = 0,
	QUAD8_EVENT_COMPARE = 1,
	QUAD8_EVENT_CARRY_BORROW = 2,
	QUAD8_EVENT_INDEX = 3,
};

static int quad8_events_configure(struct counter_device *counter)
{
	struct quad8 *const priv = counter->priv;
	unsigned long irq_enabled = 0;
	unsigned long irqflags;
	struct counter_event_node *event_node;
	unsigned int next_irq_trigger;
	unsigned long ior_cfg;
	unsigned long base_offset;

	spin_lock_irqsave(&priv->lock, irqflags);

	list_for_each_entry(event_node, &counter->events_list, l) {
		switch (event_node->event) {
		case COUNTER_EVENT_OVERFLOW:
			next_irq_trigger = QUAD8_EVENT_CARRY;
			break;
		case COUNTER_EVENT_THRESHOLD:
			next_irq_trigger = QUAD8_EVENT_COMPARE;
			break;
		case COUNTER_EVENT_OVERFLOW_UNDERFLOW:
			next_irq_trigger = QUAD8_EVENT_CARRY_BORROW;
			break;
		case COUNTER_EVENT_INDEX:
			next_irq_trigger = QUAD8_EVENT_INDEX;
			break;
		default:
			/* should never reach this path */
			spin_unlock_irqrestore(&priv->lock, irqflags);
			return -EINVAL;
		}

		/* Skip configuration if it is the same as previously set */
		if (priv->irq_trigger[event_node->channel] == next_irq_trigger)
			continue;

		/* Save new IRQ function configuration */
		priv->irq_trigger[event_node->channel] = next_irq_trigger;

		/* Load configuration to I/O Control Register */
		ior_cfg = priv->ab_enable[event_node->channel] |
			  priv->preset_enable[event_node->channel] << 1 |
			  priv->irq_trigger[event_node->channel] << 3;
		base_offset = priv->base + 2 * event_node->channel + 1;
		outb(QUAD8_CTR_IOR | ior_cfg, base_offset);

		/* Enable IRQ line */
		irq_enabled |= BIT(event_node->channel);
	}

	outb(irq_enabled, priv->base + QUAD8_REG_INDEX_INTERRUPT);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_watch_validate(struct counter_device *counter,
				const struct counter_watch *watch)
{
	struct counter_event_node *event_node;

	if (watch->channel > QUAD8_NUM_COUNTERS - 1)
		return -EINVAL;

	switch (watch->event) {
	case COUNTER_EVENT_OVERFLOW:
	case COUNTER_EVENT_THRESHOLD:
	case COUNTER_EVENT_OVERFLOW_UNDERFLOW:
	case COUNTER_EVENT_INDEX:
		list_for_each_entry(event_node, &counter->next_events_list, l)
			if (watch->channel == event_node->channel &&
				watch->event != event_node->event)
				return -EINVAL;
		return 0;
	default:
		return -EINVAL;
	}
}

static const struct counter_ops quad8_ops = {
	.signal_read = quad8_signal_read,
	.count_read = quad8_count_read,
	.count_write = quad8_count_write,
	.function_read = quad8_function_read,
	.function_write = quad8_function_write,
	.action_read = quad8_action_read,
	.events_configure = quad8_events_configure,
	.watch_validate = quad8_watch_validate,
};

static const char *const quad8_index_polarity_modes[] = {
	"negative",
	"positive"
};

static int quad8_index_polarity_get(struct counter_device *counter,
				    struct counter_signal *signal,
				    u32 *index_polarity)
{
	const struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id - 16;

	*index_polarity = priv->index_polarity[channel_id];

	return 0;
}

static int quad8_index_polarity_set(struct counter_device *counter,
				    struct counter_signal *signal,
				    u32 index_polarity)
{
	struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id - 16;
	const int base_offset = priv->base + 2 * channel_id + 1;
	unsigned long irqflags;
	unsigned int idr_cfg = index_polarity << 1;

	spin_lock_irqsave(&priv->lock, irqflags);

	idr_cfg |= priv->synchronous_mode[channel_id];

	priv->index_polarity[channel_id] = index_polarity;

	/* Load Index Control configuration to Index Control Register */
	outb(QUAD8_CTR_IDR | idr_cfg, base_offset);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static const char *const quad8_synchronous_modes[] = {
	"non-synchronous",
	"synchronous"
};

static int quad8_synchronous_mode_get(struct counter_device *counter,
				      struct counter_signal *signal,
				      u32 *synchronous_mode)
{
	const struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id - 16;

	*synchronous_mode = priv->synchronous_mode[channel_id];

	return 0;
}

static int quad8_synchronous_mode_set(struct counter_device *counter,
				      struct counter_signal *signal,
				      u32 synchronous_mode)
{
	struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id - 16;
	const int base_offset = priv->base + 2 * channel_id + 1;
	unsigned long irqflags;
	unsigned int idr_cfg = synchronous_mode;

	spin_lock_irqsave(&priv->lock, irqflags);

	idr_cfg |= priv->index_polarity[channel_id] << 1;

	/* Index function must be non-synchronous in non-quadrature mode */
	if (synchronous_mode && !priv->quadrature_mode[channel_id]) {
		spin_unlock_irqrestore(&priv->lock, irqflags);
		return -EINVAL;
	}

	priv->synchronous_mode[channel_id] = synchronous_mode;

	/* Load Index Control configuration to Index Control Register */
	outb(QUAD8_CTR_IDR | idr_cfg, base_offset);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_count_floor_read(struct counter_device *counter,
				  struct counter_count *count, u64 *floor)
{
	/* Only a floor of 0 is supported */
	*floor = 0;

	return 0;
}

static int quad8_count_mode_read(struct counter_device *counter,
				 struct counter_count *count,
				 enum counter_count_mode *cnt_mode)
{
	const struct quad8 *const priv = counter->priv;

	/* Map 104-QUAD-8 count mode to Generic Counter count mode */
	switch (priv->count_mode[count->id]) {
	case 0:
		*cnt_mode = COUNTER_COUNT_MODE_NORMAL;
		break;
	case 1:
		*cnt_mode = COUNTER_COUNT_MODE_RANGE_LIMIT;
		break;
	case 2:
		*cnt_mode = COUNTER_COUNT_MODE_NON_RECYCLE;
		break;
	case 3:
		*cnt_mode = COUNTER_COUNT_MODE_MODULO_N;
		break;
	}

	return 0;
}

static int quad8_count_mode_write(struct counter_device *counter,
				  struct counter_count *count,
				  enum counter_count_mode cnt_mode)
{
	struct quad8 *const priv = counter->priv;
	unsigned int count_mode;
	unsigned int mode_cfg;
	const int base_offset = priv->base + 2 * count->id + 1;
	unsigned long irqflags;

	/* Map Generic Counter count mode to 104-QUAD-8 count mode */
	switch (cnt_mode) {
	case COUNTER_COUNT_MODE_NORMAL:
		count_mode = 0;
		break;
	case COUNTER_COUNT_MODE_RANGE_LIMIT:
		count_mode = 1;
		break;
	case COUNTER_COUNT_MODE_NON_RECYCLE:
		count_mode = 2;
		break;
	case COUNTER_COUNT_MODE_MODULO_N:
		count_mode = 3;
		break;
	default:
		/* should never reach this path */
		return -EINVAL;
	}

	spin_lock_irqsave(&priv->lock, irqflags);

	priv->count_mode[count->id] = count_mode;

	/* Set count mode configuration value */
	mode_cfg = count_mode << 1;

	/* Add quadrature mode configuration */
	if (priv->quadrature_mode[count->id])
		mode_cfg |= (priv->quadrature_scale[count->id] + 1) << 3;

	/* Load mode configuration to Counter Mode Register */
	outb(QUAD8_CTR_CMR | mode_cfg, base_offset);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_count_enable_read(struct counter_device *counter,
				   struct counter_count *count, u8 *enable)
{
	const struct quad8 *const priv = counter->priv;

	*enable = priv->ab_enable[count->id];

	return 0;
}

static int quad8_count_enable_write(struct counter_device *counter,
				    struct counter_count *count, u8 enable)
{
	struct quad8 *const priv = counter->priv;
	const int base_offset = priv->base + 2 * count->id;
	unsigned long irqflags;
	unsigned int ior_cfg;

	spin_lock_irqsave(&priv->lock, irqflags);

	priv->ab_enable[count->id] = enable;

	ior_cfg = enable | priv->preset_enable[count->id] << 1 |
		  priv->irq_trigger[count->id] << 3;

	/* Load I/O control configuration */
	outb(QUAD8_CTR_IOR | ior_cfg, base_offset + 1);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static const char *const quad8_noise_error_states[] = {
	"No excessive noise is present at the count inputs",
	"Excessive noise is present at the count inputs"
};

static int quad8_error_noise_get(struct counter_device *counter,
				 struct counter_count *count, u32 *noise_error)
{
	const struct quad8 *const priv = counter->priv;
	const int base_offset = priv->base + 2 * count->id + 1;

	*noise_error = !!(inb(base_offset) & QUAD8_FLAG_E);

	return 0;
}

static int quad8_count_preset_read(struct counter_device *counter,
				   struct counter_count *count, u64 *preset)
{
	const struct quad8 *const priv = counter->priv;

	*preset = priv->preset[count->id];

	return 0;
}

static void quad8_preset_register_set(struct quad8 *const priv, const int id,
				      const unsigned int preset)
{
	const unsigned int base_offset = priv->base + 2 * id;
	int i;

	priv->preset[id] = preset;

	/* Reset Byte Pointer */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP, base_offset + 1);

	/* Set Preset Register */
	for (i = 0; i < 3; i++)
		outb(preset >> (8 * i), base_offset);
}

static int quad8_count_preset_write(struct counter_device *counter,
				    struct counter_count *count, u64 preset)
{
	struct quad8 *const priv = counter->priv;
	unsigned long irqflags;

	/* Only 24-bit values are supported */
	if (preset > 0xFFFFFF)
		return -ERANGE;

	spin_lock_irqsave(&priv->lock, irqflags);

	quad8_preset_register_set(priv, count->id, preset);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_count_ceiling_read(struct counter_device *counter,
				    struct counter_count *count, u64 *ceiling)
{
	struct quad8 *const priv = counter->priv;
	unsigned long irqflags;

	spin_lock_irqsave(&priv->lock, irqflags);

	/* Range Limit and Modulo-N count modes use preset value as ceiling */
	switch (priv->count_mode[count->id]) {
	case 1:
	case 3:
		*ceiling = priv->preset[count->id];
		break;
	default:
		/* By default 0x1FFFFFF (25 bits unsigned) is maximum count */
		*ceiling = 0x1FFFFFF;
		break;
	}

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_count_ceiling_write(struct counter_device *counter,
				     struct counter_count *count, u64 ceiling)
{
	struct quad8 *const priv = counter->priv;
	unsigned long irqflags;

	/* Only 24-bit values are supported */
	if (ceiling > 0xFFFFFF)
		return -ERANGE;

	spin_lock_irqsave(&priv->lock, irqflags);

	/* Range Limit and Modulo-N count modes use preset value as ceiling */
	switch (priv->count_mode[count->id]) {
	case 1:
	case 3:
		quad8_preset_register_set(priv, count->id, ceiling);
		spin_unlock_irqrestore(&priv->lock, irqflags);
		return 0;
	}

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return -EINVAL;
}

static int quad8_count_preset_enable_read(struct counter_device *counter,
					  struct counter_count *count,
					  u8 *preset_enable)
{
	const struct quad8 *const priv = counter->priv;

	*preset_enable = !priv->preset_enable[count->id];

	return 0;
}

static int quad8_count_preset_enable_write(struct counter_device *counter,
					   struct counter_count *count,
					   u8 preset_enable)
{
	struct quad8 *const priv = counter->priv;
	const int base_offset = priv->base + 2 * count->id + 1;
	unsigned long irqflags;
	unsigned int ior_cfg;

	/* Preset enable is active low in Input/Output Control register */
	preset_enable = !preset_enable;

	spin_lock_irqsave(&priv->lock, irqflags);

	priv->preset_enable[count->id] = preset_enable;

	ior_cfg = priv->ab_enable[count->id] | preset_enable << 1 |
		  priv->irq_trigger[count->id] << 3;

	/* Load I/O control configuration to Input / Output Control Register */
	outb(QUAD8_CTR_IOR | ior_cfg, base_offset);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_signal_cable_fault_read(struct counter_device *counter,
					 struct counter_signal *signal,
					 u8 *cable_fault)
{
	struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id / 2;
	unsigned long irqflags;
	bool disabled;
	unsigned int status;

	spin_lock_irqsave(&priv->lock, irqflags);

	disabled = !(priv->cable_fault_enable & BIT(channel_id));

	if (disabled) {
		spin_unlock_irqrestore(&priv->lock, irqflags);
		return -EINVAL;
	}

	/* Logic 0 = cable fault */
	status = inb(priv->base + QUAD8_DIFF_ENCODER_CABLE_STATUS);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	/* Mask respective channel and invert logic */
	*cable_fault = !(status & BIT(channel_id));

	return 0;
}

static int quad8_signal_cable_fault_enable_read(struct counter_device *counter,
						struct counter_signal *signal,
						u8 *enable)
{
	const struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id / 2;

	*enable = !!(priv->cable_fault_enable & BIT(channel_id));

	return 0;
}

static int quad8_signal_cable_fault_enable_write(struct counter_device *counter,
						 struct counter_signal *signal,
						 u8 enable)
{
	struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id / 2;
	unsigned long irqflags;
	unsigned int cable_fault_enable;

	spin_lock_irqsave(&priv->lock, irqflags);

	if (enable)
		priv->cable_fault_enable |= BIT(channel_id);
	else
		priv->cable_fault_enable &= ~BIT(channel_id);

	/* Enable is active low in Differential Encoder Cable Status register */
	cable_fault_enable = ~priv->cable_fault_enable;

	outb(cable_fault_enable, priv->base + QUAD8_DIFF_ENCODER_CABLE_STATUS);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static int quad8_signal_fck_prescaler_read(struct counter_device *counter,
					   struct counter_signal *signal,
					   u8 *prescaler)
{
	const struct quad8 *const priv = counter->priv;

	*prescaler = priv->fck_prescaler[signal->id / 2];

	return 0;
}

static int quad8_signal_fck_prescaler_write(struct counter_device *counter,
					    struct counter_signal *signal,
					    u8 prescaler)
{
	struct quad8 *const priv = counter->priv;
	const size_t channel_id = signal->id / 2;
	const int base_offset = priv->base + 2 * channel_id;
	unsigned long irqflags;

	spin_lock_irqsave(&priv->lock, irqflags);

	priv->fck_prescaler[channel_id] = prescaler;

	/* Reset Byte Pointer */
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP, base_offset + 1);

	/* Set filter clock factor */
	outb(prescaler, base_offset);
	outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP | QUAD8_RLD_PRESET_PSC,
	     base_offset + 1);

	spin_unlock_irqrestore(&priv->lock, irqflags);

	return 0;
}

static struct counter_comp quad8_signal_ext[] = {
	COUNTER_COMP_SIGNAL_BOOL("cable_fault", quad8_signal_cable_fault_read,
				 NULL),
	COUNTER_COMP_SIGNAL_BOOL("cable_fault_enable",
				 quad8_signal_cable_fault_enable_read,
				 quad8_signal_cable_fault_enable_write),
	COUNTER_COMP_SIGNAL_U8("filter_clock_prescaler",
			       quad8_signal_fck_prescaler_read,
			       quad8_signal_fck_prescaler_write)
};

static DEFINE_COUNTER_ENUM(quad8_index_pol_enum, quad8_index_polarity_modes);
static DEFINE_COUNTER_ENUM(quad8_synch_mode_enum, quad8_synchronous_modes);

static struct counter_comp quad8_index_ext[] = {
	COUNTER_COMP_SIGNAL_ENUM("index_polarity", quad8_index_polarity_get,
				 quad8_index_polarity_set,
				 quad8_index_pol_enum),
	COUNTER_COMP_SIGNAL_ENUM("synchronous_mode", quad8_synchronous_mode_get,
				 quad8_synchronous_mode_set,
				 quad8_synch_mode_enum),
};

#define QUAD8_QUAD_SIGNAL(_id, _name) {		\
	.id = (_id),				\
	.name = (_name),			\
	.ext = quad8_signal_ext,		\
	.num_ext = ARRAY_SIZE(quad8_signal_ext)	\
}

#define	QUAD8_INDEX_SIGNAL(_id, _name) {	\
	.id = (_id),				\
	.name = (_name),			\
	.ext = quad8_index_ext,			\
	.num_ext = ARRAY_SIZE(quad8_index_ext)	\
}

static struct counter_signal quad8_signals[] = {
	QUAD8_QUAD_SIGNAL(0, "Channel 1 Quadrature A"),
	QUAD8_QUAD_SIGNAL(1, "Channel 1 Quadrature B"),
	QUAD8_QUAD_SIGNAL(2, "Channel 2 Quadrature A"),
	QUAD8_QUAD_SIGNAL(3, "Channel 2 Quadrature B"),
	QUAD8_QUAD_SIGNAL(4, "Channel 3 Quadrature A"),
	QUAD8_QUAD_SIGNAL(5, "Channel 3 Quadrature B"),
	QUAD8_QUAD_SIGNAL(6, "Channel 4 Quadrature A"),
	QUAD8_QUAD_SIGNAL(7, "Channel 4 Quadrature B"),
	QUAD8_QUAD_SIGNAL(8, "Channel 5 Quadrature A"),
	QUAD8_QUAD_SIGNAL(9, "Channel 5 Quadrature B"),
	QUAD8_QUAD_SIGNAL(10, "Channel 6 Quadrature A"),
	QUAD8_QUAD_SIGNAL(11, "Channel 6 Quadrature B"),
	QUAD8_QUAD_SIGNAL(12, "Channel 7 Quadrature A"),
	QUAD8_QUAD_SIGNAL(13, "Channel 7 Quadrature B"),
	QUAD8_QUAD_SIGNAL(14, "Channel 8 Quadrature A"),
	QUAD8_QUAD_SIGNAL(15, "Channel 8 Quadrature B"),
	QUAD8_INDEX_SIGNAL(16, "Channel 1 Index"),
	QUAD8_INDEX_SIGNAL(17, "Channel 2 Index"),
	QUAD8_INDEX_SIGNAL(18, "Channel 3 Index"),
	QUAD8_INDEX_SIGNAL(19, "Channel 4 Index"),
	QUAD8_INDEX_SIGNAL(20, "Channel 5 Index"),
	QUAD8_INDEX_SIGNAL(21, "Channel 6 Index"),
	QUAD8_INDEX_SIGNAL(22, "Channel 7 Index"),
	QUAD8_INDEX_SIGNAL(23, "Channel 8 Index")
};

#define QUAD8_COUNT_SYNAPSES(_id) {					\
	{								\
		.actions_list = quad8_synapse_actions_list,		\
		.num_actions = ARRAY_SIZE(quad8_synapse_actions_list),	\
		.signal = quad8_signals + 2 * (_id)			\
	},								\
	{								\
		.actions_list = quad8_synapse_actions_list,		\
		.num_actions = ARRAY_SIZE(quad8_synapse_actions_list),	\
		.signal = quad8_signals + 2 * (_id) + 1			\
	},								\
	{								\
		.actions_list = quad8_index_actions_list,		\
		.num_actions = ARRAY_SIZE(quad8_index_actions_list),	\
		.signal = quad8_signals + 2 * (_id) + 16		\
	}								\
}

static struct counter_synapse quad8_count_synapses[][3] = {
	QUAD8_COUNT_SYNAPSES(0), QUAD8_COUNT_SYNAPSES(1),
	QUAD8_COUNT_SYNAPSES(2), QUAD8_COUNT_SYNAPSES(3),
	QUAD8_COUNT_SYNAPSES(4), QUAD8_COUNT_SYNAPSES(5),
	QUAD8_COUNT_SYNAPSES(6), QUAD8_COUNT_SYNAPSES(7)
};

static const enum counter_count_mode quad8_cnt_modes[] = {
	COUNTER_COUNT_MODE_NORMAL,
	COUNTER_COUNT_MODE_RANGE_LIMIT,
	COUNTER_COUNT_MODE_NON_RECYCLE,
	COUNTER_COUNT_MODE_MODULO_N,
};

static DEFINE_COUNTER_AVAILABLE(quad8_count_mode_available, quad8_cnt_modes);

static DEFINE_COUNTER_ENUM(quad8_error_noise_enum, quad8_noise_error_states);

static struct counter_comp quad8_count_ext[] = {
	COUNTER_COMP_CEILING(quad8_count_ceiling_read,
			     quad8_count_ceiling_write),
	COUNTER_COMP_FLOOR(quad8_count_floor_read, NULL),
	COUNTER_COMP_COUNT_MODE(quad8_count_mode_read, quad8_count_mode_write,
				quad8_count_mode_available),
	COUNTER_COMP_DIRECTION(quad8_direction_read),
	COUNTER_COMP_ENABLE(quad8_count_enable_read, quad8_count_enable_write),
	COUNTER_COMP_COUNT_ENUM("error_noise", quad8_error_noise_get, NULL,
				quad8_error_noise_enum),
	COUNTER_COMP_PRESET(quad8_count_preset_read, quad8_count_preset_write),
	COUNTER_COMP_PRESET_ENABLE(quad8_count_preset_enable_read,
				   quad8_count_preset_enable_write),
};

#define QUAD8_COUNT(_id, _cntname) {					\
	.id = (_id),							\
	.name = (_cntname),						\
	.functions_list = quad8_count_functions_list,			\
	.num_functions = ARRAY_SIZE(quad8_count_functions_list),	\
	.synapses = quad8_count_synapses[(_id)],			\
	.num_synapses =	2,						\
	.ext = quad8_count_ext,						\
	.num_ext = ARRAY_SIZE(quad8_count_ext)				\
}

static struct counter_count quad8_counts[] = {
	QUAD8_COUNT(0, "Channel 1 Count"),
	QUAD8_COUNT(1, "Channel 2 Count"),
	QUAD8_COUNT(2, "Channel 3 Count"),
	QUAD8_COUNT(3, "Channel 4 Count"),
	QUAD8_COUNT(4, "Channel 5 Count"),
	QUAD8_COUNT(5, "Channel 6 Count"),
	QUAD8_COUNT(6, "Channel 7 Count"),
	QUAD8_COUNT(7, "Channel 8 Count")
};

static irqreturn_t quad8_irq_handler(int irq, void *private)
{
	struct quad8 *const priv = private;
	const unsigned long base = priv->base;
	unsigned long irq_status;
	unsigned long channel;
	u8 event;

	irq_status = inb(base + QUAD8_REG_INTERRUPT_STATUS);
	if (!irq_status)
		return IRQ_NONE;

	for_each_set_bit(channel, &irq_status, QUAD8_NUM_COUNTERS) {
		switch (priv->irq_trigger[channel]) {
		case QUAD8_EVENT_CARRY:
			event = COUNTER_EVENT_OVERFLOW;
				break;
		case QUAD8_EVENT_COMPARE:
			event = COUNTER_EVENT_THRESHOLD;
				break;
		case QUAD8_EVENT_CARRY_BORROW:
			event = COUNTER_EVENT_OVERFLOW_UNDERFLOW;
				break;
		case QUAD8_EVENT_INDEX:
			event = COUNTER_EVENT_INDEX;
				break;
		default:
			/* should never reach this path */
			WARN_ONCE(true, "invalid interrupt trigger function %u configured for channel %lu\n",
				  priv->irq_trigger[channel], channel);
			continue;
		}

		counter_push_event(&priv->counter, event, channel);
	}

	/* Clear pending interrupts on device */
	outb(QUAD8_CHAN_OP_ENABLE_INTERRUPT_FUNC, base + QUAD8_REG_CHAN_OP);

	return IRQ_HANDLED;
}

static int quad8_probe(struct device *dev, unsigned int id)
{
	struct quad8 *priv;
	int i, j;
	unsigned int base_offset;
	int err;

	if (!devm_request_region(dev, base[id], QUAD8_EXTENT, dev_name(dev))) {
		dev_err(dev, "Unable to lock port addresses (0x%X-0x%X)\n",
			base[id], base[id] + QUAD8_EXTENT);
		return -EBUSY;
	}

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/* Initialize Counter device and driver data */
	priv->counter.name = dev_name(dev);
	priv->counter.parent = dev;
	priv->counter.ops = &quad8_ops;
	priv->counter.counts = quad8_counts;
	priv->counter.num_counts = ARRAY_SIZE(quad8_counts);
	priv->counter.signals = quad8_signals;
	priv->counter.num_signals = ARRAY_SIZE(quad8_signals);
	priv->counter.priv = priv;
	priv->base = base[id];

	spin_lock_init(&priv->lock);

	/* Reset Index/Interrupt Register */
	outb(0x00, base[id] + QUAD8_REG_INDEX_INTERRUPT);
	/* Reset all counters and disable interrupt function */
	outb(QUAD8_CHAN_OP_RESET_COUNTERS, base[id] + QUAD8_REG_CHAN_OP);
	/* Set initial configuration for all counters */
	for (i = 0; i < QUAD8_NUM_COUNTERS; i++) {
		base_offset = base[id] + 2 * i;
		/* Reset Byte Pointer */
		outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP, base_offset + 1);
		/* Reset filter clock factor */
		outb(0, base_offset);
		outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP | QUAD8_RLD_PRESET_PSC,
		     base_offset + 1);
		/* Reset Byte Pointer */
		outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_BP, base_offset + 1);
		/* Reset Preset Register */
		for (j = 0; j < 3; j++)
			outb(0x00, base_offset);
		/* Reset Borrow, Carry, Compare, and Sign flags */
		outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_FLAGS, base_offset + 1);
		/* Reset Error flag */
		outb(QUAD8_CTR_RLD | QUAD8_RLD_RESET_E, base_offset + 1);
		/* Binary encoding; Normal count; non-quadrature mode */
		outb(QUAD8_CTR_CMR, base_offset + 1);
		/* Disable A and B inputs; preset on index; FLG1 as Carry */
		outb(QUAD8_CTR_IOR, base_offset + 1);
		/* Disable index function; negative index polarity */
		outb(QUAD8_CTR_IDR, base_offset + 1);
	}
	/* Disable Differential Encoder Cable Status for all channels */
	outb(0xFF, base[id] + QUAD8_DIFF_ENCODER_CABLE_STATUS);
	/* Enable all counters and enable interrupt function */
	outb(QUAD8_CHAN_OP_ENABLE_INTERRUPT_FUNC, base[id] + QUAD8_REG_CHAN_OP);

	err = devm_request_irq(dev, irq[id], quad8_irq_handler, IRQF_SHARED,
			       priv->counter.name, priv);
	if (err)
		return err;

	return devm_counter_register(dev, &priv->counter);
}

static struct isa_driver quad8_driver = {
	.probe = quad8_probe,
	.driver = {
		.name = "104-quad-8"
	}
};

module_isa_driver(quad8_driver, num_quad8);

MODULE_AUTHOR("William Breathitt Gray <vilhelm.gray@gmail.com>");
MODULE_DESCRIPTION("ACCES 104-QUAD-8 driver");
MODULE_LICENSE("GPL v2");
