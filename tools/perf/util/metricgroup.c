// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017, Intel Corporation.
 */

/* Manage metrics and groups of metrics from JSON files */

#include "metricgroup.h"
#include "debug.h"
#include "evlist.h"
#include "evsel.h"
#include "strbuf.h"
#include "pmu.h"
#include "pmu-hybrid.h"
#include "expr.h"
#include "rblist.h"
#include <string.h>
#include <errno.h>
#include "strlist.h"
#include <assert.h>
#include <linux/ctype.h>
#include <linux/list_sort.h>
#include <linux/string.h>
#include <linux/zalloc.h>
#include <subcmd/parse-options.h>
#include <api/fs/fs.h>
#include "util.h"
#include <asm/bug.h>
#include "cgroup.h"

struct metric_event *metricgroup__lookup(struct rblist *metric_events,
					 struct evsel *evsel,
					 bool create)
{
	struct rb_node *nd;
	struct metric_event me = {
		.evsel = evsel
	};

	if (!metric_events)
		return NULL;

	nd = rblist__find(metric_events, &me);
	if (nd)
		return container_of(nd, struct metric_event, nd);
	if (create) {
		rblist__add_node(metric_events, &me);
		nd = rblist__find(metric_events, &me);
		if (nd)
			return container_of(nd, struct metric_event, nd);
	}
	return NULL;
}

static int metric_event_cmp(struct rb_node *rb_node, const void *entry)
{
	struct metric_event *a = container_of(rb_node,
					      struct metric_event,
					      nd);
	const struct metric_event *b = entry;

	if (a->evsel == b->evsel)
		return 0;
	if ((char *)a->evsel < (char *)b->evsel)
		return -1;
	return +1;
}

static struct rb_node *metric_event_new(struct rblist *rblist __maybe_unused,
					const void *entry)
{
	struct metric_event *me = malloc(sizeof(struct metric_event));

	if (!me)
		return NULL;
	memcpy(me, entry, sizeof(struct metric_event));
	me->evsel = ((struct metric_event *)entry)->evsel;
	INIT_LIST_HEAD(&me->head);
	return &me->nd;
}

static void metric_event_delete(struct rblist *rblist __maybe_unused,
				struct rb_node *rb_node)
{
	struct metric_event *me = container_of(rb_node, struct metric_event, nd);
	struct metric_expr *expr, *tmp;

	list_for_each_entry_safe(expr, tmp, &me->head, nd) {
		free((char *)expr->metric_name);
		free(expr->metric_refs);
		free(expr->metric_events);
		free(expr);
	}

	free(me);
}

static void metricgroup__rblist_init(struct rblist *metric_events)
{
	rblist__init(metric_events);
	metric_events->node_cmp = metric_event_cmp;
	metric_events->node_new = metric_event_new;
	metric_events->node_delete = metric_event_delete;
}

void metricgroup__rblist_exit(struct rblist *metric_events)
{
	rblist__exit(metric_events);
}

/*
 * A node in the list of referenced metrics. metric_expr
 * is held as a convenience to avoid a search through the
 * metric list.
 */
struct metric_ref_node {
	const char *metric_name;
	const char *metric_expr;
	struct list_head list;
};

/**
 * The metric under construction. The data held here will be placed in a
 * metric_expr.
 */
struct metric {
	struct list_head nd;
	/**
	 * The expression parse context importantly holding the IDs contained
	 * within the expression.
	 */
	struct expr_parse_ctx *pctx;
	/** The name of the metric such as "IPC". */
	const char *metric_name;
	/** Modifier on the metric such as "u" or NULL for none. */
	const char *modifier;
	/** The expression to parse, for example, "instructions/cycles". */
	const char *metric_expr;
	/**
	 * The "ScaleUnit" that scales and adds a unit to the metric during
	 * output.
	 */
	const char *metric_unit;
	/** Optional null terminated array of referenced metrics. */
	struct metric_ref *metric_refs;
	/**
	 * Is there a constraint on the group of events? In which case the
	 * events won't be grouped.
	 */
	bool has_constraint;
	/**
	 * Parsed events for the metric. Optional as events may be taken from a
	 * different metric whose group contains all the IDs necessary for this
	 * one.
	 */
	struct evlist *evlist;
};

static void metricgroup___watchdog_constraint_hint(const char *name, bool foot)
{
	static bool violate_nmi_constraint;

	if (!foot) {
		pr_warning("Splitting metric group %s into standalone metrics.\n", name);
		violate_nmi_constraint = true;
		return;
	}

	if (!violate_nmi_constraint)
		return;

	pr_warning("Try disabling the NMI watchdog to comply NO_NMI_WATCHDOG metric constraint:\n"
		   "    echo 0 > /proc/sys/kernel/nmi_watchdog\n"
		   "    perf stat ...\n"
		   "    echo 1 > /proc/sys/kernel/nmi_watchdog\n");
}

static bool metricgroup__has_constraint(const struct pmu_event *pe)
{
	if (!pe->metric_constraint)
		return false;

	if (!strcmp(pe->metric_constraint, "NO_NMI_WATCHDOG") &&
	    sysctl__nmi_watchdog_enabled()) {
		metricgroup___watchdog_constraint_hint(pe->metric_name, false);
		return true;
	}

	return false;
}

static struct metric *metric__new(const struct pmu_event *pe,
				  const char *modifier,
				  bool metric_no_group,
				  int runtime)
{
	struct metric *m;

	m = zalloc(sizeof(*m));
	if (!m)
		return NULL;

	m->pctx = expr__ctx_new();
	if (!m->pctx) {
		free(m);
		return NULL;
	}

	m->metric_name = pe->metric_name;
	m->modifier = modifier ? strdup(modifier) : NULL;
	if (modifier && !m->modifier) {
		expr__ctx_free(m->pctx);
		free(m);
		return NULL;
	}
	m->metric_expr = pe->metric_expr;
	m->metric_unit = pe->unit;
	m->pctx->runtime = runtime;
	m->has_constraint = metric_no_group || metricgroup__has_constraint(pe);
	m->metric_refs = NULL;
	m->evlist = NULL;

	return m;
}

static void metric__free(struct metric *m)
{
	free(m->metric_refs);
	expr__ctx_free(m->pctx);
	free((char *)m->modifier);
	evlist__delete(m->evlist);
	free(m);
}

static bool contains_metric_id(struct evsel **metric_events, int num_events,
			       const char *metric_id)
{
	int i;

	for (i = 0; i < num_events; i++) {
		if (!strcmp(evsel__metric_id(metric_events[i]), metric_id))
			return true;
	}
	return false;
}

/**
 * setup_metric_events - Find a group of events in metric_evlist that correspond
 *                       to the IDs from a parsed metric expression.
 * @ids: the metric IDs to match.
 * @metric_evlist: the list of perf events.
 * @out_metric_events: holds the created metric events array.
 */
static int setup_metric_events(struct hashmap *ids,
			       struct evlist *metric_evlist,
			       struct evsel ***out_metric_events)
{
	struct evsel **metric_events;
	const char *metric_id;
	struct evsel *ev;
	size_t ids_size, matched_events, i;

	*out_metric_events = NULL;
	ids_size = hashmap__size(ids);

	metric_events = calloc(sizeof(void *), ids_size + 1);
	if (!metric_events)
		return -ENOMEM;

	matched_events = 0;
	evlist__for_each_entry(metric_evlist, ev) {
		struct expr_id_data *val_ptr;

		/*
		 * Check for duplicate events with the same name. For
		 * example, uncore_imc/cas_count_read/ will turn into 6
		 * events per socket on skylakex. Only the first such
		 * event is placed in metric_events.
		 */
		metric_id = evsel__metric_id(ev);
		if (contains_metric_id(metric_events, matched_events, metric_id))
			continue;
		/*
		 * Does this event belong to the parse context? For
		 * combined or shared groups, this metric may not care
		 * about this event.
		 */
		if (hashmap__find(ids, metric_id, (void **)&val_ptr)) {
			metric_events[matched_events++] = ev;

			if (matched_events >= ids_size)
				break;
		}
	}
	if (matched_events < ids_size) {
		free(metric_events);
		return -EINVAL;
	}
	for (i = 0; i < ids_size; i++) {
		ev = metric_events[i];
		ev->collect_stat = true;

		/*
		 * The metric leader points to the identically named
		 * event in metric_events.
		 */
		ev->metric_leader = ev;
		/*
		 * Mark two events with identical names in the same
		 * group (or globally) as being in use as uncore events
		 * may be duplicated for each pmu. Set the metric leader
		 * of such events to be the event that appears in
		 * metric_events.
		 */
		metric_id = evsel__metric_id(ev);
		evlist__for_each_entry_continue(metric_evlist, ev) {
			if (!strcmp(evsel__metric_id(ev), metric_id))
				ev->metric_leader = metric_events[i];
		}
	}
	*out_metric_events = metric_events;
	return 0;
}

static bool match_metric(const char *n, const char *list)
{
	int len;
	char *m;

	if (!list)
		return false;
	if (!strcmp(list, "all"))
		return true;
	if (!n)
		return !strcasecmp(list, "No_group");
	len = strlen(list);
	m = strcasestr(n, list);
	if (!m)
		return false;
	if ((m == n || m[-1] == ';' || m[-1] == ' ') &&
	    (m[len] == 0 || m[len] == ';'))
		return true;
	return false;
}

static bool match_pe_metric(const struct pmu_event *pe, const char *metric)
{
	return match_metric(pe->metric_group, metric) ||
	       match_metric(pe->metric_name, metric);
}

struct mep {
	struct rb_node nd;
	const char *name;
	struct strlist *metrics;
};

static int mep_cmp(struct rb_node *rb_node, const void *entry)
{
	struct mep *a = container_of(rb_node, struct mep, nd);
	struct mep *b = (struct mep *)entry;

	return strcmp(a->name, b->name);
}

static struct rb_node *mep_new(struct rblist *rl __maybe_unused,
					const void *entry)
{
	struct mep *me = malloc(sizeof(struct mep));

	if (!me)
		return NULL;
	memcpy(me, entry, sizeof(struct mep));
	me->name = strdup(me->name);
	if (!me->name)
		goto out_me;
	me->metrics = strlist__new(NULL, NULL);
	if (!me->metrics)
		goto out_name;
	return &me->nd;
out_name:
	zfree(&me->name);
out_me:
	free(me);
	return NULL;
}

static struct mep *mep_lookup(struct rblist *groups, const char *name)
{
	struct rb_node *nd;
	struct mep me = {
		.name = name
	};
	nd = rblist__find(groups, &me);
	if (nd)
		return container_of(nd, struct mep, nd);
	rblist__add_node(groups, &me);
	nd = rblist__find(groups, &me);
	if (nd)
		return container_of(nd, struct mep, nd);
	return NULL;
}

static void mep_delete(struct rblist *rl __maybe_unused,
		       struct rb_node *nd)
{
	struct mep *me = container_of(nd, struct mep, nd);

	strlist__delete(me->metrics);
	zfree(&me->name);
	free(me);
}

static void metricgroup__print_strlist(struct strlist *metrics, bool raw)
{
	struct str_node *sn;
	int n = 0;

	strlist__for_each_entry (sn, metrics) {
		if (raw)
			printf("%s%s", n > 0 ? " " : "", sn->s);
		else
			printf("  %s\n", sn->s);
		n++;
	}
	if (raw)
		putchar('\n');
}

static int metricgroup__print_pmu_event(const struct pmu_event *pe,
					bool metricgroups, char *filter,
					bool raw, bool details,
					struct rblist *groups,
					struct strlist *metriclist)
{
	const char *g;
	char *omg, *mg;

	g = pe->metric_group;
	if (!g && pe->metric_name) {
		if (pe->name)
			return 0;
		g = "No_group";
	}

	if (!g)
		return 0;

	mg = strdup(g);

	if (!mg)
		return -ENOMEM;
	omg = mg;
	while ((g = strsep(&mg, ";")) != NULL) {
		struct mep *me;
		char *s;

		g = skip_spaces(g);
		if (*g == 0)
			g = "No_group";
		if (filter && !strstr(g, filter))
			continue;
		if (raw)
			s = (char *)pe->metric_name;
		else {
			if (asprintf(&s, "%s\n%*s%s]",
				     pe->metric_name, 8, "[", pe->desc) < 0)
				return -1;
			if (details) {
				if (asprintf(&s, "%s\n%*s%s]",
					     s, 8, "[", pe->metric_expr) < 0)
					return -1;
			}
		}

		if (!s)
			continue;

		if (!metricgroups) {
			strlist__add(metriclist, s);
		} else {
			me = mep_lookup(groups, g);
			if (!me)
				continue;
			strlist__add(me->metrics, s);
		}

		if (!raw)
			free(s);
	}
	free(omg);

	return 0;
}

struct metricgroup_print_sys_idata {
	struct strlist *metriclist;
	char *filter;
	struct rblist *groups;
	bool metricgroups;
	bool raw;
	bool details;
};

typedef int (*metricgroup_sys_event_iter_fn)(const struct pmu_event *pe, void *);

struct metricgroup_iter_data {
	metricgroup_sys_event_iter_fn fn;
	void *data;
};

static int metricgroup__sys_event_iter(const struct pmu_event *pe, void *data)
{
	struct metricgroup_iter_data *d = data;
	struct perf_pmu *pmu = NULL;

	if (!pe->metric_expr || !pe->compat)
		return 0;

	while ((pmu = perf_pmu__scan(pmu))) {

		if (!pmu->id || strcmp(pmu->id, pe->compat))
			continue;

		return d->fn(pe, d->data);
	}

	return 0;
}

static int metricgroup__print_sys_event_iter(const struct pmu_event *pe, void *data)
{
	struct metricgroup_print_sys_idata *d = data;

	return metricgroup__print_pmu_event(pe, d->metricgroups, d->filter, d->raw,
				     d->details, d->groups, d->metriclist);
}

void metricgroup__print(bool metrics, bool metricgroups, char *filter,
			bool raw, bool details, const char *pmu_name)
{
	const struct pmu_events_map *map = pmu_events_map__find();
	const struct pmu_event *pe;
	int i;
	struct rblist groups;
	struct rb_node *node, *next;
	struct strlist *metriclist = NULL;

	if (!metricgroups) {
		metriclist = strlist__new(NULL, NULL);
		if (!metriclist)
			return;
	}

	rblist__init(&groups);
	groups.node_new = mep_new;
	groups.node_cmp = mep_cmp;
	groups.node_delete = mep_delete;
	for (i = 0; map; i++) {
		pe = &map->table[i];

		if (!pe->name && !pe->metric_group && !pe->metric_name)
			break;
		if (!pe->metric_expr)
			continue;
		if (pmu_name && perf_pmu__is_hybrid(pe->pmu) &&
		    strcmp(pmu_name, pe->pmu)) {
			continue;
		}
		if (metricgroup__print_pmu_event(pe, metricgroups, filter,
						 raw, details, &groups,
						 metriclist) < 0)
			return;
	}

	{
		struct metricgroup_iter_data data = {
			.fn = metricgroup__print_sys_event_iter,
			.data = (void *) &(struct metricgroup_print_sys_idata){
				.metriclist = metriclist,
				.metricgroups = metricgroups,
				.filter = filter,
				.raw = raw,
				.details = details,
				.groups = &groups,
			},
		};

		pmu_for_each_sys_event(metricgroup__sys_event_iter, &data);
	}

	if (!filter || !rblist__empty(&groups)) {
		if (metricgroups && !raw)
			printf("\nMetric Groups:\n\n");
		else if (metrics && !raw)
			printf("\nMetrics:\n\n");
	}

	for (node = rb_first_cached(&groups.entries); node; node = next) {
		struct mep *me = container_of(node, struct mep, nd);

		if (metricgroups)
			printf("%s%s%s", me->name, metrics && !raw ? ":" : "", raw ? " " : "\n");
		if (metrics)
			metricgroup__print_strlist(me->metrics, raw);
		next = rb_next(node);
		rblist__remove_node(&groups, node);
	}
	if (!metricgroups)
		metricgroup__print_strlist(metriclist, raw);
	strlist__delete(metriclist);
}

static const char *code_characters = ",-=@";

static int encode_metric_id(struct strbuf *sb, const char *x)
{
	char *c;
	int ret = 0;

	for (; *x; x++) {
		c = strchr(code_characters, *x);
		if (c) {
			ret = strbuf_addch(sb, '!');
			if (ret)
				break;

			ret = strbuf_addch(sb, '0' + (c - code_characters));
			if (ret)
				break;
		} else {
			ret = strbuf_addch(sb, *x);
			if (ret)
				break;
		}
	}
	return ret;
}

static int decode_metric_id(struct strbuf *sb, const char *x)
{
	const char *orig = x;
	size_t i;
	char c;
	int ret;

	for (; *x; x++) {
		c = *x;
		if (*x == '!') {
			x++;
			i = *x - '0';
			if (i > strlen(code_characters)) {
				pr_err("Bad metric-id encoding in: '%s'", orig);
				return -1;
			}
			c = code_characters[i];
		}
		ret = strbuf_addch(sb, c);
		if (ret)
			return ret;
	}
	return 0;
}

static int decode_all_metric_ids(struct evlist *perf_evlist, const char *modifier)
{
	struct evsel *ev;
	struct strbuf sb = STRBUF_INIT;
	char *cur;
	int ret = 0;

	evlist__for_each_entry(perf_evlist, ev) {
		if (!ev->metric_id)
			continue;

		ret = strbuf_setlen(&sb, 0);
		if (ret)
			break;

		ret = decode_metric_id(&sb, ev->metric_id);
		if (ret)
			break;

		free((char *)ev->metric_id);
		ev->metric_id = strdup(sb.buf);
		if (!ev->metric_id) {
			ret = -ENOMEM;
			break;
		}
		/*
		 * If the name is just the parsed event, use the metric-id to
		 * give a more friendly display version.
		 */
		if (strstr(ev->name, "metric-id=")) {
			bool has_slash = false;

			free(ev->name);
			for (cur = strchr(sb.buf, '@') ; cur; cur = strchr(++cur, '@')) {
				*cur = '/';
				has_slash = true;
			}

			if (modifier) {
				if (!has_slash && !strchr(sb.buf, ':')) {
					ret = strbuf_addch(&sb, ':');
					if (ret)
						break;
				}
				ret = strbuf_addstr(&sb, modifier);
				if (ret)
					break;
			}
			ev->name = strdup(sb.buf);
			if (!ev->name) {
				ret = -ENOMEM;
				break;
			}
		}
	}
	strbuf_release(&sb);
	return ret;
}

static int metricgroup__build_event_string(struct strbuf *events,
					   const struct expr_parse_ctx *ctx,
					   const char *modifier,
					   bool has_constraint)
{
	struct hashmap_entry *cur;
	size_t bkt;
	bool no_group = true, has_duration = false;
	int ret = 0;

#define RETURN_IF_NON_ZERO(x) do { if (x) return x; } while (0)

	hashmap__for_each_entry(ctx->ids, cur, bkt) {
		const char *sep, *rsep, *id = cur->key;

		pr_debug("found event %s\n", id);
		/*
		 * Duration time maps to a software event and can make
		 * groups not count. Always use it outside a
		 * group.
		 */
		if (!strcmp(id, "duration_time")) {
			has_duration = true;
			continue;
		}
		/* Separate events with commas and open the group if necessary. */
		if (no_group) {
			if (!has_constraint) {
				ret = strbuf_addch(events, '{');
				RETURN_IF_NON_ZERO(ret);
			}

			no_group = false;
		} else {
			ret = strbuf_addch(events, ',');
			RETURN_IF_NON_ZERO(ret);
		}
		/*
		 * Encode the ID as an event string. Add a qualifier for
		 * metric_id that is the original name except with characters
		 * that parse-events can't parse replaced. For example,
		 * 'msr@tsc@' gets added as msr/tsc,metric-id=msr!3tsc!3/
		 */
		sep = strchr(id, '@');
		if (sep != NULL) {
			ret = strbuf_add(events, id, sep - id);
			RETURN_IF_NON_ZERO(ret);
			ret = strbuf_addch(events, '/');
			RETURN_IF_NON_ZERO(ret);
			rsep = strrchr(sep, '@');
			ret = strbuf_add(events, sep + 1, rsep - sep - 1);
			RETURN_IF_NON_ZERO(ret);
			ret = strbuf_addstr(events, ",metric-id=");
			RETURN_IF_NON_ZERO(ret);
			sep = rsep;
		} else {
			sep = strchr(id, ':');
			if (sep != NULL) {
				ret = strbuf_add(events, id, sep - id);
				RETURN_IF_NON_ZERO(ret);
			} else {
				ret = strbuf_addstr(events, id);
				RETURN_IF_NON_ZERO(ret);
			}
			ret = strbuf_addstr(events, "/metric-id=");
			RETURN_IF_NON_ZERO(ret);
		}
		ret = encode_metric_id(events, id);
		RETURN_IF_NON_ZERO(ret);
		ret = strbuf_addstr(events, "/");
		RETURN_IF_NON_ZERO(ret);

		if (sep != NULL) {
			ret = strbuf_addstr(events, sep + 1);
			RETURN_IF_NON_ZERO(ret);
		}
		if (modifier) {
			ret = strbuf_addstr(events, modifier);
			RETURN_IF_NON_ZERO(ret);
		}
	}
	if (has_duration) {
		if (no_group) {
			/* Strange case of a metric of just duration_time. */
			ret = strbuf_addf(events, "duration_time");
		} else if (!has_constraint)
			ret = strbuf_addf(events, "}:W,duration_time");
		else
			ret = strbuf_addf(events, ",duration_time");
	} else if (!no_group && !has_constraint)
		ret = strbuf_addf(events, "}:W");

	return ret;
#undef RETURN_IF_NON_ZERO
}

int __weak arch_get_runtimeparam(const struct pmu_event *pe __maybe_unused)
{
	return 1;
}

/*
 * A singly linked list on the stack of the names of metrics being
 * processed. Used to identify recursion.
 */
struct visited_metric {
	const char *name;
	const struct visited_metric *parent;
};

struct metricgroup_add_iter_data {
	struct list_head *metric_list;
	const char *metric_name;
	const char *modifier;
	int *ret;
	bool *has_match;
	bool metric_no_group;
	struct metric *root_metric;
	const struct visited_metric *visited;
	const struct pmu_events_map *map;
};

static int add_metric(struct list_head *metric_list,
		      const struct pmu_event *pe,
		      const char *modifier,
		      bool metric_no_group,
		      struct metric *root_metric,
		      const struct visited_metric *visited,
		      const struct pmu_events_map *map);

/**
 * resolve_metric - Locate metrics within the root metric and recursively add
 *                    references to them.
 * @metric_list: The list the metric is added to.
 * @modifier: if non-null event modifiers like "u".
 * @metric_no_group: Should events written to events be grouped "{}" or
 *                   global. Grouping is the default but due to multiplexing the
 *                   user may override.
 * @root_metric: Metrics may reference other metrics to form a tree. In this
 *               case the root_metric holds all the IDs and a list of referenced
 *               metrics. When adding a root this argument is NULL.
 * @visited: A singly linked list of metric names being added that is used to
 *           detect recursion.
 * @map: The map that is searched for metrics, most commonly the table for the
 *       architecture perf is running upon.
 */
static int resolve_metric(struct list_head *metric_list,
			  const char *modifier,
			  bool metric_no_group,
			  struct metric *root_metric,
			  const struct visited_metric *visited,
			  const struct pmu_events_map *map)
{
	struct hashmap_entry *cur;
	size_t bkt;
	struct to_resolve {
		/* The metric to resolve. */
		const struct pmu_event *pe;
		/*
		 * The key in the IDs map, this may differ from in case,
		 * etc. from pe->metric_name.
		 */
		const char *key;
	} *pending = NULL;
	int i, ret = 0, pending_cnt = 0;

	/*
	 * Iterate all the parsed IDs and if there's a matching metric and it to
	 * the pending array.
	 */
	hashmap__for_each_entry(root_metric->pctx->ids, cur, bkt) {
		const struct pmu_event *pe;

		pe = metricgroup__find_metric(cur->key, map);
		if (pe) {
			pending = realloc(pending,
					(pending_cnt + 1) * sizeof(struct to_resolve));
			if (!pending)
				return -ENOMEM;

			pending[pending_cnt].pe = pe;
			pending[pending_cnt].key = cur->key;
			pending_cnt++;
		}
	}

	/* Remove the metric IDs from the context. */
	for (i = 0; i < pending_cnt; i++)
		expr__del_id(root_metric->pctx, pending[i].key);

	/*
	 * Recursively add all the metrics, IDs are added to the root metric's
	 * context.
	 */
	for (i = 0; i < pending_cnt; i++) {
		ret = add_metric(metric_list, pending[i].pe, modifier, metric_no_group,
				root_metric, visited, map);
		if (ret)
			break;
	}

	free(pending);
	return ret;
}

/**
 * __add_metric - Add a metric to metric_list.
 * @metric_list: The list the metric is added to.
 * @pe: The pmu_event containing the metric to be added.
 * @modifier: if non-null event modifiers like "u".
 * @metric_no_group: Should events written to events be grouped "{}" or
 *                   global. Grouping is the default but due to multiplexing the
 *                   user may override.
 * @runtime: A special argument for the parser only known at runtime.
 * @root_metric: Metrics may reference other metrics to form a tree. In this
 *               case the root_metric holds all the IDs and a list of referenced
 *               metrics. When adding a root this argument is NULL.
 * @visited: A singly linked list of metric names being added that is used to
 *           detect recursion.
 * @map: The map that is searched for metrics, most commonly the table for the
 *       architecture perf is running upon.
 */
static int __add_metric(struct list_head *metric_list,
			const struct pmu_event *pe,
			const char *modifier,
			bool metric_no_group,
			int runtime,
			struct metric *root_metric,
			const struct visited_metric *visited,
			const struct pmu_events_map *map)
{
	const struct visited_metric *vm;
	int ret;
	bool is_root = !root_metric;
	struct visited_metric visited_node = {
		.name = pe->metric_name,
		.parent = visited,
	};

	for (vm = visited; vm; vm = vm->parent) {
		if (!strcmp(pe->metric_name, vm->name)) {
			pr_err("failed: recursion detected for %s\n", pe->metric_name);
			return -1;
		}
	}

	if (is_root) {
		/*
		 * This metric is the root of a tree and may reference other
		 * metrics that are added recursively.
		 */
		root_metric = metric__new(pe, modifier, metric_no_group, runtime);
		if (!root_metric)
			return -ENOMEM;

	} else {
		int cnt = 0;

		/*
		 * This metric was referenced in a metric higher in the
		 * tree. Check if the same metric is already resolved in the
		 * metric_refs list.
		 */
		if (root_metric->metric_refs) {
			for (; root_metric->metric_refs[cnt].metric_name; cnt++) {
				if (!strcmp(pe->metric_name,
					    root_metric->metric_refs[cnt].metric_name))
					return 0;
			}
		}

		/* Create reference. Need space for the entry and the terminator. */
		root_metric->metric_refs = realloc(root_metric->metric_refs,
						(cnt + 2) * sizeof(struct metric_ref));
		if (!root_metric->metric_refs)
			return -ENOMEM;

		/*
		 * Intentionally passing just const char pointers,
		 * from 'pe' object, so they never go away. We don't
		 * need to change them, so there's no need to create
		 * our own copy.
		 */
		root_metric->metric_refs[cnt].metric_name = pe->metric_name;
		root_metric->metric_refs[cnt].metric_expr = pe->metric_expr;

		/* Null terminate array. */
		root_metric->metric_refs[cnt+1].metric_name = NULL;
		root_metric->metric_refs[cnt+1].metric_expr = NULL;
	}

	/*
	 * For both the parent and referenced metrics, we parse
	 * all the metric's IDs and add it to the root context.
	 */
	if (expr__find_ids(pe->metric_expr, NULL, root_metric->pctx) < 0) {
		/* Broken metric. */
		ret = -EINVAL;
	} else {
		/* Resolve referenced metrics. */
		ret = resolve_metric(metric_list, modifier, metric_no_group, root_metric,
				     &visited_node, map);
	}

	if (ret) {
		if (is_root)
			metric__free(root_metric);

	} else if (is_root)
		list_add(&root_metric->nd, metric_list);

	return ret;
}

#define map_for_each_event(__pe, __idx, __map)					\
	if (__map)								\
		for (__idx = 0, __pe = &__map->table[__idx];			\
		     __pe->name || __pe->metric_group || __pe->metric_name;	\
		     __pe = &__map->table[++__idx])

#define map_for_each_metric(__pe, __idx, __map, __metric)		\
	map_for_each_event(__pe, __idx, __map)				\
		if (__pe->metric_expr &&				\
		    (match_metric(__pe->metric_group, __metric) ||	\
		     match_metric(__pe->metric_name, __metric)))

const struct pmu_event *metricgroup__find_metric(const char *metric,
						 const struct pmu_events_map *map)
{
	const struct pmu_event *pe;
	int i;

	map_for_each_event(pe, i, map) {
		if (match_metric(pe->metric_name, metric))
			return pe;
	}

	return NULL;
}

static int add_metric(struct list_head *metric_list,
		      const struct pmu_event *pe,
		      const char *modifier,
		      bool metric_no_group,
		      struct metric *root_metric,
		      const struct visited_metric *visited,
		      const struct pmu_events_map *map)
{
	int ret = 0;

	pr_debug("metric expr %s for %s\n", pe->metric_expr, pe->metric_name);

	if (!strstr(pe->metric_expr, "?")) {
		ret = __add_metric(metric_list, pe, modifier, metric_no_group, 0,
				   root_metric, visited, map);
	} else {
		int j, count;

		count = arch_get_runtimeparam(pe);

		/* This loop is added to create multiple
		 * events depend on count value and add
		 * those events to metric_list.
		 */

		for (j = 0; j < count && !ret; j++)
			ret = __add_metric(metric_list, pe, modifier, metric_no_group, j,
					root_metric, visited, map);
	}

	return ret;
}

static int metricgroup__add_metric_sys_event_iter(const struct pmu_event *pe,
						  void *data)
{
	struct metricgroup_add_iter_data *d = data;
	int ret;

	if (!match_pe_metric(pe, d->metric_name))
		return 0;

	ret = add_metric(d->metric_list, pe, d->modifier, d->metric_no_group,
			 d->root_metric, d->visited, d->map);
	if (ret)
		goto out;

	*(d->has_match) = true;

out:
	*(d->ret) = ret;
	return ret;
}

static int metric_list_cmp(void *priv __maybe_unused, const struct list_head *l,
			   const struct list_head *r)
{
	const struct metric *left = container_of(l, struct metric, nd);
	const struct metric *right = container_of(r, struct metric, nd);

	return hashmap__size(right->pctx->ids) - hashmap__size(left->pctx->ids);
}

/**
 * metricgroup__add_metric - Find and add a metric, or a metric group.
 * @metric_name: The name of the metric or metric group. For example, "IPC"
 *               could be the name of a metric and "TopDownL1" the name of a
 *               metric group.
 * @modifier: if non-null event modifiers like "u".
 * @metric_no_group: Should events written to events be grouped "{}" or
 *                   global. Grouping is the default but due to multiplexing the
 *                   user may override.
 * @metric_list: The list that the metric or metric group are added to.
 * @map: The map that is searched for metrics, most commonly the table for the
 *       architecture perf is running upon.
 */
static int metricgroup__add_metric(const char *metric_name, const char *modifier,
				   bool metric_no_group,
				   struct list_head *metric_list,
				   const struct pmu_events_map *map)
{
	const struct pmu_event *pe;
	LIST_HEAD(list);
	int i, ret;
	bool has_match = false;

	/*
	 * Iterate over all metrics seeing if metric matches either the name or
	 * group. When it does add the metric to the list.
	 */
	map_for_each_metric(pe, i, map, metric_name) {
		has_match = true;
		ret = add_metric(&list, pe, modifier, metric_no_group,
				 /*root_metric=*/NULL,
				 /*visited_metrics=*/NULL, map);
		if (ret)
			goto out;
	}

	{
		struct metricgroup_iter_data data = {
			.fn = metricgroup__add_metric_sys_event_iter,
			.data = (void *) &(struct metricgroup_add_iter_data) {
				.metric_list = &list,
				.metric_name = metric_name,
				.modifier = modifier,
				.metric_no_group = metric_no_group,
				.has_match = &has_match,
				.ret = &ret,
				.map = map,
			},
		};

		pmu_for_each_sys_event(metricgroup__sys_event_iter, &data);
	}
	/* End of pmu events. */
	if (!has_match)
		ret = -EINVAL;

out:
	/*
	 * add to metric_list so that they can be released
	 * even if it's failed
	 */
	list_splice(&list, metric_list);
	return ret;
}

/**
 * metricgroup__add_metric_list - Find and add metrics, or metric groups,
 *                                specified in a list.
 * @list: the list of metrics or metric groups. For example, "IPC,CPI,TopDownL1"
 *        would match the IPC and CPI metrics, and TopDownL1 would match all
 *        the metrics in the TopDownL1 group.
 * @metric_no_group: Should events written to events be grouped "{}" or
 *                   global. Grouping is the default but due to multiplexing the
 *                   user may override.
 * @metric_list: The list that metrics are added to.
 * @map: The map that is searched for metrics, most commonly the table for the
 *       architecture perf is running upon.
 */
static int metricgroup__add_metric_list(const char *list, bool metric_no_group,
					struct list_head *metric_list,
					const struct pmu_events_map *map)
{
	char *list_itr, *list_copy, *metric_name, *modifier;
	int ret, count = 0;

	list_copy = strdup(list);
	if (!list_copy)
		return -ENOMEM;
	list_itr = list_copy;

	while ((metric_name = strsep(&list_itr, ",")) != NULL) {
		modifier = strchr(metric_name, ':');
		if (modifier)
			*modifier++ = '\0';

		ret = metricgroup__add_metric(metric_name, modifier,
					      metric_no_group, metric_list,
					      map);
		if (ret == -EINVAL)
			pr_err("Cannot find metric or group `%s'\n", metric_name);

		if (ret)
			break;

		count++;
	}
	free(list_copy);

	if (!ret) {
		/*
		 * Warn about nmi_watchdog if any parsed metrics had the
		 * NO_NMI_WATCHDOG constraint.
		 */
		metricgroup___watchdog_constraint_hint(NULL, true);
		/* No metrics. */
		if (count == 0)
			return -EINVAL;
	}
	return ret;
}

static void metricgroup__free_metrics(struct list_head *metric_list)
{
	struct metric *m, *tmp;

	list_for_each_entry_safe (m, tmp, metric_list, nd) {
		list_del_init(&m->nd);
		metric__free(m);
	}
}

/**
 * build_combined_expr_ctx - Make an expr_parse_ctx with all has_constraint
 *                           metric IDs, as the IDs are held in a set,
 *                           duplicates will be removed.
 * @metric_list: List to take metrics from.
 * @combined: Out argument for result.
 */
static int build_combined_expr_ctx(const struct list_head *metric_list,
				   struct expr_parse_ctx **combined)
{
	struct hashmap_entry *cur;
	size_t bkt;
	struct metric *m;
	char *dup;
	int ret;

	*combined = expr__ctx_new();
	if (!*combined)
		return -ENOMEM;

	list_for_each_entry(m, metric_list, nd) {
		if (m->has_constraint && !m->modifier) {
			hashmap__for_each_entry(m->pctx->ids, cur, bkt) {
				dup = strdup(cur->key);
				if (!dup) {
					ret = -ENOMEM;
					goto err_out;
				}
				ret = expr__add_id(*combined, dup);
				if (ret)
					goto err_out;
			}
		}
	}
	return 0;
err_out:
	expr__ctx_free(*combined);
	*combined = NULL;
	return ret;
}

/**
 * parse_ids - Build the event string for the ids and parse them creating an
 *             evlist. The encoded metric_ids are decoded.
 * @fake_pmu: used when testing metrics not supported by the current CPU.
 * @ids: the event identifiers parsed from a metric.
 * @modifier: any modifiers added to the events.
 * @has_constraint: false if events should be placed in a weak group.
 * @out_evlist: the created list of events.
 */
static int parse_ids(struct perf_pmu *fake_pmu, struct expr_parse_ctx *ids,
		     const char *modifier, bool has_constraint, struct evlist **out_evlist)
{
	struct parse_events_error parse_error;
	struct evlist *parsed_evlist;
	struct strbuf events = STRBUF_INIT;
	int ret;

	*out_evlist = NULL;
	if (hashmap__size(ids->ids) == 0) {
		char *tmp;
		/*
		 * No ids/events in the expression parsing context. Events may
		 * have been removed because of constant evaluation, e.g.:
		 *  event1 if #smt_on else 0
		 * Add a duration_time event to avoid a parse error on an empty
		 * string.
		 */
		tmp = strdup("duration_time");
		if (!tmp)
			return -ENOMEM;

		ids__insert(ids->ids, tmp);
	}
	ret = metricgroup__build_event_string(&events, ids, modifier,
					      has_constraint);
	if (ret)
		return ret;

	parsed_evlist = evlist__new();
	if (!parsed_evlist) {
		ret = -ENOMEM;
		goto err_out;
	}
	pr_debug("Parsing metric events '%s'\n", events.buf);
	parse_events_error__init(&parse_error);
	ret = __parse_events(parsed_evlist, events.buf, &parse_error, fake_pmu);
	if (ret) {
		parse_events_error__print(&parse_error, events.buf);
		goto err_out;
	}
	ret = decode_all_metric_ids(parsed_evlist, modifier);
	if (ret)
		goto err_out;

	*out_evlist = parsed_evlist;
	parsed_evlist = NULL;
err_out:
	parse_events_error__exit(&parse_error);
	evlist__delete(parsed_evlist);
	strbuf_release(&events);
	return ret;
}

static int parse_groups(struct evlist *perf_evlist, const char *str,
			bool metric_no_group,
			bool metric_no_merge,
			struct perf_pmu *fake_pmu,
			struct rblist *metric_events_list,
			const struct pmu_events_map *map)
{
	struct evlist *combined_evlist = NULL;
	LIST_HEAD(metric_list);
	struct metric *m;
	int ret;

	if (metric_events_list->nr_entries == 0)
		metricgroup__rblist_init(metric_events_list);
	ret = metricgroup__add_metric_list(str, metric_no_group,
					   &metric_list, map);
	if (ret)
		goto out;

	/* Sort metrics from largest to smallest. */
	list_sort(NULL, &metric_list, metric_list_cmp);

	if (!metric_no_merge) {
		struct expr_parse_ctx *combined = NULL;

		ret = build_combined_expr_ctx(&metric_list, &combined);

		if (!ret && combined && hashmap__size(combined->ids)) {
			ret = parse_ids(fake_pmu, combined, /*modifier=*/NULL,
					/*has_constraint=*/true,
					&combined_evlist);
		}
		if (combined)
			expr__ctx_free(combined);

		if (ret)
			goto out;
	}

	list_for_each_entry(m, &metric_list, nd) {
		struct metric_event *me;
		struct evsel **metric_events;
		struct evlist *metric_evlist = NULL;
		struct metric *n;
		struct metric_expr *expr;

		if (combined_evlist && m->has_constraint) {
			metric_evlist = combined_evlist;
		} else if (!metric_no_merge) {
			/*
			 * See if the IDs for this metric are a subset of an
			 * earlier metric.
			 */
			list_for_each_entry(n, &metric_list, nd) {
				if (m == n)
					break;

				if (n->evlist == NULL)
					continue;

				if ((!m->modifier && n->modifier) ||
				    (m->modifier && !n->modifier) ||
				    (m->modifier && n->modifier &&
					    strcmp(m->modifier, n->modifier)))
					continue;

				if (expr__subset_of_ids(n->pctx, m->pctx)) {
					pr_debug("Events in '%s' fully contained within '%s'\n",
						 m->metric_name, n->metric_name);
					metric_evlist = n->evlist;
					break;
				}

			}
		}
		if (!metric_evlist) {
			ret = parse_ids(fake_pmu, m->pctx, m->modifier,
					m->has_constraint, &m->evlist);
			if (ret)
				goto out;

			metric_evlist = m->evlist;
		}
		ret = setup_metric_events(m->pctx->ids, metric_evlist, &metric_events);
		if (ret) {
			pr_debug("Cannot resolve IDs for %s: %s\n",
				m->metric_name, m->metric_expr);
			goto out;
		}

		me = metricgroup__lookup(metric_events_list, metric_events[0], true);

		expr = malloc(sizeof(struct metric_expr));
		if (!expr) {
			ret = -ENOMEM;
			free(metric_events);
			goto out;
		}

		expr->metric_refs = m->metric_refs;
		m->metric_refs = NULL;
		expr->metric_expr = m->metric_expr;
		if (m->modifier) {
			char *tmp;

			if (asprintf(&tmp, "%s:%s", m->metric_name, m->modifier) < 0)
				expr->metric_name = NULL;
			else
				expr->metric_name = tmp;
		} else
			expr->metric_name = strdup(m->metric_name);

		if (!expr->metric_name) {
			ret = -ENOMEM;
			free(metric_events);
			goto out;
		}
		expr->metric_unit = m->metric_unit;
		expr->metric_events = metric_events;
		expr->runtime = m->pctx->runtime;
		list_add(&expr->nd, &me->head);
	}


	if (combined_evlist) {
		evlist__splice_list_tail(perf_evlist, &combined_evlist->core.entries);
		evlist__delete(combined_evlist);
	}

	list_for_each_entry(m, &metric_list, nd) {
		if (m->evlist)
			evlist__splice_list_tail(perf_evlist, &m->evlist->core.entries);
	}

out:
	metricgroup__free_metrics(&metric_list);
	return ret;
}

int metricgroup__parse_groups(const struct option *opt,
			      const char *str,
			      bool metric_no_group,
			      bool metric_no_merge,
			      struct rblist *metric_events)
{
	struct evlist *perf_evlist = *(struct evlist **)opt->value;
	const struct pmu_events_map *map = pmu_events_map__find();

	return parse_groups(perf_evlist, str, metric_no_group,
			    metric_no_merge, NULL, metric_events, map);
}

int metricgroup__parse_groups_test(struct evlist *evlist,
				   const struct pmu_events_map *map,
				   const char *str,
				   bool metric_no_group,
				   bool metric_no_merge,
				   struct rblist *metric_events)
{
	return parse_groups(evlist, str, metric_no_group,
			    metric_no_merge, &perf_pmu__fake, metric_events, map);
}

bool metricgroup__has_metric(const char *metric)
{
	const struct pmu_events_map *map = pmu_events_map__find();
	const struct pmu_event *pe;
	int i;

	if (!map)
		return false;

	for (i = 0; ; i++) {
		pe = &map->table[i];

		if (!pe->name && !pe->metric_group && !pe->metric_name)
			break;
		if (!pe->metric_expr)
			continue;
		if (match_metric(pe->metric_name, metric))
			return true;
	}
	return false;
}

int metricgroup__copy_metric_events(struct evlist *evlist, struct cgroup *cgrp,
				    struct rblist *new_metric_events,
				    struct rblist *old_metric_events)
{
	unsigned i;

	for (i = 0; i < rblist__nr_entries(old_metric_events); i++) {
		struct rb_node *nd;
		struct metric_event *old_me, *new_me;
		struct metric_expr *old_expr, *new_expr;
		struct evsel *evsel;
		size_t alloc_size;
		int idx, nr;

		nd = rblist__entry(old_metric_events, i);
		old_me = container_of(nd, struct metric_event, nd);

		evsel = evlist__find_evsel(evlist, old_me->evsel->core.idx);
		if (!evsel)
			return -EINVAL;
		new_me = metricgroup__lookup(new_metric_events, evsel, true);
		if (!new_me)
			return -ENOMEM;

		pr_debug("copying metric event for cgroup '%s': %s (idx=%d)\n",
			 cgrp ? cgrp->name : "root", evsel->name, evsel->core.idx);

		list_for_each_entry(old_expr, &old_me->head, nd) {
			new_expr = malloc(sizeof(*new_expr));
			if (!new_expr)
				return -ENOMEM;

			new_expr->metric_expr = old_expr->metric_expr;
			new_expr->metric_name = strdup(old_expr->metric_name);
			if (!new_expr->metric_name)
				return -ENOMEM;

			new_expr->metric_unit = old_expr->metric_unit;
			new_expr->runtime = old_expr->runtime;

			if (old_expr->metric_refs) {
				/* calculate number of metric_events */
				for (nr = 0; old_expr->metric_refs[nr].metric_name; nr++)
					continue;
				alloc_size = sizeof(*new_expr->metric_refs);
				new_expr->metric_refs = calloc(nr + 1, alloc_size);
				if (!new_expr->metric_refs) {
					free(new_expr);
					return -ENOMEM;
				}

				memcpy(new_expr->metric_refs, old_expr->metric_refs,
				       nr * alloc_size);
			} else {
				new_expr->metric_refs = NULL;
			}

			/* calculate number of metric_events */
			for (nr = 0; old_expr->metric_events[nr]; nr++)
				continue;
			alloc_size = sizeof(*new_expr->metric_events);
			new_expr->metric_events = calloc(nr + 1, alloc_size);
			if (!new_expr->metric_events) {
				free(new_expr->metric_refs);
				free(new_expr);
				return -ENOMEM;
			}

			/* copy evsel in the same position */
			for (idx = 0; idx < nr; idx++) {
				evsel = old_expr->metric_events[idx];
				evsel = evlist__find_evsel(evlist, evsel->core.idx);
				if (evsel == NULL) {
					free(new_expr->metric_events);
					free(new_expr->metric_refs);
					free(new_expr);
					return -EINVAL;
				}
				new_expr->metric_events[idx] = evsel;
			}

			list_add(&new_expr->nd, &new_me->head);
		}
	}
	return 0;
}
