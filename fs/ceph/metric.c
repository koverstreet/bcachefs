/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/ceph/ceph_debug.h>

#include <linux/types.h>
#include <linux/percpu_counter.h>
#include <linux/math64.h>

#include "metric.h"
#include "mds_client.h"

static bool ceph_mdsc_send_metrics(struct ceph_mds_client *mdsc,
				   struct ceph_mds_session *s)
{
	struct ceph_metric_head *head;
	struct ceph_metric_cap *cap;
	struct ceph_metric_read_latency *read;
	struct ceph_metric_write_latency *write;
	struct ceph_metric_metadata_latency *meta;
	struct ceph_metric_dlease *dlease;
	struct ceph_opened_files *files;
	struct ceph_pinned_icaps *icaps;
	struct ceph_opened_inodes *inodes;
	struct ceph_read_io_size *rsize;
	struct ceph_write_io_size *wsize;
	struct ceph_client_metric *m = &mdsc->metric;
	u64 nr_caps = atomic64_read(&m->total_caps);
	u32 header_len = sizeof(struct ceph_metric_header);
	struct ceph_msg *msg;
	struct timespec64 ts;
	s64 sum;
	s32 items = 0;
	s32 len;

	len = sizeof(*head) + sizeof(*cap) + sizeof(*read) + sizeof(*write)
	      + sizeof(*meta) + sizeof(*dlease) + sizeof(*files)
	      + sizeof(*icaps) + sizeof(*inodes) + sizeof(*rsize)
	      + sizeof(*wsize);

	msg = ceph_msg_new(CEPH_MSG_CLIENT_METRICS, len, GFP_NOFS, true);
	if (!msg) {
		pr_err("send metrics to mds%d, failed to allocate message\n",
		       s->s_mds);
		return false;
	}

	head = msg->front.iov_base;

	/* encode the cap metric */
	cap = (struct ceph_metric_cap *)(head + 1);
	cap->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_CAP_INFO);
	cap->header.ver = 1;
	cap->header.compat = 1;
	cap->header.data_len = cpu_to_le32(sizeof(*cap) - header_len);
	cap->hit = cpu_to_le64(percpu_counter_sum(&m->i_caps_hit));
	cap->mis = cpu_to_le64(percpu_counter_sum(&m->i_caps_mis));
	cap->total = cpu_to_le64(nr_caps);
	items++;

	/* encode the read latency metric */
	read = (struct ceph_metric_read_latency *)(cap + 1);
	read->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_READ_LATENCY);
	read->header.ver = 1;
	read->header.compat = 1;
	read->header.data_len = cpu_to_le32(sizeof(*read) - header_len);
	sum = m->metric[METRIC_READ].latency_sum;
	jiffies_to_timespec64(sum, &ts);
	read->sec = cpu_to_le32(ts.tv_sec);
	read->nsec = cpu_to_le32(ts.tv_nsec);
	items++;

	/* encode the write latency metric */
	write = (struct ceph_metric_write_latency *)(read + 1);
	write->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_WRITE_LATENCY);
	write->header.ver = 1;
	write->header.compat = 1;
	write->header.data_len = cpu_to_le32(sizeof(*write) - header_len);
	sum = m->metric[METRIC_WRITE].latency_sum;
	jiffies_to_timespec64(sum, &ts);
	write->sec = cpu_to_le32(ts.tv_sec);
	write->nsec = cpu_to_le32(ts.tv_nsec);
	items++;

	/* encode the metadata latency metric */
	meta = (struct ceph_metric_metadata_latency *)(write + 1);
	meta->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_METADATA_LATENCY);
	meta->header.ver = 1;
	meta->header.compat = 1;
	meta->header.data_len = cpu_to_le32(sizeof(*meta) - header_len);
	sum = m->metric[METRIC_METADATA].latency_sum;
	jiffies_to_timespec64(sum, &ts);
	meta->sec = cpu_to_le32(ts.tv_sec);
	meta->nsec = cpu_to_le32(ts.tv_nsec);
	items++;

	/* encode the dentry lease metric */
	dlease = (struct ceph_metric_dlease *)(meta + 1);
	dlease->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_DENTRY_LEASE);
	dlease->header.ver = 1;
	dlease->header.compat = 1;
	dlease->header.data_len = cpu_to_le32(sizeof(*dlease) - header_len);
	dlease->hit = cpu_to_le64(percpu_counter_sum(&m->d_lease_hit));
	dlease->mis = cpu_to_le64(percpu_counter_sum(&m->d_lease_mis));
	dlease->total = cpu_to_le64(atomic64_read(&m->total_dentries));
	items++;

	sum = percpu_counter_sum(&m->total_inodes);

	/* encode the opened files metric */
	files = (struct ceph_opened_files *)(dlease + 1);
	files->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_OPENED_FILES);
	files->header.ver = 1;
	files->header.compat = 1;
	files->header.data_len = cpu_to_le32(sizeof(*files) - header_len);
	files->opened_files = cpu_to_le64(atomic64_read(&m->opened_files));
	files->total = cpu_to_le64(sum);
	items++;

	/* encode the pinned icaps metric */
	icaps = (struct ceph_pinned_icaps *)(files + 1);
	icaps->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_PINNED_ICAPS);
	icaps->header.ver = 1;
	icaps->header.compat = 1;
	icaps->header.data_len = cpu_to_le32(sizeof(*icaps) - header_len);
	icaps->pinned_icaps = cpu_to_le64(nr_caps);
	icaps->total = cpu_to_le64(sum);
	items++;

	/* encode the opened inodes metric */
	inodes = (struct ceph_opened_inodes *)(icaps + 1);
	inodes->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_OPENED_INODES);
	inodes->header.ver = 1;
	inodes->header.compat = 1;
	inodes->header.data_len = cpu_to_le32(sizeof(*inodes) - header_len);
	inodes->opened_inodes = cpu_to_le64(percpu_counter_sum(&m->opened_inodes));
	inodes->total = cpu_to_le64(sum);
	items++;

	/* encode the read io size metric */
	rsize = (struct ceph_read_io_size *)(inodes + 1);
	rsize->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_READ_IO_SIZES);
	rsize->header.ver = 1;
	rsize->header.compat = 1;
	rsize->header.data_len = cpu_to_le32(sizeof(*rsize) - header_len);
	rsize->total_ops = cpu_to_le64(m->metric[METRIC_READ].total);
	rsize->total_size = cpu_to_le64(m->metric[METRIC_READ].size_sum);
	items++;

	/* encode the write io size metric */
	wsize = (struct ceph_write_io_size *)(rsize + 1);
	wsize->header.type = cpu_to_le32(CLIENT_METRIC_TYPE_WRITE_IO_SIZES);
	wsize->header.ver = 1;
	wsize->header.compat = 1;
	wsize->header.data_len = cpu_to_le32(sizeof(*wsize) - header_len);
	wsize->total_ops = cpu_to_le64(m->metric[METRIC_WRITE].total);
	wsize->total_size = cpu_to_le64(m->metric[METRIC_WRITE].size_sum);
	items++;

	put_unaligned_le32(items, &head->num);
	msg->front.iov_len = len;
	msg->hdr.version = cpu_to_le16(1);
	msg->hdr.compat_version = cpu_to_le16(1);
	msg->hdr.front_len = cpu_to_le32(msg->front.iov_len);
	dout("client%llu send metrics to mds%d\n",
	     ceph_client_gid(mdsc->fsc->client), s->s_mds);
	ceph_con_send(&s->s_con, msg);

	return true;
}


static void metric_get_session(struct ceph_mds_client *mdsc)
{
	struct ceph_mds_session *s;
	int i;

	mutex_lock(&mdsc->mutex);
	for (i = 0; i < mdsc->max_sessions; i++) {
		s = __ceph_lookup_mds_session(mdsc, i);
		if (!s)
			continue;

		/*
		 * Skip it if MDS doesn't support the metric collection,
		 * or the MDS will close the session's socket connection
		 * directly when it get this message.
		 */
		if (check_session_state(s) &&
		    test_bit(CEPHFS_FEATURE_METRIC_COLLECT, &s->s_features)) {
			mdsc->metric.session = s;
			break;
		}

		ceph_put_mds_session(s);
	}
	mutex_unlock(&mdsc->mutex);
}

static void metric_delayed_work(struct work_struct *work)
{
	struct ceph_client_metric *m =
		container_of(work, struct ceph_client_metric, delayed_work.work);
	struct ceph_mds_client *mdsc =
		container_of(m, struct ceph_mds_client, metric);

	if (mdsc->stopping)
		return;

	if (!m->session || !check_session_state(m->session)) {
		if (m->session) {
			ceph_put_mds_session(m->session);
			m->session = NULL;
		}
		metric_get_session(mdsc);
	}
	if (m->session) {
		ceph_mdsc_send_metrics(mdsc, m->session);
		metric_schedule_delayed(m);
	}
}

int ceph_metric_init(struct ceph_client_metric *m)
{
	struct ceph_metric *metric;
	int ret, i;

	if (!m)
		return -EINVAL;

	atomic64_set(&m->total_dentries, 0);
	ret = percpu_counter_init(&m->d_lease_hit, 0, GFP_KERNEL);
	if (ret)
		return ret;

	ret = percpu_counter_init(&m->d_lease_mis, 0, GFP_KERNEL);
	if (ret)
		goto err_d_lease_mis;

	atomic64_set(&m->total_caps, 0);
	ret = percpu_counter_init(&m->i_caps_hit, 0, GFP_KERNEL);
	if (ret)
		goto err_i_caps_hit;

	ret = percpu_counter_init(&m->i_caps_mis, 0, GFP_KERNEL);
	if (ret)
		goto err_i_caps_mis;

	for (i = 0; i < METRIC_MAX; i++) {
		metric = &m->metric[i];
		spin_lock_init(&metric->lock);
		metric->size_sum = 0;
		metric->size_min = U64_MAX;
		metric->size_max = 0;
		metric->total = 0;
		metric->latency_sum = 0;
		metric->latency_sq_sum = 0;
		metric->latency_min = KTIME_MAX;
		metric->latency_max = 0;
	}

	atomic64_set(&m->opened_files, 0);
	ret = percpu_counter_init(&m->opened_inodes, 0, GFP_KERNEL);
	if (ret)
		goto err_opened_inodes;
	ret = percpu_counter_init(&m->total_inodes, 0, GFP_KERNEL);
	if (ret)
		goto err_total_inodes;

	m->session = NULL;
	INIT_DELAYED_WORK(&m->delayed_work, metric_delayed_work);

	return 0;

err_total_inodes:
	percpu_counter_destroy(&m->opened_inodes);
err_opened_inodes:
	percpu_counter_destroy(&m->i_caps_mis);
err_i_caps_mis:
	percpu_counter_destroy(&m->i_caps_hit);
err_i_caps_hit:
	percpu_counter_destroy(&m->d_lease_mis);
err_d_lease_mis:
	percpu_counter_destroy(&m->d_lease_hit);

	return ret;
}

void ceph_metric_destroy(struct ceph_client_metric *m)
{
	if (!m)
		return;

	cancel_delayed_work_sync(&m->delayed_work);

	percpu_counter_destroy(&m->total_inodes);
	percpu_counter_destroy(&m->opened_inodes);
	percpu_counter_destroy(&m->i_caps_mis);
	percpu_counter_destroy(&m->i_caps_hit);
	percpu_counter_destroy(&m->d_lease_mis);
	percpu_counter_destroy(&m->d_lease_hit);

	ceph_put_mds_session(m->session);
}

#define METRIC_UPDATE_MIN_MAX(min, max, new)	\
{						\
	if (unlikely(new < min))		\
		min = new;			\
	if (unlikely(new > max))		\
		max = new;			\
}

static inline void __update_stdev(ktime_t total, ktime_t lsum,
				  ktime_t *sq_sump, ktime_t lat)
{
	ktime_t avg, sq;

	if (unlikely(total == 1))
		return;

	/* the sq is (lat - old_avg) * (lat - new_avg) */
	avg = DIV64_U64_ROUND_CLOSEST((lsum - lat), (total - 1));
	sq = lat - avg;
	avg = DIV64_U64_ROUND_CLOSEST(lsum, total);
	sq = sq * (lat - avg);
	*sq_sump += sq;
}

void ceph_update_metrics(struct ceph_metric *m,
			 ktime_t r_start, ktime_t r_end,
			 unsigned int size, int rc)
{
	ktime_t lat = ktime_sub(r_end, r_start);
	ktime_t total;

	if (unlikely(rc < 0 && rc != -ENOENT && rc != -ETIMEDOUT))
		return;

	spin_lock(&m->lock);
	total = ++m->total;
	m->size_sum += size;
	METRIC_UPDATE_MIN_MAX(m->size_min, m->size_max, size);
	m->latency_sum += lat;
	METRIC_UPDATE_MIN_MAX(m->latency_min, m->latency_max, lat);
	__update_stdev(total, m->latency_sum, &m->latency_sq_sum, lat);
	spin_unlock(&m->lock);
}
