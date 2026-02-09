/*
 * HIGH-LEVEL TRACE RECORD EMITTING INTERFACES
 */
enum emit_scope {
	EMIT_ARR,
	EMIT_OBJ,
};

struct emit_state {
	int lvl;
	enum emit_scope scope[5];
	int cnt[5]; /* object field or array items counts, per-level */

	bool is_pb;
	TracePacket pb;
	struct pb_anns anns;
};

static __thread struct emit_state em = {.lvl = -1};

static void emit_obj_start(void)
{
	if (!env.jtrace)
		return;

	em.scope[++em.lvl] = EMIT_OBJ;
	fprintf(env.jtrace, "{");
}

static void emit_obj_end(void)
{
	if (!env.jtrace)
		return;

	em.cnt[em.lvl--] = 0;
	if (em.lvl < 0) /* outermost level, we are done with current record */
		fprintf(env.jtrace, "},\n");
	else
		fprintf(env.jtrace, "}");
}

static void emit_key(const char *key)
{
	fprintf(env.jtrace, "%s\"%s\":", em.cnt[em.lvl] ? "," : "", key);
	em.cnt[em.lvl]++;
}

static void emit_subobj_start(const char *key)
{
	if (!env.jtrace)
		return;

	emit_key(key);
	emit_obj_start();
}

__unused
static void emit_kv_str(pb_iid key_iid, const char *key, pb_iid value_iid, const char *value)
{
	if (env.jtrace) {
		emit_key(key);
		fprintf(env.jtrace, "\"%s\"", value);
	}
	if (env.trace && em.is_pb)
		anns_add_str(&em.anns, key_iid, key, value_iid, value);
}

__unused
__attribute__((format(printf, 3, 4)))
static void emit_kv_fmt(pb_iid key_iid, const char *key, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (env.jtrace) {
		emit_key(key);

		fprintf(env.jtrace, "\"");

		va_list apj;
		va_copy(apj, ap);

		vfprintf(env.jtrace, fmt, apj);
		va_end(apj);

		fprintf(env.jtrace, "\"");
	}

	if (env.trace && em.is_pb)
		anns_add_str(&em.anns, key_iid, key, IID_NONE, vsfmt(fmt, ap));

	va_end(ap);
}

__unused
static void emit_kv_int(pb_iid key_iid, const char *key, int64_t value)
{
	if (env.jtrace) {
		emit_key(key);
		fprintf(env.jtrace, "%lld", (long long)value);
	}
	if (env.trace && em.is_pb)
		anns_add_int(&em.anns, key_iid, key, value);
}

__unused
static void emit_kv_float(pb_iid key_iid, const char *key, const char *fmt, double value)
{
	if (env.jtrace) {
		emit_key(key);
		fprintf(env.jtrace, fmt, value);
		em.cnt[em.lvl]++;
	}
	if (env.trace && em.is_pb)
		anns_add_double(&em.anns, key_iid, key, value);
}

__unused
static void emit_arr_start(void)
{
	if (!env.jtrace)
		return;

	em.scope[++em.lvl] = EMIT_ARR;
	fprintf(env.jtrace, "[");
}

__unused
static void emit_arr_end(void)
{
	if (!env.jtrace)
		return;

	em.cnt[em.lvl--] = 0;
	fprintf(env.jtrace, "]");
}

__unused
static void emit_subarr_start(const char *key)
{
	if (!env.jtrace)
		return;

	emit_key(key);
	emit_arr_start();
}

static void emit_arr_elem(void)
{
	if (!env.jtrace)
		return;

	if (em.cnt[em.lvl])
		fprintf(env.jtrace, ",");
	em.cnt[em.lvl]++;
}

__unused
static void emit_arr_str(const char *value)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();
	fprintf(env.jtrace, "\"%s\"", value);
}

__unused
__attribute__((format(printf, 1, 2)))
static void emit_arr_fmt(const char *fmt, ...)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();

	fprintf(env.jtrace, "\"");

	va_list ap;
	va_start(ap, fmt);
	vfprintf(env.jtrace, fmt, ap);
	va_end(ap);

	fprintf(env.jtrace, "\"");
}

__unused
static void emit_arr_int(long long value)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();
	fprintf(env.jtrace, "%lld", value);
}

__unused
static void emit_arr_float(const char *fmt, double value)
{
	if (!env.jtrace)
		return;

	emit_arr_elem();
	fprintf(env.jtrace, fmt, value);
}

struct emit_rec { bool done; };

static void emit_cleanup(struct emit_rec *r)
{
	if (env.jtrace) {
		while (em.lvl >= 0) {
			if (em.scope[em.lvl] == EMIT_OBJ)
				emit_obj_end();
			else
				emit_arr_end();
		}
	}
	if (env.trace && em.is_pb) {
		enc_trace_packet(&em.pb);
		em.is_pb = false;
	}
}

/*
 * USAGE
 */

static void emit_thread_meta(const struct wprof_thread *t, const char *name)
{
	int tid, pid;

	if (!env.jtrace)
		return;

	tid = track_tid(t);
	pid = track_pid(t);
	
	emit_obj_start();
		emit_kv_str(0, "ph", 0, "M");
		emit_kv_str(0, "name", 0, "thread_name");
		emit_kv_int(0, "tid", tid);
		emit_kv_int(0, "pid", pid);
		emit_key("args"); emit_obj_start();
			emit_kv_str(0, "name", 0, name);
		emit_obj_end();
	emit_obj_end();
}

__unused
static struct emit_rec emit_instant_pre(u64 ts,
					pb_iid name_iid, const char *name)
{
	if (env.jtrace) {
		emit_obj_start();
			emit_kv_str(0, "ph", 0, "i");
			emit_kv_float(0, "ts", "%.3lf", (ts - env.sess_start_ts) / 1000.0);
			emit_kv_fmt(0, "name", name);
			/* assume thread-scoped instant event */
			// emit_kv_str("s", "t");
			emit_kv_int(0, "tid", track_tid(t));
			emit_kv_int(0, "pid", track_pid(t));
	}

	if (env.trace) {
		em.pb = (TracePacket) {
			PB_INIT(timestamp) = ts - env.sess_start_ts,
			PB_TRUST_SEQ_ID(),
			PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
				PB_INIT(track_uuid) = task_track_uuid(t),
				PB_INIT(type) = perfetto_protos_TrackEvent_Type_TYPE_INSTANT,
				PB_NAME(TrackEvent, name_field, name_iid, name),
				.debug_annotations = PB_ANNOTATIONS(&em.anns),
			}},
		};
		anns_reset(&em.anns);
		em.is_pb = true;
	}

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_instant(ts, t, name_iid, name)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, name_iid, name);						\
	     !___r.done; ___r.done = true)
