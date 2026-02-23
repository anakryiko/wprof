/*
 * LOW-LEVEL JSON BUILDER PRIMITIVES
 *
 * All functions take a struct json_state* as the first argument.
 * Track nesting level, scope, and comma state for correct output.
 * Outputs one JSON object per line (newline-delimited JSON).
 */

enum json_scope {
	JSON_OBJ,
	JSON_ARR,
};

struct json_state {
	FILE *f;
	int lvl;
	enum json_scope scope[5];
	int cnt[5]; /* comma tracking per level */
};

#define JSON_STATE_INIT(file) { .f = (file), .lvl = -1 }

static void json_obj_start(struct json_state *js)
{
	++js->lvl;
	js->scope[js->lvl] = JSON_OBJ;
	js->cnt[js->lvl] = 0;
	fprintf(js->f, "{");
}

static void json_obj_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	if (js->lvl < 0) /* outermost level, emit newline */
		fprintf(js->f, "}\n");
	else
		fprintf(js->f, "}");
}

static void json_key(struct json_state *js, const char *key)
{
	fprintf(js->f, "%s\"%s\":", js->cnt[js->lvl] ? "," : "", key);
	js->cnt[js->lvl]++;
}

static void json_subobj_start(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_obj_start(js);
}

static void json_kv_str(struct json_state *js, const char *key, const char *value)
{
	json_key(js, key);
	fprintf(js->f, "\"%s\"", value);
}

__attribute__((format(printf, 3, 4)))
static void json_kv_fmt(struct json_state *js, const char *key, const char *fmt, ...)
{
	json_key(js, key);
	fprintf(js->f, "\"");

	va_list ap;
	va_start(ap, fmt);
	vfprintf(js->f, fmt, ap);
	va_end(ap);

	fprintf(js->f, "\"");
}

static void json_kv_int(struct json_state *js, const char *key, long long value)
{
	json_key(js, key);
	fprintf(js->f, "%lld", value);
}

__unused
static void json_kv_float(struct json_state *js, const char *key, const char *fmt, double value)
{
	json_key(js, key);
	fprintf(js->f, fmt, value);
}

__unused
static void json_arr_start(struct json_state *js)
{
	++js->lvl;
	js->scope[js->lvl] = JSON_ARR;
	js->cnt[js->lvl] = 0;
	fprintf(js->f, "[");
}

__unused
static void json_arr_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	fprintf(js->f, "]");
}

__unused
static void json_subarr_start(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_arr_start(js);
}

static void json_arr_elem(struct json_state *js)
{
	if (js->cnt[js->lvl])
		fprintf(js->f, ",");
	js->cnt[js->lvl]++;
}

__unused
static void json_arr_str(struct json_state *js, const char *value)
{
	json_arr_elem(js);
	fprintf(js->f, "\"%s\"", value);
}

__unused
__attribute__((format(printf, 2, 3)))
static void json_arr_fmt(struct json_state *js, const char *fmt, ...)
{
	json_arr_elem(js);
	fprintf(js->f, "\"");

	va_list ap;
	va_start(ap, fmt);
	vfprintf(js->f, fmt, ap);
	va_end(ap);

	fprintf(js->f, "\"");
}

__unused
static void json_arr_int(struct json_state *js, long long value)
{
	json_arr_elem(js);
	fprintf(js->f, "%lld", value);
}

__unused
static void json_arr_float(struct json_state *js, const char *fmt, double value)
{
	json_arr_elem(js);
	fprintf(js->f, fmt, value);
}
