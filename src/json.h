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

/*
 * Length of the well-formed UTF-8 sequence starting at p, or 0 if p[0] is not a
 * valid lead byte / the sequence is malformed (overlong, surrogate, truncated).
 * A NUL terminator can never pass as a continuation byte, so this never reads
 * past the end of a C string.
 */
static inline int json_utf8_seq_len(const unsigned char *p)
{
	switch (p[0]) {
	case 0x00 ... 0x7f:
		return 1;
	case 0xc2 ... 0xdf:
		return (p[1] & 0xc0) == 0x80 ? 2 : 0;
	case 0xe0:
		return (p[1] >= 0xa0 && p[1] <= 0xbf && (p[2] & 0xc0) == 0x80) ? 3 : 0;
	case 0xe1 ... 0xec:
	case 0xee ... 0xef:
		return ((p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80) ? 3 : 0;
	case 0xed:
		return (p[1] >= 0x80 && p[1] <= 0x9f && (p[2] & 0xc0) == 0x80) ? 3 : 0;
	case 0xf0:
		return (p[1] >= 0x90 && p[1] <= 0xbf && (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80) ? 4 : 0;
	case 0xf1 ... 0xf3:
		return ((p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80) ? 4 : 0;
	case 0xf4:
		return (p[1] >= 0x80 && p[1] <= 0x8f && (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80) ? 4 : 0;
	default:
		return 0;
	}
}

/*
 * Write s as the body of a JSON string (caller emits the surrounding quotes),
 * escaping per RFC 8259. Control characters become \uXXXX; each byte of an
 * invalid UTF-8 sequence is escaped as \u00XX, preserving its value, so
 * arbitrary byte content (e.g. utrace buffers or metadata with quotes or
 * newlines) can never produce undecodable output.
 */
static inline void json_puts(struct json_state *js, const char *s)
{
	FILE *f = js->f;
	const unsigned char *p = (const unsigned char *)s;

	while (*p) {
		const unsigned char *run = p;

		while (*p >= 0x20 && *p < 0x80 && *p != '"' && *p != '\\')
			p++;
		if (p > run)
			fwrite(run, 1, p - run, f);

		unsigned char c = *p;
		switch (c) {
		case 0: return;
		case '"':  fputs("\\\"", f); p++; break;
		case '\\': fputs("\\\\", f); p++; break;
		case '\n': fputs("\\n", f); p++; break;
		case '\t': fputs("\\t", f); p++; break;
		case '\r': fputs("\\r", f); p++; break;
		case '\b': fputs("\\b", f); p++; break;
		case '\f': fputs("\\f", f); p++; break;
		default:
			if (c < 0x20) {
				fprintf(f, "\\u%04x", c);
				p++;
			} else {
				int n = json_utf8_seq_len(p);

				if (n) {
					fwrite(p, 1, n, f);
					p += n;
				} else {
					fprintf(f, "\\u%04x", c);
					p++;
				}
			}
		}
	}
}

static inline void json_vprintf(struct json_state *js, const char *fmt, va_list ap)
{
	char buf[256];
	va_list ap2;

	va_copy(ap2, ap);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (n < 0) {
		va_end(ap2);
		return;
	}
	if ((size_t)n < sizeof(buf)) {
		json_puts(js, buf);
	} else {
		char *heap = malloc(n + 1);

		vsnprintf(heap, n + 1, fmt, ap2);
		json_puts(js, heap);
		free(heap);
	}
	va_end(ap2);
}

static inline void json_obj_start(struct json_state *js)
{
	++js->lvl;
	js->scope[js->lvl] = JSON_OBJ;
	js->cnt[js->lvl] = 0;
	fprintf(js->f, "{");
}

static inline void json_obj_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	if (js->lvl < 0) /* outermost level, emit newline */
		fprintf(js->f, "}\n");
	else
		fprintf(js->f, "}");
}

static inline void json_key(struct json_state *js, const char *key)
{
	if (js->cnt[js->lvl])
		fputc(',', js->f);
	fputc('"', js->f);
	json_puts(js, key);
	fputs("\":", js->f);
	js->cnt[js->lvl]++;
}

static inline void json_subobj_start(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_obj_start(js);
}

static inline void json_kv_str(struct json_state *js, const char *key, const char *value)
{
	json_key(js, key);
	fputc('"', js->f);
	json_puts(js, value);
	fputc('"', js->f);
}

__attribute__((format(printf, 3, 4)))
static inline void json_kv_fmt(struct json_state *js, const char *key, const char *fmt, ...)
{
	json_key(js, key);
	fputc('"', js->f);

	va_list ap;
	va_start(ap, fmt);
	json_vprintf(js, fmt, ap);
	va_end(ap);

	fputc('"', js->f);
}

static inline void json_kv_int(struct json_state *js, const char *key, long long value)
{
	json_key(js, key);
	fprintf(js->f, "%lld", value);
}

static inline void json_kv_uint(struct json_state *js, const char *key, unsigned long long value)
{
	json_key(js, key);
	fprintf(js->f, "%llu", value);
}

static inline void json_kv_null(struct json_state *js, const char *key)
{
	json_key(js, key);
	fputs("null", js->f);
}

static inline void json_kv_float(struct json_state *js, const char *key, const char *fmt, double value)
{
	json_key(js, key);
	fprintf(js->f, fmt, value);
}

static inline void json_kv_ts(struct json_state *js, const char *key, u64 ns)
{
	json_kv_float(js, key, "%.9lf", ns / 1e9);
}

static inline void json_kv_bool(struct json_state *js, const char *key, bool value)
{
	json_key(js, key);
	fprintf(js->f, "%s", value ? "true" : "false");
}

static inline void json_arr_start(struct json_state *js)
{
	++js->lvl;
	js->scope[js->lvl] = JSON_ARR;
	js->cnt[js->lvl] = 0;
	fprintf(js->f, "[");
}

static inline void json_arr_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	fprintf(js->f, "]");
}

static inline void json_subarr_start(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_arr_start(js);
}

static inline void json_arr_elem(struct json_state *js)
{
	if (js->cnt[js->lvl])
		fprintf(js->f, ",");
	js->cnt[js->lvl]++;
}

static inline void json_arr_str(struct json_state *js, const char *value)
{
	json_arr_elem(js);
	fputc('"', js->f);
	json_puts(js, value);
	fputc('"', js->f);
}

__attribute__((format(printf, 2, 3)))
static inline void json_arr_fmt(struct json_state *js, const char *fmt, ...)
{
	json_arr_elem(js);
	fputc('"', js->f);

	va_list ap;
	va_start(ap, fmt);
	json_vprintf(js, fmt, ap);
	va_end(ap);

	fputc('"', js->f);
}

__unused
static inline void json_arr_int(struct json_state *js, long long value)
{
	json_arr_elem(js);
	fprintf(js->f, "%lld", value);
}

static inline void json_arr_float(struct json_state *js, const char *fmt, double value)
{
	json_arr_elem(js);
	fprintf(js->f, fmt, value);
}
