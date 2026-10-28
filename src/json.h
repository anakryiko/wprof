#include "strs.h"

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
	struct sbuf out;
	int lvl;
	enum json_scope scope[5];
	int cnt[5]; /* comma tracking per level */
};

#define JSON_STATE_INIT(file) { .f = (file), .lvl = -1 }

static inline void json_flush(struct json_state *js)
{
	fwrite(js->out.buf, 1, js->out.len, js->f);
	sbuf_reset(&js->out);
}

static inline void json_finish(struct json_state *js)
{
	sbuf_free(&js->out);
}

static inline void json_write(struct json_state *js, const void *p, size_t n)
{
	sbuf_append(&js->out, p, n);
}

static inline void json_putc(struct json_state *js, char c)
{
	sbuf_putc(&js->out, c);
}

/* Write a NUL-terminated decimal string backward from the buffer's end; return its start. */
static inline char *json_decimal(char *buf, size_t size, unsigned long long value)
{
	char *end = buf + size - 1;

	*end = '\0';
	do {
		--end;
		*end = '0' + value % 10;
		value /= 10;
	} while (value);
	return end;
}

static inline void json_int(struct json_state *js, long long value)
{
	/* 19 decimal digits + sign + NUL. */
	char buf[21], *end = buf + sizeof(buf) - 1;
	unsigned long long magnitude = value;

	if (value < 0)
		magnitude = 0ULL - magnitude; /* unsigned subtraction also handles LLONG_MIN */
	char *p = json_decimal(buf, sizeof(buf), magnitude);
	if (value < 0) {
		--p;
		*p = '-';
	}
	json_write(js, p, end - p);
}

static inline void json_uint(struct json_state *js, unsigned long long value)
{
	/* 20 decimal digits + NUL. */
	char buf[21], *end = buf + sizeof(buf) - 1;
	char *p = json_decimal(buf, sizeof(buf), value);

	json_write(js, p, end - p);
}

static inline void json_float(struct json_state *js, const char *fmt, double value)
{
	char buf[32];
	int n = snprintf(buf, sizeof(buf), fmt, value);

	if (n < 0)
		BUG("JSON float formatting failed for format '%s'\n", fmt);
	if ((size_t)n >= sizeof(buf))
		BUG("JSON float buffer too small for format '%s': need %zu bytes, have %zu\n",
		    fmt, (size_t)n + 1, sizeof(buf));
	json_write(js, buf, n);
}

static inline void json_ts(struct json_state *js, u64 ns)
{
	static const u64 ns_per_sec = 1000000000ULL;
	char frac[] = ".000000000";

	json_uint(js, ns / ns_per_sec);
	json_decimal(frac + 1, sizeof(frac) - 1, ns % ns_per_sec);
	json_write(js, frac, sizeof(frac) - 1);
}

static inline void json_escape(struct json_state *js, unsigned char c)
{
	static const char hex[] = "0123456789abcdef";
	char buf[] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] };

	json_write(js, buf, sizeof(buf));
}

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
	const unsigned char *p = (const unsigned char *)s;

	while (*p) {
		const unsigned char *run = p;

		while (*p >= 0x20 && *p < 0x80 && *p != '"' && *p != '\\')
			p++;
		if (p > run)
			json_write(js, run, p - run);

		unsigned char c = *p;
		switch (c) {
		case 0: return;
		case '"':  json_write(js, "\\\"", 2); p++; break;
		case '\\': json_write(js, "\\\\", 2); p++; break;
		case '\n': json_write(js, "\\n", 2); p++; break;
		case '\t': json_write(js, "\\t", 2); p++; break;
		case '\r': json_write(js, "\\r", 2); p++; break;
		case '\b': json_write(js, "\\b", 2); p++; break;
		case '\f': json_write(js, "\\f", 2); p++; break;
		default:
			if (c < 0x20) {
				json_escape(js, c);
				p++;
			} else {
				int n = json_utf8_seq_len(p);

				if (n) {
					json_write(js, p, n);
					p += n;
				} else {
					json_escape(js, c);
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
	json_putc(js, '{');
}

static inline void json_obj_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	if (js->lvl < 0) { /* outermost level, emit newline */
		json_write(js, "}\n", 2);
		json_flush(js);
	} else
		json_putc(js, '}');
}

static inline void json_key(struct json_state *js, const char *key)
{
	if (js->cnt[js->lvl])
		json_putc(js, ',');
	json_putc(js, '"');
	json_puts(js, key);
	json_write(js, "\":", 2);
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
	json_putc(js, '"');
	json_puts(js, value);
	json_putc(js, '"');
}

__attribute__((format(printf, 3, 4)))
static inline void json_kv_fmt(struct json_state *js, const char *key, const char *fmt, ...)
{
	json_key(js, key);
	json_putc(js, '"');

	va_list ap;
	va_start(ap, fmt);
	json_vprintf(js, fmt, ap);
	va_end(ap);

	json_putc(js, '"');
}

static inline void json_kv_int(struct json_state *js, const char *key, long long value)
{
	json_key(js, key);
	json_int(js, value);
}

static inline void json_kv_uint(struct json_state *js, const char *key, unsigned long long value)
{
	json_key(js, key);
	json_uint(js, value);
}

static inline void json_kv_null(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_write(js, "null", 4);
}

static inline void json_kv_float(struct json_state *js, const char *key, const char *fmt, double value)
{
	json_key(js, key);
	json_float(js, fmt, value);
}

static inline void json_kv_ts(struct json_state *js, const char *key, u64 ns)
{
	json_key(js, key);
	json_ts(js, ns);
}

static inline void json_kv_bool(struct json_state *js, const char *key, bool value)
{
	json_key(js, key);
	json_write(js, value ? "true" : "false", value ? 4 : 5);
}

static inline void json_arr_start(struct json_state *js)
{
	++js->lvl;
	js->scope[js->lvl] = JSON_ARR;
	js->cnt[js->lvl] = 0;
	json_putc(js, '[');
}

static inline void json_arr_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	json_putc(js, ']');
}

static inline void json_subarr_start(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_arr_start(js);
}

static inline void json_arr_elem(struct json_state *js)
{
	if (js->cnt[js->lvl])
		json_putc(js, ',');
	js->cnt[js->lvl]++;
}

static inline void json_arr_str(struct json_state *js, const char *value)
{
	json_arr_elem(js);
	json_putc(js, '"');
	json_puts(js, value);
	json_putc(js, '"');
}

__attribute__((format(printf, 2, 3)))
static inline void json_arr_fmt(struct json_state *js, const char *fmt, ...)
{
	json_arr_elem(js);
	json_putc(js, '"');

	va_list ap;
	va_start(ap, fmt);
	json_vprintf(js, fmt, ap);
	va_end(ap);

	json_putc(js, '"');
}

__unused
static inline void json_arr_int(struct json_state *js, long long value)
{
	json_arr_elem(js);
	json_int(js, value);
}

static inline void json_arr_float(struct json_state *js, const char *fmt, double value)
{
	json_arr_elem(js);
	json_float(js, fmt, value);
}

__unused
static inline void json_arr_null(struct json_state *js)
{
	json_arr_elem(js);
	json_write(js, "null", 4);
}
