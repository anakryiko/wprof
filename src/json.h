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

struct json_buf {
	FILE *f;
	char *data;
	size_t len;
};

struct json_state {
	struct json_buf out;
	int lvl;
	enum json_scope scope[5];
	int cnt[5]; /* comma tracking per level */
};

#define JSON_STATE_INIT(file) { .out = { .f = (file) }, .lvl = -1 }

#define JSON_BUF_SZ (1024 * 1024)

static inline void json_init(struct json_state *js)
{
	js->out.data = malloc(JSON_BUF_SZ);
}

static inline void json_flush(struct json_buf *b)
{
	if (b->len)
		fwrite(b->data, 1, b->len, b->f);
	b->len = 0;
}

static inline void json_finish(struct json_state *js)
{
	json_flush(&js->out);
	free(js->out.data);
}

static inline void json_write(struct json_buf *b, const void *p, size_t n)
{
	if (n > JSON_BUF_SZ) {
		json_flush(b);
		fwrite(p, 1, n, b->f);
		return;
	}
	if (n > JSON_BUF_SZ - b->len)
		json_flush(b);
	memcpy(b->data + b->len, p, n);
	b->len += n;
}

static inline void json_putc(struct json_buf *b, char c)
{
	if (b->len == JSON_BUF_SZ)
		json_flush(b);
	b->data[b->len++] = c;
}

static inline char *json_decimal(char *end, unsigned long long value)
{
	do {
		*--end = '0' + value % 10;
		value /= 10;
	} while (value);
	return end;
}

static inline void json_int(struct json_buf *b, long long value)
{
	char buf[20], *end = buf + sizeof(buf);
	unsigned long long magnitude = value;

	if (value < 0)
		magnitude = 0ULL - magnitude; /* unsigned subtraction also handles LLONG_MIN */
	char *p = json_decimal(end, magnitude);
	if (value < 0)
		*--p = '-';
	json_write(b, p, end - p);
}

static inline void json_uint(struct json_buf *b, unsigned long long value)
{
	char buf[20], *end = buf + sizeof(buf);
	char *p = json_decimal(end, value);

	json_write(b, p, end - p);
}

/* Fixed-precision %f formats, including %.9lf of DBL_MAX, fit in this buffer. */
static inline void json_float(struct json_buf *b, const char *fmt, double value)
{
	char buf[400];
	int n = snprintf(buf, sizeof(buf), fmt, value);

	if (n < 0 || (size_t)n >= sizeof(buf))
		BUG("Invalid JSON float format\n");
	json_write(b, buf, n);
}

static inline void json_ts(struct json_buf *b, u64 ns)
{
	/* Below 2^22 seconds, double division error is less than half a nanosecond,
	 * so %.9lf rounds back to ns with the default rounding mode and C locale.
	 */
	if (ns >= (1ULL << 22) * 1000000000ULL) {
		json_float(b, "%.9lf", ns / 1e9);
		return;
	}
	char frac[] = ".000000000";

	json_uint(b, ns / 1000000000ULL);
	json_decimal(frac + sizeof(frac) - 1, ns % 1000000000ULL);
	json_write(b, frac, sizeof(frac) - 1);
}

static inline void json_escape(struct json_buf *b, unsigned char c)
{
	const char hex[] = "0123456789abcdef";
	char buf[] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] };

	json_write(b, buf, sizeof(buf));
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
static inline void json_puts(struct json_buf *b, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	while (*p) {
		const unsigned char *run = p;

		while (*p >= 0x20 && *p < 0x80 && *p != '"' && *p != '\\')
			p++;
		if (p > run)
			json_write(b, run, p - run);

		unsigned char c = *p;
		switch (c) {
		case 0: return;
		case '"':  json_write(b, "\\\"", 2); p++; break;
		case '\\': json_write(b, "\\\\", 2); p++; break;
		case '\n': json_write(b, "\\n", 2); p++; break;
		case '\t': json_write(b, "\\t", 2); p++; break;
		case '\r': json_write(b, "\\r", 2); p++; break;
		case '\b': json_write(b, "\\b", 2); p++; break;
		case '\f': json_write(b, "\\f", 2); p++; break;
		default:
			if (c < 0x20) {
				json_escape(b, c);
				p++;
			} else {
				int n = json_utf8_seq_len(p);

				if (n) {
					json_write(b, p, n);
					p += n;
				} else {
					json_escape(b, c);
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
		json_puts(&js->out, buf);
	} else {
		char *heap = malloc(n + 1);

		vsnprintf(heap, n + 1, fmt, ap2);
		json_puts(&js->out, heap);
		free(heap);
	}
	va_end(ap2);
}

static inline void json_obj_start(struct json_state *js)
{
	++js->lvl;
	js->scope[js->lvl] = JSON_OBJ;
	js->cnt[js->lvl] = 0;
	json_putc(&js->out, '{');
}

static inline void json_obj_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	if (js->lvl < 0) /* outermost level, emit newline */
		json_write(&js->out, "}\n", 2);
	else
		json_putc(&js->out, '}');
}

static inline void json_key(struct json_state *js, const char *key)
{
	if (js->cnt[js->lvl])
		json_putc(&js->out, ',');
	json_putc(&js->out, '"');
	json_puts(&js->out, key);
	json_write(&js->out, "\":", 2);
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
	json_putc(&js->out, '"');
	json_puts(&js->out, value);
	json_putc(&js->out, '"');
}

__attribute__((format(printf, 3, 4)))
static inline void json_kv_fmt(struct json_state *js, const char *key, const char *fmt, ...)
{
	json_key(js, key);
	json_putc(&js->out, '"');

	va_list ap;
	va_start(ap, fmt);
	json_vprintf(js, fmt, ap);
	va_end(ap);

	json_putc(&js->out, '"');
}

static inline void json_kv_int(struct json_state *js, const char *key, long long value)
{
	json_key(js, key);
	json_int(&js->out, value);
}

static inline void json_kv_uint(struct json_state *js, const char *key, unsigned long long value)
{
	json_key(js, key);
	json_uint(&js->out, value);
}

static inline void json_kv_null(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_write(&js->out, "null", 4);
}

static inline void json_kv_float(struct json_state *js, const char *key, const char *fmt, double value)
{
	json_key(js, key);
	json_float(&js->out, fmt, value);
}

static inline void json_kv_ts(struct json_state *js, const char *key, u64 ns)
{
	json_key(js, key);
	json_ts(&js->out, ns);
}

static inline void json_kv_bool(struct json_state *js, const char *key, bool value)
{
	json_key(js, key);
	json_write(&js->out, value ? "true" : "false", value ? 4 : 5);
}

static inline void json_arr_start(struct json_state *js)
{
	++js->lvl;
	js->scope[js->lvl] = JSON_ARR;
	js->cnt[js->lvl] = 0;
	json_putc(&js->out, '[');
}

static inline void json_arr_end(struct json_state *js)
{
	js->cnt[js->lvl] = 0;
	js->lvl--;
	json_putc(&js->out, ']');
}

static inline void json_subarr_start(struct json_state *js, const char *key)
{
	json_key(js, key);
	json_arr_start(js);
}

static inline void json_arr_elem(struct json_state *js)
{
	if (js->cnt[js->lvl])
		json_putc(&js->out, ',');
	js->cnt[js->lvl]++;
}

static inline void json_arr_str(struct json_state *js, const char *value)
{
	json_arr_elem(js);
	json_putc(&js->out, '"');
	json_puts(&js->out, value);
	json_putc(&js->out, '"');
}

__attribute__((format(printf, 2, 3)))
static inline void json_arr_fmt(struct json_state *js, const char *fmt, ...)
{
	json_arr_elem(js);
	json_putc(&js->out, '"');

	va_list ap;
	va_start(ap, fmt);
	json_vprintf(js, fmt, ap);
	va_end(ap);

	json_putc(&js->out, '"');
}

__unused
static inline void json_arr_int(struct json_state *js, long long value)
{
	json_arr_elem(js);
	json_int(&js->out, value);
}

static inline void json_arr_float(struct json_state *js, const char *fmt, double value)
{
	json_arr_elem(js);
	json_float(&js->out, fmt, value);
}

__unused
static inline void json_arr_null(struct json_state *js)
{
	json_arr_elem(js);
	json_write(&js->out, "null", 4);
}
