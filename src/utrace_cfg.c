// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "env.h"
#include "utrace_cfg.h"

struct strv {
	const char *s;
	int len;
};

static struct strv sv(const char *s, int len)
{
	return (struct strv){ .s = s, .len = len };
}

static struct strv sv_new(const char *s)
{
	return sv(s, strlen(s));
}

static struct strv sv_empty(void)
{
	return sv("", 0);
}

static bool sv_is_empty(struct strv v)
{
	return v.len == 0;
}

static struct strv sv_trim(struct strv v)
{
	while (v.len > 0 && isspace(v.s[0])) { v.s++; v.len--; }
	while (v.len > 0 && isspace(v.s[v.len - 1])) { v.len--; }
	return v;
}

static bool sv_eq(struct strv a, const char *b)
{
	return strncmp(a.s, b, a.len) == 0 && b[a.len] == '\0';
}

static bool sv_starts_with(struct strv v, const char *pfx)
{
	int plen = strlen(pfx);

	return v.len >= plen && strncmp(v.s, pfx, plen) == 0;
}

static char *sv_strdup(struct strv v)
{
	return strndup(v.s, v.len);
}

/* find substring in view, return -1 if not found */
static int sv_find(struct strv v, const char *needle)
{
	int nlen = strlen(needle);

	if (nlen > v.len)
		return -1;
	for (int i = 0; i <= v.len - nlen; i++)
		if (strncmp(v.s + i, needle, nlen) == 0)
			return i;
	return -1;
}

static struct strv sv_split(struct strv v, const char *delim, struct strv *right)
{
	int pos = sv_find(v, delim);

	if (pos < 0) {
		*right = sv_empty();
		return v;
	}

	*right = sv(v.s + pos, v.len - pos);
	return sv(v.s, pos);
}

static struct strv sv_consume_left(struct strv v, int n)
{
	if (n > v.len)
		n = v.len;
	return sv(v.s + n, v.len - n);
}

/* strip matching left/right delimiters from v; returns true on success, false if either is missing */
static bool sv_unwrap(struct strv *v, const char *left, const char *right)
{
	int llen = strlen(left);
	int rlen = strlen(right);

	if (v->len < llen + rlen)
		return false;
	if (strncmp(v->s, left, llen) != 0)
		return false;
	if (strncmp(v->s + v->len - rlen, right, rlen) != 0)
		return false;

	v->s += llen;
	v->len -= llen + rlen;
	return true;
}

static bool sv_as_long(struct strv v, long *val)
{
	int n = 0;

	return sscanf(v.s, "%li%n", val, &n) == 1 && n == v.len;
}

/* --- error reporting with position highlighting -------------------------- */

__printf(3, 4)
static int utrace_err(struct strv orig, struct strv bad, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	eprintf("utrace: %s", vsfmt(fmt, ap));
	va_end(ap);

	eprintf("  %.*s\n", orig.len, orig.s);

	int off, len;

	if (bad.s >= orig.s && bad.s < orig.s + orig.len) {
		off = bad.s - orig.s;
		len = bad.len;
		if (off + len > orig.len)
			len = orig.len - off;
	} else {
		off = 0;
		len = orig.len;
	}
	if (len <= 0)
		len = 1;

	eprintf("  %*s%.*s\n", off, "", len,
		"^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

	return -EINVAL;
}

static const struct {
	const char *name;
	enum utrace_arg_type type;
} arg_type_table[] = {
	{ "u8",  UTRACE_ARG_U8 },
	{ "u16", UTRACE_ARG_U16 },
	{ "u32", UTRACE_ARG_U32 },
	{ "u64", UTRACE_ARG_U64 },
	{ "s8",  UTRACE_ARG_S8 },
	{ "s16", UTRACE_ARG_S16 },
	{ "s32", UTRACE_ARG_S32 },
	{ "int", UTRACE_ARG_S32 },
	{ "s64", UTRACE_ARG_S64 },
	{ "long", UTRACE_ARG_S64 },
	{ "str", UTRACE_ARG_STR },
};

static int parse_arg_type(struct strv v, enum utrace_arg_type *out)
{
	for (int i = 0; i < ARRAY_SIZE(arg_type_table); i++) {
		if (sv_eq(v, arg_type_table[i].name)) {
			*out = arg_type_table[i].type;
			return 0;
		}
	}
	return -EINVAL;
}

static const char *arg_type_str(enum utrace_arg_type t)
{
	for (int i = 0; i < ARRAY_SIZE(arg_type_table); i++)
		if (arg_type_table[i].type == t)
			return arg_type_table[i].name;
	return "???";
}

static const struct {
	const char *prefix;
	enum utrace_type type;
} probe_type_table[] = {
	{ "uret:",  UTRACE_URETPROBE },
	{ "uspan:", UTRACE_UPROBE_SPAN },
	{ "usdt:",  UTRACE_USDT },
	{ "u:",     UTRACE_UPROBE },
	{ "kret:",  UTRACE_KRETPROBE },
	{ "kspan:", UTRACE_KPROBE_SPAN },
	{ "k:",     UTRACE_KPROBE },
	{ "tp:",    UTRACE_TRACEPOINT },
	{ "raw_tp:", UTRACE_RAW_TRACEPOINT },
};

/* parse "IDX[:TYPE][->NAME]" argument definition without "arg:" prefix */
static int parse_arg_param(struct strv orig, struct strv def, struct utrace_param *p)
{
	struct strv name, arg, arg_type;
	enum utrace_arg_type atype = UTRACE_ARG_U64;
	long idx;

	def = sv_trim(def);
	if (sv_is_empty(def))
		return utrace_err(orig, def, "empty arg definition\n");

	/* split off optional "->name" suffix */
	def = sv_split(def, "->", &name);
	if (!sv_is_empty(name)) {
		name = sv_trim(sv_consume_left(name, 2));
		if (sv_is_empty(name))
			return utrace_err(orig, name, "empty arg name after '->'\n");
	}

	/* split "idx[:type]" */
	arg = sv_trim(sv_split(def, ":", &arg_type));

	if (sv_eq(arg, "ret")) {
		idx = UTRACE_ARG_RET;
	} else {
		if (!sv_as_long(arg, &idx) || idx < 0 || idx > INT_MAX)
			return utrace_err(orig, arg, "invalid arg index\n");
	}

	if (!sv_is_empty(arg_type)) {
		arg_type = sv_trim(sv_consume_left(arg_type, 1));
		if (parse_arg_type(arg_type, &atype))
			return utrace_err(orig, arg_type, "unknown arg type\n");
	}

	p->type = UTRACE_PARAM_ARG;
	p->arg.arg_idx = idx;
	p->arg.arg_type = atype;
	p->arg.name = sv_is_empty(name) ? NULL : sv_strdup(name);
	return 0;
}

static int parse_params(struct strv orig, struct strv def, struct utrace_param **out, int *out_cnt)
{
	struct utrace_param *params = NULL;
	int cnt = 0;

	while (!sv_is_empty(def)) {
		struct strv rest;
		struct strv param = sv_split(def, ",", &rest);

		def = sv_consume_left(rest, 1);

		if (sv_is_empty(sv_trim(param)))
			return utrace_err(orig, param, "invalid empty parameter\n");
		param = sv_trim(param);

		params = realloc(params, (cnt + 1) * sizeof(*params));

		struct utrace_param *p = &params[cnt];
		memset(p, 0, sizeof(*p));

		if (sv_eq(param, "st") || sv_eq(param, "stack") || sv_eq(param, "stacktrace")) {
			p->type = UTRACE_PARAM_CAPTURE_STACK;
		} else if (sv_starts_with(param, "path:")) {
			param = sv_trim(sv_consume_left(param, 5));

			if (sv_is_empty(param))
				return utrace_err(orig, param, "invalid empty path\n");

			p->type = UTRACE_PARAM_BINARY_PATH;
			p->binary.path = sv_strdup(param);
		} else if (sv_starts_with(param, "pid:")) {
			param = sv_trim(sv_consume_left(param, 4));

			long pid = -1;
			if (!sv_as_long(param, &pid) || pid <= 0 || pid > INT_MAX)
				return utrace_err(orig, param, "invalid PID value\n");

			p->type = UTRACE_PARAM_PID;
			p->pid.pid = (int)pid;
		} else if (sv_starts_with(param, "arg:")) {
			param = sv_trim(sv_consume_left(param, 4));
			int err = parse_arg_param(orig, param, p);
			if (err)
				return err;
		} else {
			return utrace_err(orig, param, "unknown parameter\n");
		}
		cnt++;
	}

	*out = params;
	*out_cnt = cnt;
	return 0;
}

static bool is_uprobe(enum utrace_type t)
{
	switch (t) {
	case UTRACE_UPROBE:
	case UTRACE_URETPROBE:
	case UTRACE_UPROBE_SPAN:
	case UTRACE_USDT:
		return true;
	default:
		return false;
	}
}

static bool is_ret_probe(enum utrace_type t)
{
	return t == UTRACE_URETPROBE || t == UTRACE_KRETPROBE;
}

static bool is_span_probe(enum utrace_type t)
{
	switch (t) {
	case UTRACE_SPAN:
	case UTRACE_KPROBE_SPAN:
	case UTRACE_UPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static int validate_probe_def(struct strv orig, const struct utrace_cfg *cfg)
{
	for (int i = 0; i < cfg->param_cnt; i++) {
		const struct utrace_param *p = &cfg->params[i];

		if (p->type == UTRACE_PARAM_ARG) {
			if (is_ret_probe(cfg->type) && p->arg.arg_idx != UTRACE_ARG_RET)
				return utrace_err(orig, orig, "return probes only support arg:ret captures, not arg:%d\n", p->arg.arg_idx);
			if (!is_ret_probe(cfg->type) && p->arg.arg_idx == UTRACE_ARG_RET)
				return utrace_err(orig, orig, "arg:ret is only valid on return probes (uret/kret)\n");
		}
		if (p->type == UTRACE_PARAM_BINARY_PATH && !is_uprobe(cfg->type))
			return utrace_err(orig, orig, "'path' parameter is only valid for uprobe-based probes\n");
	}

	return 0;
}

/* parse a single probe definition: "type:target-spec (params)" */
static int parse_settings(struct strv orig, struct strv def, struct utrace_settings *settings)
{
	memset(settings, 0, sizeof(*settings));

	while (!sv_is_empty(def)) {
		struct strv rest;
		struct strv tok = sv_trim(sv_split(def, ",", &rest));

		def = sv_is_empty(rest) ? sv_empty() : sv_consume_left(rest, 1);

		if (sv_is_empty(tok))
			continue;

		return utrace_err(orig, tok, "unknown setting\n");
	}

	return 0;
}

static int parse_probe_def(struct strv orig, struct strv def, struct utrace_cfg *cfg)
{
	struct strv params;
	int i, err;

	def = sv_trim(def);
	if (sv_is_empty(def))
		return utrace_err(orig, def, "empty probe definition\n");

	/* split by '(' to carve out optional params */
	def = sv_split(def, "(", &params);
	def = sv_trim(def);
	if (sv_is_empty(def))
		return utrace_err(orig, def, "empty probe definition\n");

	/* match type prefix */
	for (i = 0; i < ARRAY_SIZE(probe_type_table); i++) {
		if (!sv_starts_with(def, probe_type_table[i].prefix))
			continue;

		cfg->type = probe_type_table[i].type;
		def = sv_consume_left(def, strlen(probe_type_table[i].prefix));
		def = sv_trim(def);
	}
	if (cfg->type == UTRACE_INVALID)
		return utrace_err(orig, def, "unrecognized probe type\n");

	switch (cfg->type) {
	case UTRACE_UPROBE:
	case UTRACE_URETPROBE:
	case UTRACE_UPROBE_SPAN: {
		struct strv name, offset;

		name = sv_split(def, "+", &offset);
		name = sv_trim(name);
		cfg->uprobe.name = sv_strdup(name);

		if (!sv_is_empty(offset)) {
			if (cfg->type != UTRACE_UPROBE)
				return utrace_err(orig, offset, "only uprobe supports offset\n");

			offset = sv_consume_left(sv_trim(offset), 1);
			if (!sv_as_long(offset, &cfg->uprobe.off))
				return utrace_err(orig, offset, "invalid offset value\n");
		}
		break;
	}
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN: {
		struct strv name, offset;

		name = sv_split(def, "+", &offset);
		name = sv_trim(name);
		cfg->uprobe.name = sv_strdup(name);

		if (!sv_is_empty(offset)) {
			if (cfg->type != UTRACE_KPROBE)
				return utrace_err(orig, offset, "only kprobe supports offset\n");

			offset = sv_consume_left(sv_trim(offset), 1);
			if (!sv_as_long(offset, &cfg->kprobe.off))
				return utrace_err(orig, offset, "invalid offset value\n");
		}

		break;
	}
	case UTRACE_USDT: {
		struct strv provider, name;

		provider = sv_split(def, ":", &name);
		provider = sv_trim(provider);
		name = sv_trim(name);

		if (sv_is_empty(provider) || sv_is_empty(name))
			return utrace_err(orig, def, "USDT probe requires 'provider:name' format\n");

		cfg->usdt.provider = sv_strdup(provider);
		cfg->usdt.name = sv_strdup(name);
		break;
	}
	case UTRACE_TRACEPOINT: {
		struct strv cat, name;

		cat = sv_split(def, ":", &name);
		cat = sv_trim(cat);
		name = sv_trim(name);

		if (sv_is_empty(cat) || sv_is_empty(cat))
			return utrace_err(orig, def, "tracepoint probe requires 'category:name' format\n");

		cfg->tp.cat = sv_strdup(cat);
		cfg->tp.name = sv_strdup(name);
		break;
	}
	case UTRACE_RAW_TRACEPOINT:
		cfg->raw_tp.name = sv_strdup(def);
		break;
	default:
		return utrace_err(orig, def, "unexpected probe type %d\n", cfg->type);
	}

	if (!sv_is_empty(params)) {
		params = sv_trim(params);
		if (!sv_unwrap(&params, "(", ")"))
			return utrace_err(orig, params, "parameters must be enclosed in (...)\n");
		err = parse_params(orig, params, &cfg->params, &cfg->param_cnt);
		if (err)
			return err;
	}

	return validate_probe_def(orig, cfg);
}

/*
 * General form of utrace definition:
 * <target-type>:<target-spec> (<param-type>:<param-spec>, ...) { <setting-type>:<setting-spec> }
 *
 * For generic span definition, general shape is:
 * <target> (<params>) + <target> (<params>) { <settings> }
 *
 * General logic is to split out all these different parts, while remembering that they
 * are all optional, except for <target-type>:<target-spec>.
 */
static int parse_cfg(struct strv def, struct utrace_cfg *cfg)
{
	struct strv orig = def;
	struct strv settings, left, right;
	int err;

	memset(cfg, 0, sizeof(*cfg));

	def = sv_trim(def);
	if (sv_is_empty(def))
		return utrace_err(orig, orig, "empty definition\n");

	/* split by '{' to carve out optional settings */
	def = sv_split(def, "{", &settings);
	def = sv_trim(def);
	settings = sv_trim(settings);
	if (!sv_is_empty(settings)) {
		if (!sv_unwrap(&settings, "{", "}"))
			return utrace_err(orig, settings, "settings must be enclosed in {...}\n");
		err = parse_settings(orig, sv_trim(settings), &cfg->settings);
		if (err)
			return err;
	}

	/* split by '<=>' in case this is a span */
	left = sv_split(def, "<=>", &right);
	left = sv_trim(left);

	if (sv_is_empty(right)) {
		err = parse_probe_def(orig, def, cfg);
		if (err)
			return err;
	} else {
		right = sv_trim(sv_consume_left(right, 3));

		cfg->type = UTRACE_SPAN;
		cfg->span.entry = calloc(1, sizeof(*cfg->span.entry));
		cfg->span.exit = calloc(1, sizeof(*cfg->span.exit));

		err = parse_probe_def(orig, left, cfg->span.entry);
		err = err ?: parse_probe_def(orig, right, cfg->span.exit);
		if (err)
			return err;

		if (is_span_probe(cfg->span.entry->type) || is_span_probe(cfg->span.exit->type))
			return utrace_err(orig, def, "nested spans are not allowed\n");

		return 0;
	}

	/* TODO: high-level validation of settings against probe definition */
	return 0;
}

int utrace_cfg_parse(const char *def)
{
	env.utrace_cfg_cnt++;
	env.utrace_cfgs = realloc(env.utrace_cfgs, env.utrace_cfg_cnt * sizeof(*env.utrace_cfgs));

	int err = parse_cfg(sv_new(def), &env.utrace_cfgs[env.utrace_cfg_cnt - 1]);
	if (err)
		env.utrace_cfg_cnt--;
	return err;
}

int utrace_cfg_parse_file(const char *path)
{
	FILE *f;
	char *line = NULL;
	size_t line_cap = 0;
	ssize_t line_len;
	int line_nr = 0;

	f = fopen(path, "r");
	if (!f) {
		eprintf("utrace: failed to open config file '%s': %s\n", path, strerror(errno));
		return -errno;
	}

	while ((line_len = getline(&line, &line_cap, f)) != -1) {
		line_nr++;

		/* strip newline */
		while (line_len > 0 && line[line_len - 1])
			line[--line_len] = '\0';

		/* skip blank lines and comments */
		const char *p = line;
		while (*p && isspace(*p))
			p++;
		if (*p == '\0' || *p == '#')
			continue;

		int err = utrace_cfg_parse(p);
		if (err) {
			eprintf("utrace: error parsing line #%d of '%s'\n", line_nr, path);
			free(line);
			fclose(f);
			return err;
		}
	}

	free(line);
	fclose(f);
	return 0;
}

static const char *utrace_type_str(enum utrace_type t)
{
	switch (t) {
	case UTRACE_UPROBE:		return "u";
	case UTRACE_URETPROBE:		return "uret";
	case UTRACE_USDT:		return "usdt";
	case UTRACE_KPROBE:		return "k";
	case UTRACE_KRETPROBE:		return "kret";
	case UTRACE_TRACEPOINT:		return "tp";
	case UTRACE_RAW_TRACEPOINT:	return "raw_tp";
	case UTRACE_UPROBE_SPAN:	return "uspan";
	case UTRACE_KPROBE_SPAN:	return "kspan";
	case UTRACE_SPAN:		return "span";
	default:			return "???";
	}
}

static void utrace_cfg_dump_single(const struct utrace_cfg *cfg, char *buf, int sz, int *pos)
{
#define APPEND(fmt, ...) do { *pos += snprintf(buf + *pos, sz - *pos, fmt, ##__VA_ARGS__); } while (0)

	APPEND("%s:", utrace_type_str(cfg->type));

	switch (cfg->type) {
	case UTRACE_UPROBE:
	case UTRACE_URETPROBE:
	case UTRACE_UPROBE_SPAN:
		APPEND("%s", cfg->uprobe.name);
		if (cfg->uprobe.off)
			APPEND("+%ld", cfg->uprobe.off);
		break;
	case UTRACE_USDT:
		APPEND("%s:%s", cfg->usdt.provider, cfg->usdt.name);
		break;
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
		APPEND("%s", cfg->kprobe.name);
		if (cfg->kprobe.off)
			APPEND("+%ld", cfg->kprobe.off);
		break;
	case UTRACE_TRACEPOINT:
		APPEND("%s:%s", cfg->tp.cat, cfg->tp.name);
		break;
	case UTRACE_RAW_TRACEPOINT:
		APPEND("%s", cfg->raw_tp.name);
		break;
	default:
		break;
	}

	if (cfg->param_cnt > 0) {
		APPEND(" (");
		for (int i = 0; i < cfg->param_cnt; i++) {
			const struct utrace_param *p = &cfg->params[i];
			if (i > 0)
				APPEND(", ");
			switch (p->type) {
			case UTRACE_PARAM_CAPTURE_STACK:
				APPEND("stack");
				break;
			case UTRACE_PARAM_BINARY_PATH:
				APPEND("path:%s", p->binary.path);
				break;
			case UTRACE_PARAM_PID:
				APPEND("pid:%d", p->pid.pid);
				break;
			case UTRACE_PARAM_ARG:
				if (p->arg.arg_idx == UTRACE_ARG_RET)
					APPEND("arg:ret");
				else
					APPEND("arg:%d", p->arg.arg_idx);
				if (p->arg.arg_type != UTRACE_ARG_U64)
					APPEND(":%s", arg_type_str(p->arg.arg_type));
				if (p->arg.name)
					APPEND("->%s", p->arg.name);
				break;
			}
		}
		APPEND(")");
	}

	/* TODO: dump settings when we have any */

#undef APPEND
}

void utrace_cfg_dump(const struct utrace_cfg *cfg)
{
	char buf[1024];
	int pos = 0;

	if (cfg->type == UTRACE_SPAN) {
		int p1 = 0, p2 = 0;
		char b1[512], b2[512];

		utrace_cfg_dump_single(cfg->span.entry, b1, sizeof(b1), &p1);
		utrace_cfg_dump_single(cfg->span.exit, b2, sizeof(b2), &p2);
		dprintf(0, "utrace: span { entry: %s, exit: %s }\n", b1, b2);
		return;
	}

	utrace_cfg_dump_single(cfg, buf, sizeof(buf), &pos);
	dprintf(0, "utrace: %s\n", buf);
}
