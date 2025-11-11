BEGIN {
	printf "const char *cupti_runtime_cbid_str_map[] = {\n"
	printf "\t[0] = \"???\",\n"
}

/CUPTI_RUNTIME_TRACE_CBID_FORCE_INT/ { next }
/CUPTI_RUNTIME_TRACE_CBID_SIZE/ { next }
/CUPTI_RUNTIME_TRACE_CBID_INVALID/ { next }

/CUPTI_RUNTIME_TRACE_CBID_/ {
	if (match($0, /CUPTI_RUNTIME_TRACE_CBID_(.+)_v[0-9]+\s*=\s*([0-9]+)/, a)) {
		printf "\t[%s] = \"%s\",\n", a[2], a[1]
	}
}

END {
	printf "};\n"
	printf "int cupti_runtime_cbid_str_map_sz = sizeof(cupti_runtime_cbid_str_map) / sizeof(cupti_runtime_cbid_str_map[0]);\n"
}
