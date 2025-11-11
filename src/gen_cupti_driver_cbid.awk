BEGIN {
	printf "const char *cupti_driver_cbid_str_map[] = {\n"
	printf "\t[0] = \"???\",\n"
}

/CUPTI_DRIVER_TRACE_CBID_FORCE_INT/ { next }
/CUPTI_DRIVER_TRACE_CBID_SIZE/ { next }
/CUPTI_DRIVER_TRACE_CBID_INVALID/ { next }

/CUPTI_DRIVER_TRACE_CBID_/ {
	if (match($0, /CUPTI_DRIVER_TRACE_CBID_(\S+)\s*=\s*([0-9]+)/, a)) {
		printf "\t[%s] = \"%s\",\n", a[2], a[1]
	}
}

END {
	printf "};\n"
	printf "int cupti_driver_cbid_str_map_sz = sizeof(cupti_driver_cbid_str_map) / sizeof(cupti_driver_cbid_str_map[0]);\n"
}
