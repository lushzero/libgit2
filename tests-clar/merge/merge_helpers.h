#ifndef INCLUDE_cl_merge_helpers_h__
#define INCLUDE_cl_merge_helpers_h__

struct merge_index_entry {
	unsigned int mode;
	char oid_str[41];
	int stage;
	char path[128];
};

int merge_test_index(git_index *index, const struct merge_index_entry expected[], size_t expected_len);

#endif