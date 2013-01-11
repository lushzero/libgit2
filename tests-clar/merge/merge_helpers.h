#ifndef INCLUDE_cl_merge_helpers_h__
#define INCLUDE_cl_merge_helpers_h__

struct merge_index_entry {
	unsigned int mode;
	char oid_str[41];
	int stage;
	char path[128];
};

struct merge_reuc_entry {
	char path[128];
	unsigned int ancestor_mode;
	unsigned int our_mode;
	unsigned int their_mode;
	char ancestor_oid_str[41];
	char our_oid_str[41];
	char their_oid_str[41];
};

int merge_branches(git_merge_result **result, git_repository *repo, const char *ours_branch, const char *theirs_branch, git_merge_opts *opts);

int merge_test_index(git_index *index, const struct merge_index_entry expected[], size_t expected_len);

int merge_test_reuc(git_index *index, const struct merge_reuc_entry expected[], size_t expected_len);

#endif
