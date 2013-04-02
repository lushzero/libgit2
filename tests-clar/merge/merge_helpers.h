#ifndef INCLUDE_cl_merge_helpers_h__
#define INCLUDE_cl_merge_helpers_h__

#include "git2/merge.h"
#include "git2/merge_branches.h"

struct merge_index_entry {
	uint16_t mode;
	char oid_str[41];
	int stage;
	char path[128];
};

struct merge_index_with_status {
    uint16_t mode;
	char oid_str[41];
	int stage;
	char path[128];
    unsigned int status;
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

struct merge_index_conflict_data {
	struct merge_index_with_status ancestor;
	struct merge_index_with_status ours;
	struct merge_index_with_status theirs;
	git_merge_conflict_type_t conflict_type;
};

int merge_trees_from_branches(
	git_merge_index **result, git_index **index, git_repository *repo,
	const char *ours_name, const char *theirs_name,
	git_merge_tree_opts *opts);

int merge_branches(git_merge_result **result, git_repository *repo, const char *ours_branch, const char *theirs_branch, git_merge_opts *opts);

int merge_test_merge_index_staged(git_merge_index *merge_index, const struct merge_index_entry expected[], size_t expected_len);

int merge_test_merge_conflicts(git_vector *conflicts, const struct merge_index_conflict_data expected[], size_t expected_len);

int merge_test_index(git_index *index, const struct merge_index_entry expected[], size_t expected_len);

int merge_test_reuc(git_index *index, const struct merge_reuc_entry expected[], size_t expected_len);

int merge_test_workdir(git_repository *repo, const struct merge_index_entry expected[], size_t expected_len);

#endif
