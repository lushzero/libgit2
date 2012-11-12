#include "clar_libgit2.h"
#include "merge_helpers.h"

int merge_test_index(git_index *index, const struct merge_index_entry expected[], size_t expected_len)
{
    size_t i;
    git_index_entry *index_entry;
    bool test_oid;
    git_oid expected_oid;

    if (git_index_entrycount(index) != expected_len) {
		abort();
        return 0;
	}
    
    for (i = 0; i < expected_len; i++) {
        if ((index_entry = git_index_get_byindex(index, i)) == NULL)
            return 0;
        
		if (strlen(expected[i].oid_str) != 0) {
            cl_git_pass(git_oid_fromstr(&expected_oid, expected[i].oid_str));
            test_oid = 1;
        } else
            test_oid = 0;
        
        if (index_entry->mode != expected[i].mode ||
            (test_oid && git_oid_cmp(&index_entry->oid, &expected_oid) != 0) ||
            git_index_entry_stage(index_entry) != expected[i].stage ||
            strcmp(index_entry->path, expected[i].path) != 0) {
			abort();
            return 0;
		}
    }
    
    return 1;
}

int merge_test_reuc(git_index *index, const struct merge_reuc_entry expected[], size_t expected_len)
{
    size_t i;
	const git_index_reuc_entry *reuc_entry;
    git_oid expected_oid;
    
    if (git_index_reuc_entrycount(index) != expected_len)
        return 0;
    
    for (i = 0; i < expected_len; i++) {
        if ((reuc_entry = git_index_reuc_get_byindex(index, i)) == NULL)
            return 0;

		if (strcmp(reuc_entry->path, expected[i].path) != 0 ||
			reuc_entry->mode[0] != expected[i].ancestor_mode ||
			reuc_entry->mode[1] != expected[i].our_mode ||
			reuc_entry->mode[2] != expected[i].their_mode)
			return 0;

		if (expected[i].ancestor_mode > 0) {
			cl_git_pass(git_oid_fromstr(&expected_oid, expected[i].ancestor_oid_str));

			if (git_oid_cmp(&reuc_entry->oid[0], &expected_oid) != 0)
				return 0;
		}

		if (expected[i].our_mode > 0) {
			cl_git_pass(git_oid_fromstr(&expected_oid, expected[i].our_oid_str));

			if (git_oid_cmp(&reuc_entry->oid[1], &expected_oid) != 0)
				return 0;
		}

		if (expected[i].their_mode > 0) {
			cl_git_pass(git_oid_fromstr(&expected_oid, expected[i].their_oid_str));

			if (git_oid_cmp(&reuc_entry->oid[2], &expected_oid) != 0)
				return 0;
		}
    }
    
    return 1;
}
