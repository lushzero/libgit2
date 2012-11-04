#include "clar_libgit2.h"
#include "merge_helpers.h"

int merge_test_index(git_index *index, const struct merge_index_entry expected[], size_t expected_len)
{
    size_t i;
    git_index_entry *index_entry;
    bool test_oid;
    git_oid expected_oid;
    
    if (git_index_entrycount(index) != expected_len)
        return 0;
    
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
            strcmp(index_entry->path, expected[i].path) != 0)
            return 0;
    }
    
    return 1;
}
