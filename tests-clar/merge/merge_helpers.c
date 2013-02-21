#include "clar_libgit2.h"
#include "buffer.h"
#include "refs.h"
#include "tree.h"
#include "merge_helpers.h"

static int merge_fake_tree(git_tree **_tree, git_repository *repo)
{
	git_tree *tree;
	
	tree = git__calloc(1, sizeof(git_tree));
	GITERR_CHECK_ALLOC(tree);
	
	git_atomic_inc(&tree->object.cached.refcount);
	tree->object.type = GIT_OBJ_TREE;
	tree->object.repo = repo;
	
	*_tree = tree;

	return 0;
}

int merge_trees_from_branches(
	git_merge_tree_result **result, git_index **index, git_repository *repo,
	const char *ours_name, const char *theirs_name,
	git_merge_tree_opts *opts)
{
	git_commit *our_commit, *their_commit, *ancestor_commit = NULL;
	git_tree *our_tree, *their_tree, *ancestor_tree;
	git_oid our_oid, their_oid, ancestor_oid;
	git_buf branch_buf = GIT_BUF_INIT;
	int error;

	git_buf_printf(&branch_buf, "%s%s", GIT_REFS_HEADS_DIR, ours_name);
	cl_git_pass(git_reference_name_to_id(&our_oid, repo, branch_buf.ptr));
	cl_git_pass(git_commit_lookup(&our_commit, repo, &our_oid));

	git_buf_clear(&branch_buf);
	git_buf_printf(&branch_buf, "%s%s", GIT_REFS_HEADS_DIR, theirs_name);
	cl_git_pass(git_reference_name_to_id(&their_oid, repo, branch_buf.ptr));
	cl_git_pass(git_commit_lookup(&their_commit, repo, &their_oid));

	error = git_merge_base(&ancestor_oid, repo, git_commit_id(our_commit), git_commit_id(their_commit));

	if (error == GIT_ENOTFOUND)
		cl_git_pass(merge_fake_tree(&ancestor_tree, repo));
	else {
		cl_git_pass(error);

		cl_git_pass(git_commit_lookup(&ancestor_commit, repo, &ancestor_oid));
		cl_git_pass(git_commit_tree(&ancestor_tree, ancestor_commit));
	}

	cl_git_pass(git_commit_tree(&our_tree, our_commit));
	cl_git_pass(git_commit_tree(&their_tree, their_commit));

	cl_git_pass(git_index_new(index));
	cl_git_pass(git_index_read_tree(*index, our_tree));

	cl_git_pass(git_merge_trees(result, repo, *index, ancestor_tree, our_tree, their_tree, opts));

	git_buf_free(&branch_buf);
	git_tree_free(our_tree);
	git_tree_free(their_tree);
	git_tree_free(ancestor_tree);
	git_commit_free(our_commit);
	git_commit_free(their_commit);
	git_commit_free(ancestor_commit);

	return 0;
}

int merge_branches(git_merge_result **result, git_repository *repo, const char *ours_branch, const char *theirs_branch, git_merge_opts *opts)
{
	git_reference *head_ref, *theirs_ref;
	git_merge_head *theirs_head;
	git_checkout_opts head_checkout_opts = GIT_CHECKOUT_OPTS_INIT;
	
	head_checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
	
	cl_git_pass(git_reference_symbolic_create(&head_ref, repo, "HEAD", ours_branch, 1));
	cl_git_pass(git_checkout_head(repo, &head_checkout_opts));
	
	cl_git_pass(git_reference_lookup(&theirs_ref, repo, theirs_branch));
	cl_git_pass(git_merge_head_from_ref(&theirs_head, repo, theirs_ref));
	
	cl_git_pass(git_merge(result, repo, (const git_merge_head **)&theirs_head, 1, opts));
	
	git_reference_free(head_ref);
	git_reference_free(theirs_ref);
	git_merge_head_free(theirs_head);
	
	return 0;
}

int merge_test_index(git_index *index, const struct merge_index_entry expected[], size_t expected_len)
{
    size_t i;
    const git_index_entry *index_entry;
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
