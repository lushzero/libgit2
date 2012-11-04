#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/merge.h"
#include "merge.h"
#include "merge_helpers.h"
#include "refs.h"
#include "fileops.h"

static git_repository *repo;
static git_index *repo_index;

#define TEST_REPO_PATH "merge-resolve"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"

struct merge_index_entry both_changed_index_entries[] = {
	{ 0100644, "233c0919c998ed110a4b6ff36f353aec8b713487", 0, "added-in-master.txt" },
	{ 0100644, "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", 0, "automergeable.txt" },
	{ 0100644, "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", 0, "changed-in-branch.txt" },
	{ 0100644, "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", 0, "changed-in-master.txt" },
	{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 0, "conflicting.txt" },
	{ 0100644, "dfe3f22baa1f6fce5447901c3086bae368de6bdd", 0, "removed-in-branch.txt" },
	{ 0100644, "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", 0, "unchanged.txt" },
};

// Fixture setup and teardown
void test_merge_trivial__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
    git_repository_index(&repo_index, repo);
}

void test_merge_trivial__cleanup(void)
{
    git_index_free(repo_index);
	cl_git_sandbox_cleanup();
}



static git_merge_result *merge_trivial_branch(const char *branch_name)
{
	git_buf branch_buf = GIT_BUF_INIT;
	git_reference *their_ref;
    git_merge_head *their_heads[1];
	git_merge_result *result;

	git_buf_printf(&branch_buf, "%s%s", GIT_REFS_HEADS_DIR, branch_name);
	cl_git_pass(git_reference_lookup(&their_ref, repo, branch_buf.ptr));
	cl_git_pass(git_merge_head_from_ref(&their_heads[0], their_ref));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, 0, git_merge_strategy_resolve, NULL));

	git_buf_free(&branch_buf);
	git_reference_free(their_ref);
	git_merge_head_free(their_heads[0]);

	return result;
}

void test_merge_trivial__both_added(void)
{
	git_merge_result *result;

	cl_assert(result = merge_trivial_branch("trivial-both-added"));
	cl_assert(!git_merge_result_is_fastforward(result));
    
    cl_assert(merge_test_index(repo_index, both_changed_index_entries, 7));
    cl_assert(git_index_reuc_entrycount(repo_index) == 0);
    
	git_merge_result_free(result);
}

void test_merge_trivial__both_changed(void)
{
	git_merge_result *result;

	cl_assert(result = merge_trivial_branch("trivial-both-changed"));
	cl_assert(!git_merge_result_is_fastforward(result));
    
    cl_assert(merge_test_index(repo_index, both_changed_index_entries, 7));
    cl_assert(git_index_reuc_entrycount(repo_index) == 0);
    
	git_merge_result_free(result);
}

void test_merge_trivial__both_removed(void)
{
	git_merge_result *result;

	cl_assert(result = merge_trivial_branch("trivial-both-removed"));
	cl_assert(!git_merge_result_is_fastforward(result));
    
    cl_assert(merge_test_index(repo_index, both_changed_index_entries, 7));
    cl_assert(git_index_reuc_entrycount(repo_index) == 0);
    
	git_merge_result_free(result);
}

