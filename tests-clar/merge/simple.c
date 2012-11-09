#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/merge.h"
#include "merge.h"
#include "merge_helpers.h"

static git_repository *repo;
static git_index *repo_index;

#define TEST_REPO_PATH "merge-resolve"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"

#define THEIRS_SIMPLE_BRANCH        "branch"
#define THEIRS_SIMPLE_OID           "7cb63eed597130ba4abb87b3e544b85021905520"

// Fixture setup and teardown
void test_merge_simple__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
    git_repository_index(&repo_index, repo);
}

void test_merge_simple__cleanup(void)
{
    git_index_free(repo_index);
	cl_git_sandbox_cleanup();
}

static git_merge_result *merge_simple_branch(int flags, git_merge_strategy_resolve_options *resolve_options)
{
	git_oid their_oids[1];
    git_merge_head *their_heads[1];
	git_merge_result *result;
    
	cl_git_pass(git_oid_fromstr(&their_oids[0], THEIRS_SIMPLE_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], &their_oids[0]));
    
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, flags, git_merge_strategy_resolve, resolve_options));
    
	return result;
}

void test_merge_simple__ours(void)
{
	git_merge_result *result;
    git_merge_strategy_resolve_options resolve_options;
    
	/* TODO: automergeable should be f2e1550a0c9e53d5811175864a29536642ae3821 */
    struct merge_index_entry merge_index_entries[] = {
		{ 0100644, "233c0919c998ed110a4b6ff36f353aec8b713487", 0, "added-in-master.txt" },
        { 0100644, "f2e1550a0c9e53d5811175864a29536642ae3821", 0, "automergeable.txt" },
        { 0100644, "4eb04c9e79e88f6640d01ff5b25ca2a60764f216", 0, "changed-in-branch.txt" },
        { 0100644, "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", 0, "changed-in-master.txt" },
        { 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 0, "conflicting.txt" },
        { 0100644, "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", 0, "unchanged.txt" },
    };

	struct merge_reuc_entry merge_reuc_entries[] = {
		{ "automergeable.txt", 0100644, 0100644, 0100644, "6212c31dab5e482247d7977e4f0dd3601decf13b", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe" },
		{ "conflicting.txt", 0100644, 0100644, 0100644, "d427e0b2e138501a3d15cc376077a3631e15bd46", "4e886e602529caa9ab11d71f86634bd1b6e0de10", "2bd0a343aeef7a2cf0d158478966a6e587ff3863" },
		{ "removed-in-branch.txt", 0100644, 0100644, 0, "dfe3f22baa1f6fce5447901c3086bae368de6bdd", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", "" },
		{ "removed-in-master.txt", 0100644, 0, 0100644, "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", "", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
	};
    
    memset(&resolve_options, 0x0, sizeof(git_merge_strategy_resolve_options));
    resolve_options.resolver = GIT_MERGE_STRATEGY_RESOLVE_OURS;
        
	cl_assert(result = merge_simple_branch(0, &resolve_options));
	cl_assert(!git_merge_result_is_fastforward(result));

    cl_assert(merge_test_index(repo_index, merge_index_entries, 6));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 4));
    
	git_merge_result_free(result);
}

void test_merge_simple__theirs(void)
{
	git_merge_result *result;
    git_merge_strategy_resolve_options resolve_options;
    
	/* TODO: automergeable should be f2e1550a0c9e53d5811175864a29536642ae3821 */
    struct merge_index_entry merge_index_entries[] = {
		{ 0100644, "233c0919c998ed110a4b6ff36f353aec8b713487", 0, "added-in-master.txt" },
        { 0100644, "f2e1550a0c9e53d5811175864a29536642ae3821", 0, "automergeable.txt" },
        { 0100644, "4eb04c9e79e88f6640d01ff5b25ca2a60764f216", 0, "changed-in-branch.txt" },
        { 0100644, "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", 0, "changed-in-master.txt" },
        { 0100644, "2bd0a343aeef7a2cf0d158478966a6e587ff3863", 0, "conflicting.txt" },
        { 0100644, "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", 0, "unchanged.txt" },
    };

	struct merge_reuc_entry merge_reuc_entries[] = {
		{ "automergeable.txt", 0100644, 0100644, 0100644, "6212c31dab5e482247d7977e4f0dd3601decf13b", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe" },
		{ "conflicting.txt", 0100644, 0100644, 0100644, "d427e0b2e138501a3d15cc376077a3631e15bd46", "4e886e602529caa9ab11d71f86634bd1b6e0de10", "2bd0a343aeef7a2cf0d158478966a6e587ff3863" },
		{ "removed-in-branch.txt", 0100644, 0100644, 0, "dfe3f22baa1f6fce5447901c3086bae368de6bdd", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", "" },
		{ "removed-in-master.txt", 0100644, 0, 0100644, "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", "", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
	};
    
    memset(&resolve_options, 0x0, sizeof(git_merge_strategy_resolve_options));
    resolve_options.resolver = GIT_MERGE_STRATEGY_RESOLVE_THEIRS;
        
	cl_assert(result = merge_simple_branch(0, &resolve_options));
	cl_assert(!git_merge_result_is_fastforward(result));

    cl_assert(merge_test_index(repo_index, merge_index_entries, 6));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 4));
    
	git_merge_result_free(result);
}
