#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/merge.h"
#include "git2/merge_branches.h"
#include "buffer.h"
#include "merge.h"
#include "merge_helpers.h"
#include "fileops.h"

static git_repository *repo;
static git_index *repo_index;

#define TEST_REPO_PATH "merge-resolve"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"

#define THEIRS_SIMPLE_BRANCH        "branch"
#define THEIRS_SIMPLE_OID           "7cb63eed597130ba4abb87b3e544b85021905520"

#define THEIRS_UNRELATED_BRANCH		"unrelated"
#define THEIRS_UNRELATED_OID		"55b4e4687e7a0d9ca367016ed930f385d4022e6f"
#define THEIRS_UNRELATED_PARENT		"d6cf6c7741b3316826af1314042550c97ded1d50"

/* Non-conflicting files, index entries are common to every merge operation */
#define ADDED_IN_MASTER_INDEX_ENTRY	\
	{ 0100644, "233c0919c998ed110a4b6ff36f353aec8b713487", 0, \
	  "added-in-master.txt" }
#define AUTOMERGEABLE_INDEX_ENTRY \
	{ 0100644, "f2e1550a0c9e53d5811175864a29536642ae3821", 0, \
	  "automergeable.txt" }
#define CHANGED_IN_BRANCH_INDEX_ENTRY \
	{ 0100644, "4eb04c9e79e88f6640d01ff5b25ca2a60764f216", 0, \
	  "changed-in-branch.txt" }
#define CHANGED_IN_MASTER_INDEX_ENTRY \
	{ 0100644, "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", 0, \
	  "changed-in-master.txt" }
#define UNCHANGED_INDEX_ENTRY \
	{ 0100644, "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", 0, \
	  "unchanged.txt" }

/* Unrelated files */
#define UNRELATED_NEW1 \
	{ 0100644, "ef58fdd8086c243bdc81f99e379acacfd21d32d6", 0, \
	  "new-in-unrelated1.txt" }
#define UNRELATED_NEW2 \
	{ 0100644, "948ba6e701c1edab0c2d394fb7c5538334129793", 0, \
	  "new-in-unrelated2.txt" }

/* Expected REUC entries */
#define AUTOMERGEABLE_REUC_ENTRY \
	{ "automergeable.txt", 0100644, 0100644, 0100644, \
	  "6212c31dab5e482247d7977e4f0dd3601decf13b", \
	  "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", \
	  "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe" }
#define CONFLICTING_REUC_ENTRY \
	{ "conflicting.txt", 0100644, 0100644, 0100644, \
	  "d427e0b2e138501a3d15cc376077a3631e15bd46", \
	  "4e886e602529caa9ab11d71f86634bd1b6e0de10", \
	  "2bd0a343aeef7a2cf0d158478966a6e587ff3863" }
#define REMOVED_IN_BRANCH_REUC_ENTRY \
	{ "removed-in-branch.txt", 0100644, 0100644, 0, \
	  "dfe3f22baa1f6fce5447901c3086bae368de6bdd", \
	  "dfe3f22baa1f6fce5447901c3086bae368de6bdd", \
	  "" }
#define REMOVED_IN_MASTER_REUC_ENTRY \
	{ "removed-in-master.txt", 0100644, 0, 0100644, \
	  "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", \
	  "", \
	  "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" }

#define AUTOMERGEABLE_MERGED_FILE \
	"this file is changed in master\n" \
	"this file is automergeable\n" \
	"this file is automergeable\n" \
	"this file is automergeable\n" \
	"this file is automergeable\n" \
	"this file is automergeable\n" \
	"this file is automergeable\n" \
	"this file is automergeable\n" \
	"this file is changed in branch\n"

#define AUTOMERGEABLE_MERGED_FILE_CRLF \
	"this file is changed in master\r\n" \
	"this file is automergeable\r\n" \
	"this file is automergeable\r\n" \
	"this file is automergeable\r\n" \
	"this file is automergeable\r\n" \
	"this file is automergeable\r\n" \
	"this file is automergeable\r\n" \
	"this file is automergeable\r\n" \
	"this file is changed in branch\r\n"

#define CONFLICTING_DIFF3_FILE \
	"<<<<<<< HEAD\n" \
	"this file is changed in master and branch\n" \
	"=======\n" \
	"this file is changed in branch and master\n" \
	">>>>>>> 7cb63eed597130ba4abb87b3e544b85021905520\n"

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

static git_merge_result *merge_simple_branch(int automerge_flags, int conflict_flags)
{
	git_oid their_oids[1];
    git_merge_head *their_heads[1];
	git_merge_result *result;
	git_merge_opts opts = GIT_MERGE_OPTS_INIT;
    
	cl_git_pass(git_oid_fromstr(&their_oids[0], THEIRS_SIMPLE_OID));
	cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &their_oids[0]));
    
	opts.merge_tree_opts.automerge_flags = automerge_flags;
	opts.conflict_flags = conflict_flags;
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, &opts));

	git_merge_head_free(their_heads[0]);
    
	return result;
}

static void set_core_autocrlf_to(git_repository *repo, bool value)
{
	git_config *cfg;

	cl_git_pass(git_repository_config(&cfg, repo));
	cl_git_pass(git_config_set_bool(cfg, "core.autocrlf", value));

	git_config_free(cfg);
}

void test_merge_simple__automerge(void)
{
	git_index *index;
	const git_index_entry *entry;

	git_merge_result *result;
	git_buf automergeable_buf = GIT_BUF_INIT;
    
	struct merge_index_entry merge_index_entries[] = {
		ADDED_IN_MASTER_INDEX_ENTRY,
		AUTOMERGEABLE_INDEX_ENTRY,
		CHANGED_IN_BRANCH_INDEX_ENTRY,
		CHANGED_IN_MASTER_INDEX_ENTRY,

		{ 0100644, "d427e0b2e138501a3d15cc376077a3631e15bd46", 1, "conflicting.txt" },
		{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 2, "conflicting.txt" },
		{ 0100644, "2bd0a343aeef7a2cf0d158478966a6e587ff3863", 3, "conflicting.txt" },

		UNCHANGED_INDEX_ENTRY,
    };

	struct merge_reuc_entry merge_reuc_entries[] = {
		AUTOMERGEABLE_REUC_ENTRY,
		REMOVED_IN_BRANCH_REUC_ENTRY,
		REMOVED_IN_MASTER_REUC_ENTRY
	};


	set_core_autocrlf_to(repo, false);

	cl_assert(result = merge_simple_branch(0, 0));
	cl_assert(!git_merge_result_is_fastforward(result));

	cl_git_pass(git_futils_readbuffer(&automergeable_buf,
		TEST_REPO_PATH "/automergeable.txt"));
	cl_assert(strcmp(automergeable_buf.ptr, AUTOMERGEABLE_MERGED_FILE) == 0);
	git_buf_free(&automergeable_buf);

	cl_assert(merge_test_index(repo_index, merge_index_entries, 8));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 3));

	git_merge_result_free(result);

	git_repository_index(&index, repo);

	cl_assert((entry = git_index_get_bypath(index, "automergeable.txt", 0)) != NULL);
	cl_assert(entry->file_size == strlen(AUTOMERGEABLE_MERGED_FILE));
    
	git_index_free(index);
}

void test_merge_simple__automerge_crlf(void)
{
#ifdef GIT_WIN32
	git_index *index;
	const git_index_entry *entry;

	git_merge_result *result;
	git_buf automergeable_buf = GIT_BUF_INIT;
    
	struct merge_index_entry merge_index_entries[] = {
		ADDED_IN_MASTER_INDEX_ENTRY,
		AUTOMERGEABLE_INDEX_ENTRY,
		CHANGED_IN_BRANCH_INDEX_ENTRY,
		CHANGED_IN_MASTER_INDEX_ENTRY,

		{ 0100644, "d427e0b2e138501a3d15cc376077a3631e15bd46", 1, "conflicting.txt" },
		{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 2, "conflicting.txt" },
		{ 0100644, "2bd0a343aeef7a2cf0d158478966a6e587ff3863", 3, "conflicting.txt" },

		UNCHANGED_INDEX_ENTRY,
	};

	struct merge_reuc_entry merge_reuc_entries[] = {
		AUTOMERGEABLE_REUC_ENTRY,
		REMOVED_IN_BRANCH_REUC_ENTRY,
		REMOVED_IN_MASTER_REUC_ENTRY
	};

	set_core_autocrlf_to(repo, true);

	cl_assert(result = merge_simple_branch(0, 0));
	cl_assert(!git_merge_result_is_fastforward(result));

	cl_git_pass(git_futils_readbuffer(&automergeable_buf,
		TEST_REPO_PATH "/automergeable.txt"));
	cl_assert(strcmp(automergeable_buf.ptr, AUTOMERGEABLE_MERGED_FILE_CRLF) == 0);
	git_buf_free(&automergeable_buf);

	cl_assert(merge_test_index(repo_index, merge_index_entries, 8));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 3));

	git_merge_result_free(result);

	git_repository_index(&index, repo);

	cl_assert((entry = git_index_get_bypath(index, "automergeable.txt", 0)) != NULL);
	cl_assert(entry->file_size == strlen(AUTOMERGEABLE_MERGED_FILE_CRLF));
    
	git_index_free(index);
#endif /* GIT_WIN32 */
}

void test_merge_simple__diff3(void)
{
	git_merge_result *result;
	git_buf conflicting_buf = GIT_BUF_INIT;
    
	struct merge_index_entry merge_index_entries[] = {
		ADDED_IN_MASTER_INDEX_ENTRY,
		AUTOMERGEABLE_INDEX_ENTRY,
		CHANGED_IN_BRANCH_INDEX_ENTRY,
		CHANGED_IN_MASTER_INDEX_ENTRY,

		{ 0100644, "d427e0b2e138501a3d15cc376077a3631e15bd46", 1, "conflicting.txt" },
		{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 2, "conflicting.txt" },
		{ 0100644, "2bd0a343aeef7a2cf0d158478966a6e587ff3863", 3, "conflicting.txt" },

		UNCHANGED_INDEX_ENTRY,
	};

	struct merge_reuc_entry merge_reuc_entries[] = {
		AUTOMERGEABLE_REUC_ENTRY,
		REMOVED_IN_BRANCH_REUC_ENTRY,
		REMOVED_IN_MASTER_REUC_ENTRY
	};
    
	cl_assert(result = merge_simple_branch(0, 0));
	cl_assert(!git_merge_result_is_fastforward(result));

	cl_git_pass(git_futils_readbuffer(&conflicting_buf,
		TEST_REPO_PATH "/conflicting.txt"));
	cl_assert(strcmp(conflicting_buf.ptr, CONFLICTING_DIFF3_FILE) == 0);
	git_buf_free(&conflicting_buf);

	cl_assert(merge_test_index(repo_index, merge_index_entries, 8));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 3));

	git_merge_result_free(result);
}

void test_merge_simple__no_diff3(void)
{
	git_merge_result *result;
    
	struct merge_index_entry merge_index_entries[] = {
		ADDED_IN_MASTER_INDEX_ENTRY,
		AUTOMERGEABLE_INDEX_ENTRY,
		CHANGED_IN_BRANCH_INDEX_ENTRY,
		CHANGED_IN_MASTER_INDEX_ENTRY,

		{ 0100644, "d427e0b2e138501a3d15cc376077a3631e15bd46", 1, "conflicting.txt" },
		{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 2, "conflicting.txt" },
		{ 0100644, "2bd0a343aeef7a2cf0d158478966a6e587ff3863", 3, "conflicting.txt" },

		UNCHANGED_INDEX_ENTRY,
	};

	struct merge_reuc_entry merge_reuc_entries[] = {
		AUTOMERGEABLE_REUC_ENTRY,
		REMOVED_IN_BRANCH_REUC_ENTRY,
		REMOVED_IN_MASTER_REUC_ENTRY
	};
    
	cl_assert(result = merge_simple_branch(0, GIT_MERGE_CONFLICT_NO_DIFF3));
	cl_assert(!git_merge_result_is_fastforward(result));

	cl_assert(merge_test_index(repo_index, merge_index_entries, 8));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 3));

	cl_assert(!git_path_exists(TEST_REPO_PATH "/conflicting.txt"));
	cl_assert(git_path_exists(TEST_REPO_PATH "/conflicting.txt~7cb63eed597130ba4abb87b3e544b85021905520"));
	cl_assert(git_path_exists(TEST_REPO_PATH "/conflicting.txt~HEAD"));
    
	git_merge_result_free(result);
}

void test_merge_simple__favor_ours(void)
{
	git_merge_result *result;
    
	struct merge_index_entry merge_index_entries[] = {
		ADDED_IN_MASTER_INDEX_ENTRY,
		AUTOMERGEABLE_INDEX_ENTRY,
		CHANGED_IN_BRANCH_INDEX_ENTRY,
		CHANGED_IN_MASTER_INDEX_ENTRY,
		{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 0, "conflicting.txt" },
		UNCHANGED_INDEX_ENTRY,
	};

	struct merge_reuc_entry merge_reuc_entries[] = {
		AUTOMERGEABLE_REUC_ENTRY,
		CONFLICTING_REUC_ENTRY,
		REMOVED_IN_BRANCH_REUC_ENTRY,
		REMOVED_IN_MASTER_REUC_ENTRY,
	};
    
	cl_assert(result = merge_simple_branch(GIT_MERGE_AUTOMERGE_FAVOR_OURS, 0));
	cl_assert(!git_merge_result_is_fastforward(result));

	cl_assert(merge_test_index(repo_index, merge_index_entries, 6));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 4));
    
	git_merge_result_free(result);
}

void test_merge_simple__favor_theirs(void)
{
	git_merge_result *result;
    
	struct merge_index_entry merge_index_entries[] = {
		ADDED_IN_MASTER_INDEX_ENTRY,
		AUTOMERGEABLE_INDEX_ENTRY,
		CHANGED_IN_BRANCH_INDEX_ENTRY,
		CHANGED_IN_MASTER_INDEX_ENTRY,
		{ 0100644, "2bd0a343aeef7a2cf0d158478966a6e587ff3863", 0, "conflicting.txt" },
		UNCHANGED_INDEX_ENTRY,
	};

	struct merge_reuc_entry merge_reuc_entries[] = {
		AUTOMERGEABLE_REUC_ENTRY,
		CONFLICTING_REUC_ENTRY,
		REMOVED_IN_BRANCH_REUC_ENTRY,
		REMOVED_IN_MASTER_REUC_ENTRY,
	};
    
	cl_assert(result = merge_simple_branch(GIT_MERGE_AUTOMERGE_FAVOR_THEIRS, 0));
	cl_assert(!git_merge_result_is_fastforward(result));

	cl_assert(merge_test_index(repo_index, merge_index_entries, 6));
	cl_assert(merge_test_reuc(repo_index, merge_reuc_entries, 4));
    
	git_merge_result_free(result);
}

void test_merge_simple__unrelated(void)
{
	git_oid their_oids[1];
	git_merge_head *their_heads[1];
	git_merge_result *result;
	git_merge_opts opts = GIT_MERGE_OPTS_INIT;
    
	struct merge_index_entry merge_index_entries[] = {
		{ 0100644, "233c0919c998ed110a4b6ff36f353aec8b713487", 0, "added-in-master.txt" },
		{ 0100644, "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", 0, "automergeable.txt" },
		{ 0100644, "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", 0, "changed-in-branch.txt" },
		{ 0100644, "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", 0, "changed-in-master.txt" },
		{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 0, "conflicting.txt" },
		{ 0100644, "ef58fdd8086c243bdc81f99e379acacfd21d32d6", 0, "new-in-unrelated1.txt" },
		{ 0100644, "948ba6e701c1edab0c2d394fb7c5538334129793", 0, "new-in-unrelated2.txt" },
		{ 0100644, "dfe3f22baa1f6fce5447901c3086bae368de6bdd", 0, "removed-in-branch.txt" },
		{ 0100644, "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", 0, "unchanged.txt" },
	};
    
	cl_git_pass(git_oid_fromstr(&their_oids[0], THEIRS_UNRELATED_PARENT));
	cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &their_oids[0]));
    
	opts.merge_tree_opts.automerge_flags = 0;
	opts.conflict_flags = 0;
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, &opts));

	cl_assert(merge_test_index(repo_index, merge_index_entries, 9));

	git_merge_head_free(their_heads[0]);
}

void test_merge_simple__unrelated_with_conflicts(void)
{
	git_oid their_oids[1];
	git_merge_head *their_heads[1];
	git_merge_result *result;
	git_merge_opts opts = GIT_MERGE_OPTS_INIT;
    
	struct merge_index_entry merge_index_entries[] = {
		{ 0100644, "233c0919c998ed110a4b6ff36f353aec8b713487", 0, "added-in-master.txt" },
		{ 0100644, "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", 2, "automergeable.txt" },
		{ 0100644, "d07ec190c306ec690bac349e87d01c4358e49bb2", 3, "automergeable.txt" },
		{ 0100644, "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", 0, "changed-in-branch.txt" },
		{ 0100644, "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", 0, "changed-in-master.txt" },
		{ 0100644, "4e886e602529caa9ab11d71f86634bd1b6e0de10", 2, "conflicting.txt" },
		{ 0100644, "4b253da36a0ae8bfce63aeabd8c5b58429925594", 3, "conflicting.txt" },
		{ 0100644, "ef58fdd8086c243bdc81f99e379acacfd21d32d6", 0, "new-in-unrelated1.txt" },
		{ 0100644, "948ba6e701c1edab0c2d394fb7c5538334129793", 0, "new-in-unrelated2.txt" },
		{ 0100644, "dfe3f22baa1f6fce5447901c3086bae368de6bdd", 0, "removed-in-branch.txt" },
		{ 0100644, "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", 0, "unchanged.txt" },
	};
    
	cl_git_pass(git_oid_fromstr(&their_oids[0], THEIRS_UNRELATED_OID));
	cl_git_pass(git_merge_head_from_oid(&their_heads[0], repo, &their_oids[0]));
    
	opts.merge_tree_opts.automerge_flags = 0;
	opts.conflict_flags = 0;
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, &opts));
	
	cl_assert(merge_test_index(repo_index, merge_index_entries, 11));
	
	git_merge_head_free(their_heads[0]);
}
