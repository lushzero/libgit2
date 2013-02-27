#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/merge.h"
#include "buffer.h"
#include "merge.h"
#include "../merge_helpers.h"
#include "fileops.h"

static git_repository *repo;

#define TEST_REPO_PATH "merge-resolve"

#define BRANCH_RENAME_OURS					"rename_conflict_ours"
#define BRANCH_RENAME_THEIRS				"rename_conflict_theirs"

// Fixture setup and teardown
void test_merge_trees_renames__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
}

void test_merge_trees_renames__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_merge_trees_renames__merge_index(void)
{
	git_merge_index *merge_index;
	git_index *index;
	git_merge_tree_opts *opts = NULL;
	
	struct merge_index_entry merge_staged_entries[] = {
		{ 0100644, "68c6c84b091926c7d90aa6a79b2bc3bb6adccd8e", 0, "0a-no-change.txt" },
		{ 0100644, "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", 0, "0b-duplicated-in-ours.txt" },
		{ 0100644, "2f56120107d680129a5d9791b521cb1e73a2ed31", 0, "0c-duplicated-in-theirs.txt" },
		{ 0100644, "0d872f8e871a30208305978ecbf9e66d864f1638", 0, "1a-newname-in-ours-edited-in-theirs.txt" },
		{ 0100644, "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", 0, "1a-newname-in-ours.txt" },
		{ 0100644, "ed9523e62e453e50dd9be1606af19399b96e397a", 0, "1b-newname-in-theirs-edited-in-ours.txt" },
		{ 0100644, "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", 0, "1b-newname-in-theirs.txt" },
		{ 0100644, "178940b450f238a56c0d75b7955cb57b38191982", 0, "2-newname-in-both.txt" },
	};
	
	struct merge_index_conflict_data merge_conflict_entries[] = {
		{
			{ 0100644, "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", 0, "0b-rewritten-in-ours.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "e376fbdd06ebf021c92724da9f26f44212734e3e", 0, "0b-rewritten-in-ours.txt", GIT_DELTA_MODIFIED },
			{ 0100644, "b2d399ae15224e1d58066e3c8df70ce37de7a656", 0, "0b-rewritten-in-ours.txt", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_BOTH_MODIFIED,
		},
		
		{
			{ 0100644, "2f56120107d680129a5d9791b521cb1e73a2ed31", 0, "0c-rewritten-in-theirs.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "efc9121fdedaf08ba180b53ebfbcf71bd488ed09", 0, "0c-rewritten-in-theirs.txt", GIT_DELTA_MODIFIED },
			{ 0100644, "712ebba6669ea847d9829e4f1059d6c830c8b531", 0, "0c-rewritten-in-theirs.txt", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_BOTH_MODIFIED,
		},
		
		{
			{ 0100644, "18cb316b1cefa0f8a6946f0e201a8e1a6f845ab9", 0, "3a-renamed-in-ours-deleted-in-theirs.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "18cb316b1cefa0f8a6946f0e201a8e1a6f845ab9", 0, "3a-newname-in-ours-deleted-in-theirs.txt", GIT_DELTA_RENAMED },
			{ 0, "", 0, "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_RENAMED_DELETED,
		},
		
		{
			{ 0100644, "36219b49367146cb2e6a1555b5a9ebd4d0328495", 0, "3b-renamed-in-theirs-deleted-in-ours.txt", GIT_DELTA_UNMODIFIED },
			{ 0, "", 0, "", GIT_DELTA_DELETED },
			{ 0100644, "36219b49367146cb2e6a1555b5a9ebd4d0328495", 0, "3b-newname-in-theirs-deleted-in-ours.txt", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_RENAMED_DELETED,
		},
		
		{
			{ 0, "", 0, "", GIT_DELTA_UNMODIFIED },
			{ 0, "", 0, "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "8b5b53cb2aa9ceb1139f5312fcfa3cc3c5a47c9a", 0, "4a-newname-in-ours-added-in-theirs.txt", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},
		
		{
			{ 0100644, "227792b52aaa0b238bea00ec7e509b02623f168c", 0, "4a-renamed-in-ours-added-in-theirs.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "227792b52aaa0b238bea00ec7e509b02623f168c", 0, "4a-newname-in-ours-added-in-theirs.txt", GIT_DELTA_RENAMED },
			{ 0, "", 0, "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},
		
		{
			{ 0, "", 0, "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "de872ee3618b894992e9d1e18ba2ebe256a112f9", 0, "4b-newname-in-theirs-added-in-ours.txt", GIT_DELTA_ADDED },
			{ 0, "", 0, "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},
		
		{
			{ 0100644, "98d52d07c0b0bbf2b46548f6aa521295c2cb55db", 0, "4b-renamed-in-theirs-added-in-ours.txt", GIT_DELTA_UNMODIFIED },
			{ 0, "", 0, "", GIT_DELTA_DELETED },
			{ 0100644, "98d52d07c0b0bbf2b46548f6aa521295c2cb55db", 0, "4b-newname-in-theirs-added-in-ours.txt", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},
		
		{
			{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 0, "5-both-renamed-1-to-2.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 0, "5-both-renamed-1-to-2-ours.txt", GIT_DELTA_RENAMED },
			{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 0, "5-both-renamed-1-to-2-theirs.txt", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2,
		},
		
		{
			
			{ 0100644, "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", 0, "6-both-renamed-side-1.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", 0, "6-both-renamed.txt", GIT_DELTA_RENAMED },
			{ 0100644, "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", 0, "6-both-renamed-side-1.txt", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1,
		},
		
		{
			{ 0100644, "b69fe837e4cecfd4c9a40cdca7c138468687df07", 0, "6-both-renamed-side-2.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "b69fe837e4cecfd4c9a40cdca7c138468687df07", 0, "6-both-renamed-side-2.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "b69fe837e4cecfd4c9a40cdca7c138468687df07", 0, "6-both-renamed.txt", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1,
		},
	};
	
	struct merge_index_conflict_data merge_reuc_entries[] = {
		{
			{ 0100644, "c3d02eeef75183df7584d8d13ac03053910c1301", 0, "1a-renamed-in-ours-edited-in-theirs.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "c3d02eeef75183df7584d8d13ac03053910c1301", 0, "1a-newname-in-ours-edited-in-theirs.txt", GIT_DELTA_RENAMED },
			{ 0100644, "0d872f8e871a30208305978ecbf9e66d864f1638", 0, "1a-renamed-in-ours-edited-in-theirs.txt", GIT_DELTA_MODIFIED },
		},
		
		{
			{ 0100644, "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", 0, "1a-renamed-in-ours.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", 0, "1a-newname-in-ours.txt", GIT_DELTA_RENAMED },
			{ 0100644, "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", 0, "1a-renamed-in-ours.txt", GIT_DELTA_UNMODIFIED },
		},
		
		{
			{ 0100644, "241a1005cd9b980732741b74385b891142bcba28", 0, "1b-renamed-in-theirs-edited-in-ours.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "ed9523e62e453e50dd9be1606af19399b96e397a", 0, "1b-renamed-in-theirs-edited-in-ours.txt", GIT_DELTA_MODIFIED },
			{ 0100644, "241a1005cd9b980732741b74385b891142bcba28", 0, "1b-newname-in-theirs-edited-in-ours.txt", GIT_DELTA_RENAMED },
		},
		
		{
			{ 0100644, "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", 0, "1b-renamed-in-theirs.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", 0, "1b-renamed-in-theirs.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", 0, "1b-newname-in-theirs.txt", GIT_DELTA_RENAMED },
		},
		
		{
			{ 0100644, "178940b450f238a56c0d75b7955cb57b38191982", 0, "2-renamed-in-both.txt", GIT_DELTA_UNMODIFIED },
			{ 0100644, "178940b450f238a56c0d75b7955cb57b38191982", 0, "2-newname-in-both.txt", GIT_DELTA_RENAMED },
			{ 0100644, "178940b450f238a56c0d75b7955cb57b38191982", 0, "2-newname-in-both.txt", GIT_DELTA_RENAMED },
		},
	};
	
	cl_git_pass(merge_trees_from_branches(&merge_index, &index, repo,
		BRANCH_RENAME_OURS, BRANCH_RENAME_THEIRS,
		opts));

	cl_assert(merge_test_merge_index_staged(merge_index, merge_staged_entries, 8));
	cl_assert(merge_test_merge_conflicts(&merge_index->conflicts, merge_conflict_entries, 11));
	cl_assert(merge_test_merge_conflicts(&merge_index->resolved, merge_reuc_entries, 5));

	git_merge_index_free(merge_index);
	git_index_free(index);
}

void test_merge_trees_renames__index(void)
{
	git_merge_index *merge_index;
	git_index *index;
	git_merge_tree_opts *opts = NULL;

	struct merge_index_entry merge_index_entries[] = {
		{ 0100644, "68c6c84b091926c7d90aa6a79b2bc3bb6adccd8e", 0, "0a-no-change.txt" },
		{ 0100644, "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", 0, "0b-duplicated-in-ours.txt" },
		{ 0100644, "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", 1, "0b-rewritten-in-ours.txt" },
		{ 0100644, "e376fbdd06ebf021c92724da9f26f44212734e3e", 2, "0b-rewritten-in-ours.txt" },
		{ 0100644, "b2d399ae15224e1d58066e3c8df70ce37de7a656", 3, "0b-rewritten-in-ours.txt" },
		{ 0100644, "2f56120107d680129a5d9791b521cb1e73a2ed31", 0, "0c-duplicated-in-theirs.txt" },
		{ 0100644, "2f56120107d680129a5d9791b521cb1e73a2ed31", 1, "0c-rewritten-in-theirs.txt" },
		{ 0100644, "efc9121fdedaf08ba180b53ebfbcf71bd488ed09", 2, "0c-rewritten-in-theirs.txt" },
		{ 0100644, "712ebba6669ea847d9829e4f1059d6c830c8b531", 3, "0c-rewritten-in-theirs.txt" },
		{ 0100644, "0d872f8e871a30208305978ecbf9e66d864f1638", 0, "1a-newname-in-ours-edited-in-theirs.txt" },
		{ 0100644, "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", 0, "1a-newname-in-ours.txt" },
		{ 0100644, "ed9523e62e453e50dd9be1606af19399b96e397a", 0, "1b-newname-in-theirs-edited-in-ours.txt" },
		{ 0100644, "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", 0, "1b-newname-in-theirs.txt" },
		{ 0100644, "178940b450f238a56c0d75b7955cb57b38191982", 0, "2-newname-in-both.txt" },
		{ 0100644, "18cb316b1cefa0f8a6946f0e201a8e1a6f845ab9", 2, "3a-newname-in-ours-deleted-in-theirs.txt" },
		{ 0100644, "36219b49367146cb2e6a1555b5a9ebd4d0328495", 3, "3b-newname-in-theirs-deleted-in-ours.txt" },
		{ 0100644, "227792b52aaa0b238bea00ec7e509b02623f168c", 2, "4a-newname-in-ours-added-in-theirs.txt" },
		{ 0100644, "98d52d07c0b0bbf2b46548f6aa521295c2cb55db", 3, "4b-newname-in-theirs-added-in-ours.txt" },
		{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 2, "5-both-renamed-1-to-2-ours.txt" },
		{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 3, "5-both-renamed-1-to-2-theirs.txt" },
		{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 1, "5-both-renamed-1-to-2.txt" },
		{ 0100644, "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", 2, "6-both-renamed.txt" },
		{ 0100644, "b69fe837e4cecfd4c9a40cdca7c138468687df07", 3, "6-both-renamed.txt" },
	};
	
	struct merge_reuc_entry merge_reuc_entries[] = {
		{ "1a-newname-in-ours-edited-in-theirs.txt",
			0, 0100644, 0,
			"",
			"c3d02eeef75183df7584d8d13ac03053910c1301",
			"" },

		{ "1a-newname-in-ours.txt",
			0, 0100644, 0,
			"",
			"d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb",
			"" },

		{ "1a-renamed-in-ours-edited-in-theirs.txt",
			0100644, 0, 0100644,
			"c3d02eeef75183df7584d8d13ac03053910c1301",
			"",
			"0d872f8e871a30208305978ecbf9e66d864f1638" },

		{ "1a-renamed-in-ours.txt",
			0100644, 0, 0100644,
			"d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb",
			"",
			"d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb" },

		{ "1b-newname-in-theirs-edited-in-ours.txt",
			0, 0, 0100644,
			"",
			"",
			"241a1005cd9b980732741b74385b891142bcba28" },
		
		{ "1b-newname-in-theirs.txt",
			0, 0, 0100644,
			"",
			"",
			"2b5f1f181ee3b58ea751f5dd5d8f9b445520a136" },

		{ "1b-renamed-in-theirs-edited-in-ours.txt",
			0100644, 0100644, 0,
			"241a1005cd9b980732741b74385b891142bcba28",
			"ed9523e62e453e50dd9be1606af19399b96e397a",
			"" },

		{ "1b-renamed-in-theirs.txt",
			0100644, 0100644, 0,
			"2b5f1f181ee3b58ea751f5dd5d8f9b445520a136",
			"2b5f1f181ee3b58ea751f5dd5d8f9b445520a136",
			"" },

		{ "2-newname-in-both.txt",
			0, 0100644, 0100644,
			"",
			"178940b450f238a56c0d75b7955cb57b38191982",
			"178940b450f238a56c0d75b7955cb57b38191982" },

		{ "2-renamed-in-both.txt",
			0100644, 0, 0,
			"178940b450f238a56c0d75b7955cb57b38191982",
			"",
			"" },
	};

	cl_git_pass(merge_trees_from_branches(&merge_index, &index, repo,
		BRANCH_RENAME_OURS, BRANCH_RENAME_THEIRS,
		opts));
	
	cl_assert(merge_test_index(index, merge_index_entries, 23));
	cl_assert(merge_test_reuc(index, merge_reuc_entries, 10));
	
	git_merge_index_free(merge_index);
	git_index_free(index);
}

void test_merge_trees_renames__no_rename_index(void)
{
	git_merge_index *merge_index;
	git_index *index;
	git_merge_tree_opts opts = GIT_MERGE_TREE_OPTS_INIT;
	
	struct merge_index_entry merge_index_entries[] = {
		{ 0100644, "68c6c84b091926c7d90aa6a79b2bc3bb6adccd8e", 0, "0a-no-change.txt" },
		{ 0100644, "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", 0, "0b-duplicated-in-ours.txt" },
		{ 0100644, "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", 1, "0b-rewritten-in-ours.txt" },
		{ 0100644, "e376fbdd06ebf021c92724da9f26f44212734e3e", 2, "0b-rewritten-in-ours.txt" },
		{ 0100644, "b2d399ae15224e1d58066e3c8df70ce37de7a656", 3, "0b-rewritten-in-ours.txt" },
		{ 0100644, "2f56120107d680129a5d9791b521cb1e73a2ed31", 0, "0c-duplicated-in-theirs.txt" },
		{ 0100644, "2f56120107d680129a5d9791b521cb1e73a2ed31", 1, "0c-rewritten-in-theirs.txt" },
		{ 0100644, "efc9121fdedaf08ba180b53ebfbcf71bd488ed09", 2, "0c-rewritten-in-theirs.txt" },
		{ 0100644, "712ebba6669ea847d9829e4f1059d6c830c8b531", 3, "0c-rewritten-in-theirs.txt" },
		{ 0100644, "c3d02eeef75183df7584d8d13ac03053910c1301", 0, "1a-newname-in-ours-edited-in-theirs.txt" },
		{ 0100644, "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", 0, "1a-newname-in-ours.txt" },
		{ 0100644, "c3d02eeef75183df7584d8d13ac03053910c1301", 1, "1a-renamed-in-ours-edited-in-theirs.txt" },
		{ 0100644, "0d872f8e871a30208305978ecbf9e66d864f1638", 3, "1a-renamed-in-ours-edited-in-theirs.txt" },
		{ 0100644, "241a1005cd9b980732741b74385b891142bcba28", 0, "1b-newname-in-theirs-edited-in-ours.txt" },
		{ 0100644, "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", 0, "1b-newname-in-theirs.txt" },
		{ 0100644, "241a1005cd9b980732741b74385b891142bcba28", 1, "1b-renamed-in-theirs-edited-in-ours.txt" },
		{ 0100644, "ed9523e62e453e50dd9be1606af19399b96e397a", 2, "1b-renamed-in-theirs-edited-in-ours.txt" },
		{ 0100644, "178940b450f238a56c0d75b7955cb57b38191982", 0, "2-newname-in-both.txt" },
		{ 0100644, "18cb316b1cefa0f8a6946f0e201a8e1a6f845ab9", 0, "3a-newname-in-ours-deleted-in-theirs.txt" },
		{ 0100644, "36219b49367146cb2e6a1555b5a9ebd4d0328495", 0, "3b-newname-in-theirs-deleted-in-ours.txt" },
		{ 0100644, "227792b52aaa0b238bea00ec7e509b02623f168c", 2, "4a-newname-in-ours-added-in-theirs.txt" },
		{ 0100644, "8b5b53cb2aa9ceb1139f5312fcfa3cc3c5a47c9a", 3, "4a-newname-in-ours-added-in-theirs.txt" },
		{ 0100644, "de872ee3618b894992e9d1e18ba2ebe256a112f9", 2, "4b-newname-in-theirs-added-in-ours.txt" },
		{ 0100644, "98d52d07c0b0bbf2b46548f6aa521295c2cb55db", 3, "4b-newname-in-theirs-added-in-ours.txt" },
		{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 0, "5-both-renamed-1-to-2-ours.txt" },
		{ 0100644, "d8fa77b6833082c1ea36b7828a582d4c43882450", 0, "5-both-renamed-1-to-2-theirs.txt" },
		{ 0100644, "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", 2, "6-both-renamed.txt" },
		{ 0100644, "b69fe837e4cecfd4c9a40cdca7c138468687df07", 3, "6-both-renamed.txt" },
	};
	
	cl_git_pass(merge_trees_from_branches(&merge_index, &index, repo,
		BRANCH_RENAME_OURS, BRANCH_RENAME_THEIRS,
		&opts));
	
	cl_assert(merge_test_index(index, merge_index_entries, 28));
	
	git_merge_index_free(merge_index);
	git_index_free(index);
}

