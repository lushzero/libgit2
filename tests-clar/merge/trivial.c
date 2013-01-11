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


static int merge_trivial(const char *ours, const char *theirs, bool automerge)
{
	git_buf branch_buf = GIT_BUF_INIT;
	git_checkout_opts checkout_opts = GIT_CHECKOUT_OPTS_INIT;
	git_reference *our_ref, *their_ref;
    git_merge_head *their_heads[1];
	git_merge_opts opts = GIT_MERGE_OPTS_INIT;
	git_merge_result *result;

	checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE;

	opts.merge_trees_opts.resolve_flags |= automerge ? 0 : GIT_MERGE_RESOLVE_NO_REMOVED;
	opts.merge_trees_opts.resolve_flags |= automerge ? 0 : GIT_MERGE_RESOLVE_NO_AUTOMERGE;

	git_buf_printf(&branch_buf, "%s%s", GIT_REFS_HEADS_DIR, ours);
	cl_git_pass(git_reference_symbolic_create(&our_ref, repo, "HEAD", branch_buf.ptr, 1));

	cl_git_pass(git_checkout_head(repo, &checkout_opts));

	git_buf_clear(&branch_buf);
	git_buf_printf(&branch_buf, "%s%s", GIT_REFS_HEADS_DIR, theirs);
	cl_git_pass(git_reference_lookup(&their_ref, repo, branch_buf.ptr));
	cl_git_pass(git_merge_head_from_ref(&their_heads[0], repo, their_ref));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, &opts));

	git_buf_free(&branch_buf);
	git_reference_free(our_ref);
	git_reference_free(their_ref);
	git_merge_head_free(their_heads[0]);
	git_merge_result_free(result);

	return 0;
}

static int merge_trivial_conflict_entrycount(void)
{
	const git_index_entry *entry;
	size_t count = 0;
	size_t i;

	for (i = 0; i < git_index_entrycount(repo_index); i++) {
		cl_assert(entry = git_index_get_byindex(repo_index, i));

		if (git_index_entry_stage(entry) > 0)
			count++;
	}

	return count;
}

/* 2ALT: ancest:(empty)+, head:*empty*, remote:remote = result:remote */
void test_merge_trivial__2alt(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-2alt", "trivial-2alt-branch", 0));

	cl_assert(entry = git_index_get_bypath(repo_index, "new-in-branch.txt", 0));
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);
	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 3ALT: ancest:(empty)+, head:head, remote:*empty* = result:head */
void test_merge_trivial__3alt(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-3alt", "trivial-3alt-branch", 0));

	cl_assert(entry = git_index_get_bypath(repo_index, "new-in-3alt.txt", 0));
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);
	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 4: ancest:(empty)^, head:head, remote:remote = result:no merge */
void test_merge_trivial__4(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-4", "trivial-4-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "new-and-different.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 2);
	cl_assert(entry = git_index_get_bypath(repo_index, "new-and-different.txt", 2));
	cl_assert(entry = git_index_get_bypath(repo_index, "new-and-different.txt", 3));
}

/* 5ALT: ancest:*, head:head, remote:head = result:head */
void test_merge_trivial__5alt_1(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-5alt-1", "trivial-5alt-1-branch", 0));

	cl_assert(entry = git_index_get_bypath(repo_index, "new-and-same.txt", 0));
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);
	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 5ALT: ancest:*, head:head, remote:head = result:head */
void test_merge_trivial__5alt_2(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-5alt-2", "trivial-5alt-2-branch", 0));

	cl_assert(entry = git_index_get_bypath(repo_index, "modified-to-same.txt", 0));
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);
	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 6: ancest:ancest+, head:(empty), remote:(empty) = result:no merge */
void test_merge_trivial__6(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-6", "trivial-6-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-both.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 1);
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-both.txt", 1));
}

/* 6: ancest:ancest+, head:(empty), remote:(empty) = result:no merge */
void test_merge_trivial__6_automerge(void)
{
	const git_index_entry *entry;
	const git_index_reuc_entry *reuc;

	cl_git_pass(merge_trivial("trivial-6", "trivial-6-branch", 1));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-both.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 1);
	cl_assert(reuc = git_index_reuc_get_bypath(repo_index, "removed-in-both.txt"));

	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 8: ancest:ancest^, head:(empty), remote:ancest = result:no merge */
void test_merge_trivial__8(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-8", "trivial-8-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-8.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 2);
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-8.txt", 1));
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-8.txt", 3));
}

/* 8: ancest:ancest^, head:(empty), remote:ancest = result:no merge */
void test_merge_trivial__8_automerge(void)
{
	const git_index_entry *entry;
	const git_index_reuc_entry *reuc;

	cl_git_pass(merge_trivial("trivial-8", "trivial-8-branch", 1));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-8.txt", 0)) == NULL);

	cl_assert(git_index_reuc_entrycount(repo_index) == 1);
	cl_assert(reuc = git_index_reuc_get_bypath(repo_index, "removed-in-8.txt"));

	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 7: ancest:ancest+, head:(empty), remote:remote = result:no merge */
void test_merge_trivial__7(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-7", "trivial-7-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-7.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 2);
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-7.txt", 1));
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-7.txt", 3));
}

/* 7: ancest:ancest+, head:(empty), remote:remote = result:no merge */
void test_merge_trivial__7_automerge(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-7", "trivial-7-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-7.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 2);
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-7.txt", 1));
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-7.txt", 3));
}

/* 10: ancest:ancest^, head:ancest, remote:(empty) = result:no merge */
void test_merge_trivial__10(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-10", "trivial-10-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-10-branch.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 2);
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-10-branch.txt", 1));
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-10-branch.txt", 2));
}

/* 10: ancest:ancest^, head:ancest, remote:(empty) = result:no merge */
void test_merge_trivial__10_automerge(void)
{
	const git_index_entry *entry;
	const git_index_reuc_entry *reuc;

	cl_git_pass(merge_trivial("trivial-10", "trivial-10-branch", 1));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-10-branch.txt", 0)) == NULL);

	cl_assert(git_index_reuc_entrycount(repo_index) == 1);
	cl_assert(reuc = git_index_reuc_get_bypath(repo_index, "removed-in-10-branch.txt"));

	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 9: ancest:ancest+, head:head, remote:(empty) = result:no merge */
void test_merge_trivial__9(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-9", "trivial-9-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-9-branch.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 2);
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-9-branch.txt", 1));
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-9-branch.txt", 2));
}

/* 9: ancest:ancest+, head:head, remote:(empty) = result:no merge */
void test_merge_trivial__9_automerge(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-9", "trivial-9-branch", 1));

	cl_assert((entry = git_index_get_bypath(repo_index, "removed-in-9-branch.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 2);
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-9-branch.txt", 1));
	cl_assert(entry = git_index_get_bypath(repo_index, "removed-in-9-branch.txt", 2));
}

/* 13: ancest:ancest+, head:head, remote:ancest = result:head */
void test_merge_trivial__13(void)
{
	const git_index_entry *entry;
	git_oid expected_oid;

	cl_git_pass(merge_trivial("trivial-13", "trivial-13-branch", 0));

	cl_assert(entry = git_index_get_bypath(repo_index, "modified-in-13.txt", 0));
	cl_git_pass(git_oid_fromstr(&expected_oid, "1cff9ec6a47a537380dedfdd17c9e76d74259a2b"));
	cl_assert(git_oid_cmp(&entry->oid, &expected_oid) == 0);

	cl_assert(git_index_reuc_entrycount(repo_index) == 0);
	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 14: ancest:ancest+, head:ancest, remote:remote = result:remote */
void test_merge_trivial__14(void)
{
	const git_index_entry *entry;
	git_oid expected_oid;

	cl_git_pass(merge_trivial("trivial-14", "trivial-14-branch", 0));

	cl_assert(entry = git_index_get_bypath(repo_index, "modified-in-14-branch.txt", 0));
	cl_git_pass(git_oid_fromstr(&expected_oid, "26153a3ff3649b6c2bb652d3f06878c6e0a172f9"));
	cl_assert(git_oid_cmp(&entry->oid, &expected_oid) == 0);

	cl_assert(git_index_reuc_entrycount(repo_index) == 0);
	cl_assert(merge_trivial_conflict_entrycount() == 0);
}

/* 11: ancest:ancest+, head:head, remote:remote = result:no merge */
void test_merge_trivial__11(void)
{
	const git_index_entry *entry;

	cl_git_pass(merge_trivial("trivial-11", "trivial-11-branch", 0));

	cl_assert((entry = git_index_get_bypath(repo_index, "modified-in-both.txt", 0)) == NULL);
	cl_assert(git_index_reuc_entrycount(repo_index) == 0);

	cl_assert(merge_trivial_conflict_entrycount() == 3);
	cl_assert(entry = git_index_get_bypath(repo_index, "modified-in-both.txt", 1));
	cl_assert(entry = git_index_get_bypath(repo_index, "modified-in-both.txt", 2));
	cl_assert(entry = git_index_get_bypath(repo_index, "modified-in-both.txt", 3));
}
