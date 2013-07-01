#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/sys/index.h"
#include "fileops.h"

static git_repository *g_repo;
static git_index *g_index;

#define TEST_REPO_PATH "merge-resolve"

#define CONFLICTING_ANCESTOR_OID   "d427e0b2e138501a3d15cc376077a3631e15bd46"
#define CONFLICTING_OURS_OID       "4e886e602529caa9ab11d71f86634bd1b6e0de10"
#define CONFLICTING_THEIRS_OID     "2bd0a343aeef7a2cf0d158478966a6e587ff3863"

#define AUTOMERGEABLE_ANCESTOR_OID "6212c31dab5e482247d7977e4f0dd3601decf13b"
#define AUTOMERGEABLE_OURS_OID     "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf"
#define AUTOMERGEABLE_THEIRS_OID   "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe"

#define CONFLICTING_OURS_FILE \
	"this file is changed in master and branch\n"
#define CONFLICTING_THEIRS_FILE \
	"this file is changed in branch and master\n"
#define CONFLICTING_DIFF3_FILE \
	"<<<<<<< ours\n" \
	"this file is changed in master and branch\n" \
	"=======\n" \
	"this file is changed in branch and master\n" \
	">>>>>>> theirs\n"

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

void test_checkout_conflict__initialize(void)
{
	g_repo = cl_git_sandbox_init(TEST_REPO_PATH);
	git_repository_index(&g_index, g_repo);

	cl_git_rewritefile(
		TEST_REPO_PATH "/.gitattributes",
		"* text eol=lf\n");
}

void test_checkout_conflict__cleanup(void)
{
	git_index_free(g_index);
	cl_git_sandbox_cleanup();
}

static void create_conflicting_index(void)
{
	git_index_entry ancestor = {0}, ours = {0}, theirs = {0};

	ancestor.mode = 0100644;
	ancestor.flags = 1 << GIT_IDXENTRY_STAGESHIFT;
	ancestor.path = "conflicting.txt";
	git_oid_fromstr(&ancestor.oid, CONFLICTING_ANCESTOR_OID);

	ours.mode = 0100644;
	ours.flags = 2 << GIT_IDXENTRY_STAGESHIFT;
	ours.path = "conflicting.txt";
	git_oid_fromstr(&ours.oid, CONFLICTING_OURS_OID);

	theirs.mode = 0100644;
	theirs.flags = 3 << GIT_IDXENTRY_STAGESHIFT;
	theirs.path = "conflicting.txt";
	git_oid_fromstr(&theirs.oid, CONFLICTING_THEIRS_OID);

	p_unlink(TEST_REPO_PATH "/conflicting.txt");

	git_index_remove_bypath(g_index, "conflicting.txt");
	git_index_add(g_index, &ancestor);
	git_index_add(g_index, &ours);
	git_index_add(g_index, &theirs);

	git_index_write(g_index);
}

static void create_automergeable_index(void)
{
	git_index_entry ancestor = {0}, ours = {0}, theirs = {0};

	ancestor.mode = 0100644;
	ancestor.flags = 1 << GIT_IDXENTRY_STAGESHIFT;
	ancestor.path = "automergeable.txt";
	git_oid_fromstr(&ancestor.oid, AUTOMERGEABLE_ANCESTOR_OID);

	ours.mode = 0100644;
	ours.flags = 2 << GIT_IDXENTRY_STAGESHIFT;
	ours.path = "automergeable.txt";
	git_oid_fromstr(&ours.oid, AUTOMERGEABLE_OURS_OID);

	theirs.mode = 0100644;
	theirs.flags = 3 << GIT_IDXENTRY_STAGESHIFT;
	theirs.path = "automergeable.txt";
	git_oid_fromstr(&theirs.oid, AUTOMERGEABLE_THEIRS_OID);

	p_unlink(TEST_REPO_PATH "/automergeable.txt");

	git_index_remove_bypath(g_index, "automergeable.txt");
	git_index_add(g_index, &ancestor);
	git_index_add(g_index, &ours);
	git_index_add(g_index, &theirs);

	git_index_write(g_index);
}

void test_checkout_conflict__fails(void)
{
	git_buf conflicting_buf = GIT_BUF_INIT;
	git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;

	opts.checkout_strategy |= GIT_CHECKOUT_USE_OURS;

	create_conflicting_index();

	cl_git_pass(git_checkout_index(g_repo, g_index, &opts));

	cl_git_pass(git_futils_readbuffer(&conflicting_buf,
		TEST_REPO_PATH "/conflicting.txt"));
	cl_assert(strcmp(conflicting_buf.ptr, CONFLICTING_OURS_FILE) == 0);
	git_buf_free(&conflicting_buf);
}

void test_checkout_conflict__ignored(void)
{
	git_buf conflicting_buf = GIT_BUF_INIT;
	git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;

	opts.checkout_strategy |= GIT_CHECKOUT_SKIP_UNMERGED;

	create_conflicting_index();

	cl_git_pass(git_checkout_index(g_repo, g_index, &opts));

	cl_assert(!git_path_exists(TEST_REPO_PATH "/conflicting.txt"));
}

void test_checkout_conflict__ours(void)
{
	git_buf conflicting_buf = GIT_BUF_INIT;
	git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;

	opts.checkout_strategy |= GIT_CHECKOUT_USE_OURS;

	create_conflicting_index();

	cl_git_pass(git_checkout_index(g_repo, g_index, &opts));

	cl_git_pass(git_futils_readbuffer(&conflicting_buf,
		TEST_REPO_PATH "/conflicting.txt"));
	cl_assert(strcmp(conflicting_buf.ptr, CONFLICTING_OURS_FILE) == 0);
	git_buf_free(&conflicting_buf);
}

void test_checkout_conflict__theirs(void)
{
	git_buf conflicting_buf = GIT_BUF_INIT;
	git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;

	opts.checkout_strategy |= GIT_CHECKOUT_USE_THEIRS;

	create_conflicting_index();

	cl_git_pass(git_checkout_index(g_repo, g_index, &opts));

	cl_git_pass(git_futils_readbuffer(&conflicting_buf,
		TEST_REPO_PATH "/conflicting.txt"));
	cl_assert(strcmp(conflicting_buf.ptr, CONFLICTING_THEIRS_FILE) == 0);
	git_buf_free(&conflicting_buf);
}

void test_checkout_conflict__diff3(void)
{
	git_buf conflicting_buf = GIT_BUF_INIT;
	git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;

	create_conflicting_index();

	cl_git_pass(git_checkout_index(g_repo, g_index, &opts));

	cl_git_pass(git_futils_readbuffer(&conflicting_buf,
		TEST_REPO_PATH "/conflicting.txt"));
	cl_assert(strcmp(conflicting_buf.ptr, CONFLICTING_DIFF3_FILE) == 0);
	git_buf_free(&conflicting_buf);
}

void test_checkout_conflict__automerge(void)
{
	git_buf conflicting_buf = GIT_BUF_INIT;
	git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;

	create_automergeable_index();

	cl_git_pass(git_checkout_index(g_repo, g_index, &opts));

	cl_git_pass(git_futils_readbuffer(&conflicting_buf,
		TEST_REPO_PATH "/automergeable.txt"));
	cl_assert(strcmp(conflicting_buf.ptr, AUTOMERGEABLE_MERGED_FILE) == 0);
	git_buf_free(&conflicting_buf);
}
