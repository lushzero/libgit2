#include "clar_libgit2.h"
#include "git2/repository.h"
#include "git2/merge.h"
#include "merge.h"
#include "merge_helpers.h"
#include "refs.h"
#include "fileops.h"

static git_repository *repo;
static git_index *repo_index;

#define TEST_REPO_PATH "merge"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"

#define ORIG_HEAD                   "977c696519c5a3004c5f1d15d60c89dbeb8f235f"

#define THEIRS_SIMPLE_BRANCH        "branch"
#define THEIRS_SIMPLE_OID           "7cb63eed597130ba4abb87b3e544b85021905520"

#define OCTO1_BRANCH                "octo1"
#define OCTO1_OID                   "16f825815cfd20a07a75c71554e82d8eede0b061"

#define OCTO2_BRANCH                "octo2"
#define OCTO2_OID                   "158dc7bedb202f5b26502bf3574faa7f4238d56c"

#define OCTO3_BRANCH                "octo3"
#define OCTO3_OID                   "50ce7d7d01217679e26c55939eef119e0c93e272"

#define OCTO4_BRANCH                "octo4"
#define OCTO4_OID                   "54269b3f6ec3d7d4ede24dd350dd5d605495c3ae"

#define OCTO5_BRANCH                "octo5"
#define OCTO5_OID                   "e4f618a2c3ed0669308735727df5ebf2447f022f"

// Fixture setup and teardown
void test_merge_setup__initialize(void)
{
	repo = cl_git_sandbox_init("merge");
    git_repository_index(&repo_index, repo);
}

void test_merge_setup__cleanup(void)
{
    git_index_free(repo_index);
	cl_git_sandbox_cleanup();
}

static int fake_strategy(int *success,
	git_repository *repo,
	const git_commit *our_commit,
	const git_commit *ancestor_commit,
	const git_commit *their_commits[],
	size_t their_commits_len,
	void *data)
{
    /* Avoid unused warnings */
    if (repo && our_commit && ancestor_commit && their_commits && their_commits_len && data)
        ;
    
	*success = 0;
	return 0;
}

static bool test_file_contents(const char *filename, const char *expected)
{
    git_buf file_path_buf = GIT_BUF_INIT, file_buf = GIT_BUF_INIT;
    bool equals;
    
    git_buf_printf(&file_path_buf, "%s/%s", git_repository_path(repo), filename);
    
    cl_git_pass(git_futils_readbuffer(&file_buf, file_path_buf.ptr));
    equals = (strcmp(file_buf.ptr, expected) == 0);

    git_buf_free(&file_path_buf);
    git_buf_free(&file_buf);
    
    return equals;
}

/* git merge --no-ff octo1 */
void test_merge_setup__one_branch(void)
{
    git_reference *octo1_ref;
    git_merge_head *their_heads[1];
	git_merge_result *result;
    
    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], octo1_ref));
    
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, GIT_MERGE_NO_FASTFORWARD, fake_strategy, NULL));

    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, "no-ff"));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branch '" OCTO1_BRANCH "'\n"));

    git_reference_free(octo1_ref);
    
    git_merge_head_free(their_heads[0]);
}

/* git merge --no-ff 16f825815cfd20a07a75c71554e82d8eede0b061 */
void test_merge_setup__one_oid(void)
{
    git_oid octo1_oid;
    git_merge_head *their_heads[1];
	git_merge_result *result;
    
    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], &octo1_oid));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 1, GIT_MERGE_NO_FASTFORWARD, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, "no-ff"));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'\n"));
    
    git_merge_head_free(their_heads[0]);
}

/* git merge octo1 octo2 */
void test_merge_setup__two_branches(void)
{
    git_reference *octo1_ref;
    git_reference *octo2_ref;
    git_merge_head *their_heads[2];
	git_merge_result *result;
    
    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], octo1_ref));

    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], octo2_ref));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 2, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "' and '" OCTO2_BRANCH "'\n"));
    
    git_reference_free(octo1_ref);
    git_reference_free(octo2_ref);
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
}

/* git merge octo1 octo2 octo3 */
void test_merge_setup__three_branches(void)
{
    git_reference *octo1_ref;
    git_reference *octo2_ref;
    git_reference *octo3_ref;
    git_merge_head *their_heads[3];
	git_merge_result *result;
    
    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], octo1_ref));
    
    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], octo2_ref));

    cl_git_pass(git_reference_lookup(&octo3_ref, repo, GIT_REFS_HEADS_DIR OCTO3_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[2], octo3_ref));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 3, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "', '" OCTO2_BRANCH "' and '" OCTO3_BRANCH "'\n"));
    
    git_reference_free(octo1_ref);
    git_reference_free(octo2_ref);
    git_reference_free(octo3_ref);
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 158dc7bedb202f5b26502bf3574faa7f4238d56c 50ce7d7d01217679e26c55939eef119e0c93e272 */
void test_merge_setup__three_oids(void)
{
    git_oid octo1_oid;
    git_oid octo2_oid;
    git_oid octo3_oid;
    git_merge_head *their_heads[3];
	git_merge_result *result;
    
    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], &octo1_oid));
    
    cl_git_pass(git_oid_fromstr(&octo2_oid, OCTO2_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], &octo2_oid));

    cl_git_pass(git_oid_fromstr(&octo3_oid, OCTO3_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], &octo3_oid));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 3, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; commit '" OCTO2_OID "'; commit '" OCTO3_OID "'\n"));
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}

/* git merge octo1 158dc7bedb202f5b26502bf3574faa7f4238d56c */
void test_merge_setup__branches_and_oids_1(void)
{
    git_reference *octo1_ref;
    git_oid octo2_oid;
    git_merge_head *their_heads[2];
	git_merge_result *result;

    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], octo1_ref));

    cl_git_pass(git_oid_fromstr(&octo2_oid, OCTO2_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], &octo2_oid));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 2, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branch '" OCTO1_BRANCH "'; commit '" OCTO2_OID "'\n"));
    
    git_reference_free(octo1_ref);
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
}

/* git merge octo1 158dc7bedb202f5b26502bf3574faa7f4238d56c octo3 54269b3f6ec3d7d4ede24dd350dd5d605495c3ae */
void test_merge_setup__branches_and_oids_2(void)
{
    git_reference *octo1_ref;
    git_oid octo2_oid;
    git_reference *octo3_ref;
    git_oid octo4_oid;
    git_merge_head *their_heads[4];
	git_merge_result *result;
    
    cl_git_pass(git_reference_lookup(&octo1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], octo1_ref));
    
    cl_git_pass(git_oid_fromstr(&octo2_oid, OCTO2_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], &octo2_oid));

    cl_git_pass(git_reference_lookup(&octo3_ref, repo, GIT_REFS_HEADS_DIR OCTO3_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[2], octo3_ref));
    
    cl_git_pass(git_oid_fromstr(&octo4_oid, OCTO4_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[3], &octo4_oid));
    
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 4, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n" OCTO4_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "' and '" OCTO3_BRANCH "'; commit '" OCTO2_OID "'; commit '" OCTO4_OID "'\n"));
    
    git_reference_free(octo1_ref);
    git_reference_free(octo3_ref);
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
    git_merge_head_free(their_heads[3]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 octo2 50ce7d7d01217679e26c55939eef119e0c93e272 octo4 */
void test_merge_setup__branches_and_oids_3(void)
{
    git_oid octo1_oid;
    git_reference *octo2_ref;
    git_oid octo3_oid;
    git_reference *octo4_ref;
    git_merge_head *their_heads[4];
	git_merge_result *result;

    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], &octo1_oid));

    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], octo2_ref));

    cl_git_pass(git_oid_fromstr(&octo3_oid, OCTO3_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], &octo3_oid));
    
    cl_git_pass(git_reference_lookup(&octo4_ref, repo, GIT_REFS_HEADS_DIR OCTO4_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[3], octo4_ref));
    
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 4, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n" OCTO4_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; branches '" OCTO2_BRANCH "' and '" OCTO4_BRANCH "'; commit '" OCTO3_OID "'\n"));
    
    git_reference_free(octo2_ref);
    git_reference_free(octo4_ref);
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
    git_merge_head_free(their_heads[3]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 octo2 50ce7d7d01217679e26c55939eef119e0c93e272 octo4 octo5 */
void test_merge_setup__branches_and_oids_4(void)
{
    git_oid octo1_oid;
    git_reference *octo2_ref;
    git_oid octo3_oid;
    git_reference *octo4_ref;
    git_reference *octo5_ref;
    git_merge_head *their_heads[5];
	git_merge_result *result;
    
    cl_git_pass(git_oid_fromstr(&octo1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], &octo1_oid));
    
    cl_git_pass(git_reference_lookup(&octo2_ref, repo, GIT_REFS_HEADS_DIR OCTO2_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], octo2_ref));
    
    cl_git_pass(git_oid_fromstr(&octo3_oid, OCTO3_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], &octo3_oid));
    
    cl_git_pass(git_reference_lookup(&octo4_ref, repo, GIT_REFS_HEADS_DIR OCTO4_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[3], octo4_ref));

    cl_git_pass(git_reference_lookup(&octo5_ref, repo, GIT_REFS_HEADS_DIR OCTO5_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[4], octo5_ref));

	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 5, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO2_OID "\n" OCTO3_OID "\n" OCTO4_OID "\n" OCTO5_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; branches '" OCTO2_BRANCH "', '" OCTO4_BRANCH "' and '" OCTO5_BRANCH "'; commit '" OCTO3_OID "'\n"));
    
    git_reference_free(octo2_ref);
    git_reference_free(octo4_ref);
    git_reference_free(octo5_ref);
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
    git_merge_head_free(their_heads[3]);
    git_merge_head_free(their_heads[4]);
}

/* git merge octo1 octo1 octo1 */
void test_merge_setup__three_same_branches(void)
{
    git_reference *octo1_1_ref;
    git_reference *octo1_2_ref;
    git_reference *octo1_3_ref;
    git_merge_head *their_heads[3];
	git_merge_result *result;
    
    cl_git_pass(git_reference_lookup(&octo1_1_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[0], octo1_1_ref));
    
    cl_git_pass(git_reference_lookup(&octo1_2_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[1], octo1_2_ref));
    
    cl_git_pass(git_reference_lookup(&octo1_3_ref, repo, GIT_REFS_HEADS_DIR OCTO1_BRANCH));
    cl_git_pass(git_merge_head_from_ref(&their_heads[2], octo1_3_ref));
    
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 3, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO1_OID "\n" OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge branches '" OCTO1_BRANCH "', '" OCTO1_BRANCH "' and '" OCTO1_BRANCH "'\n"));
    
    git_reference_free(octo1_1_ref);
    git_reference_free(octo1_2_ref);
    git_reference_free(octo1_3_ref);
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}

/* git merge 16f825815cfd20a07a75c71554e82d8eede0b061 16f825815cfd20a07a75c71554e82d8eede0b061 16f825815cfd20a07a75c71554e82d8eede0b061 */
void test_merge_setup__three_same_oids(void)
{
    git_oid octo1_1_oid;
    git_oid octo1_2_oid;
    git_oid octo1_3_oid;
    git_merge_head *their_heads[3];
	git_merge_result *result;
    
    cl_git_pass(git_oid_fromstr(&octo1_1_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[0], &octo1_1_oid));
    
    cl_git_pass(git_oid_fromstr(&octo1_2_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[1], &octo1_2_oid));
    
    cl_git_pass(git_oid_fromstr(&octo1_3_oid, OCTO1_OID));
    cl_git_pass(git_merge_head_from_oid(&their_heads[2], &octo1_3_oid));
    
	cl_git_pass(git_merge(&result, repo, (const git_merge_head **)their_heads, 3, 0, fake_strategy, NULL));
    
    cl_assert(test_file_contents(GIT_MERGE_HEAD_FILE, OCTO1_OID "\n" OCTO1_OID "\n" OCTO1_OID "\n"));
    cl_assert(test_file_contents(GIT_ORIG_HEAD_FILE, ORIG_HEAD "\n"));
    cl_assert(test_file_contents(GIT_MERGE_MODE_FILE, ""));
    cl_assert(test_file_contents(GIT_MERGE_MSG_FILE, "Merge commit '" OCTO1_OID "'; commit '" OCTO1_OID "'; commit '" OCTO1_OID "'\n"));
    
    git_merge_head_free(their_heads[0]);
    git_merge_head_free(their_heads[1]);
    git_merge_head_free(their_heads[2]);
}
