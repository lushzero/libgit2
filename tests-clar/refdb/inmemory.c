#include "clar_libgit2.h"
#include "refdb.h"
#include "repository.h"
#include "testdb.h"

static git_repository *repo;
static git_refdb *refdb;
static git_refdb_backend *refdb_backend;

void test_refdb_inmemory__initialize(void)
{
	cl_git_pass(git_repository_init(&repo, "refdb_inmemory", 0));
	cl_git_pass(git_repository_refdb(&refdb, repo));
	cl_git_pass(refdb_backend_test(&refdb_backend, repo));
	cl_git_pass(git_refdb_set_backend(refdb, refdb_backend));
}

void test_refdb_inmemory__cleanup(void)
{
	git_repository_free(repo);
	cl_fixture_cleanup("refdb_inmemory");
}

void populate_references(void)
{
}

void test_refdb_inmemory__read(void)
{
	git_reference *write1, *read1;
	git_oid oid1;
	
	cl_git_pass(git_oid_fromstr(&oid1, "c47800c7266a2be04c571c04d5a6614691ea99bd"));
	cl_git_pass(git_reference_create(&write1, repo, GIT_REFS_HEADS_DIR "test1", &oid1, 0));

	cl_git_pass(git_reference_lookup(&read1, repo, GIT_REFS_HEADS_DIR "test1"));
	cl_assert(strcmp(git_reference_name(read1), git_reference_name(write1)) == 0);
	cl_assert(git_oid_cmp(git_reference_target(read1), git_reference_target(write1)) == 0);
		
	git_reference_free(write1);
	git_reference_free(read1);
}
