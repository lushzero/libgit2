#include <refdb.h>
#include <git2/refdb.h>
#include <git2/refdb_backend.h>

typedef struct refdb_test_backend {
	git_refdb_backend parent;
	
	git_repository *repo;
	git_vector refs;
} refdb_test_backend;

static int ref_name_cmp(const void *a, const void *b)
{
	return strcmp(git_reference_name((git_reference *)a),
		git_reference_name((git_reference *)b));
}

static int refdb_test_backend__exists(
	int *exists,
	git_refdb_backend *_backend,
	const char *ref_name)
{
	refdb_test_backend *backend;
	size_t i;
	git_reference *ref;
	
	assert(_backend);
	backend = (refdb_test_backend *)_backend;
	
	*exists = 0;
	
	git_vector_foreach(&backend->refs, i, ref) {
		if (strcmp(git_reference_name(ref), ref_name) == 0)
			*exists = 1;
	}
	
	return 0;
}

static int ref_cpy(git_reference *dst, git_reference *src)
{
	if (dst->name)
		git__free(dst->name);
	
	if (dst->flags & GIT_REF_SYMBOLIC)
		git__free(dst->target.symbolic);
	
	dst->flags = src->flags;

	dst->name = git__strdup(src->name);
	GITERR_CHECK_ALLOC(dst->name);
	
	dst->mtime = src->mtime;

	if (dst->flags & GIT_REF_OID)
		git_oid_cpy(&dst->target.oid, &src->target.oid);
	else {
		dst->target.symbolic = git__strdup(src->target.symbolic);
		GITERR_CHECK_ALLOC(dst->target.symbolic);
	}
	
	return 0;
}

static int refdb_test_backend__write(
	git_refdb_backend *_backend,
	git_reference *ref)
{
	refdb_test_backend *backend;
	git_reference *ref_dup;
	
	assert(_backend);
	backend = (refdb_test_backend *)_backend;

	ref_dup = git__calloc(1, sizeof(git_reference));
	GITERR_CHECK_ALLOC(ref_dup);
	
	if (ref_cpy(ref_dup, ref) < 0)
		return -1;

	git_vector_insert(&backend->refs, ref_dup);
	
	return 0;
}

static int refdb_test_backend__lookup(
	git_refdb_backend *_backend,
	git_reference *out)
{
	refdb_test_backend *backend;
	size_t i;
	git_reference *r;

	assert(_backend);
	backend = (refdb_test_backend *)_backend;
	
	git_vector_foreach(&backend->refs, i, r) {
		if (strcmp(out->name, r->name) == 0) {
			if (out->mtime == r->mtime)
				return 0;
			
			return ref_cpy(out, r);
		}
	}

	return GIT_ENOTFOUND;
}

static int refdb_test_backend__foreach(
	git_refdb_backend *_backend,
	unsigned int list_flags,
	git_reference_foreach_cb callback,
	void *payload)
{
	refdb_test_backend *backend;
	size_t i;
	git_reference *r;
	
	assert(_backend);
	backend = (refdb_test_backend *)_backend;

	git_vector_foreach(&backend->refs, i, r) {
		if ((r->flags & GIT_REF_OID) != (list_flags & GIT_REF_OID) ||
			(r->flags & GIT_REF_SYMBOLIC) != (list_flags & GIT_REF_SYMBOLIC))
			continue;
		
		if (callback(r->name, payload) != 0)
			return GIT_EUSER;
	}
	
	return 0;
}

static int refdb_test_backend__delete(
	git_refdb_backend *_backend,
	git_reference *ref)
{
	refdb_test_backend *backend;
	size_t i;
	git_reference *r;

	assert(_backend);
	backend = (refdb_test_backend *)_backend;

	git_vector_foreach(&backend->refs, i, r) {
		if (strcmp(ref->name, r->name) == 0) {
			git_reference_free(ref);
			git_vector_remove(&backend->refs, i);
			return 0;
		}
	}

	return GIT_ENOTFOUND;
}

static int refdb_test_backend__packall(git_refdb_backend *_backend)
{
	GIT_UNUSED(_backend);
	return 0;
}

static void refdb_test_backend__free(git_refdb_backend *_backend)
{
	refdb_test_backend *backend;
	size_t i;
	git_reference *ref;
	
	assert(_backend);
	backend = (refdb_test_backend *)_backend;

	git_vector_foreach(&backend->refs, i, ref)
		git_reference_free(ref);
	
	git_vector_free(&backend->refs);
}

int refdb_backend_test(
	git_refdb_backend **backend_out,
	git_repository *repo)
{
	refdb_test_backend *backend;

	backend = git__calloc(1, sizeof(refdb_test_backend));
	GITERR_CHECK_ALLOC(backend);
	
	git_vector_init(&backend->refs, 0, ref_name_cmp);

	backend->repo = repo;

	backend->parent.exists = &refdb_test_backend__exists;
	backend->parent.lookup = &refdb_test_backend__lookup;
	backend->parent.foreach = &refdb_test_backend__foreach;
	backend->parent.write = &refdb_test_backend__write;
	backend->parent.delete = &refdb_test_backend__delete;
	backend->parent.packall = &refdb_test_backend__packall;
	backend->parent.free = &refdb_test_backend__free;

	*backend_out = (git_refdb_backend *)backend;
	return 0;
}
