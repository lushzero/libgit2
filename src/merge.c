/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "posix.h"
#include "repository.h"
#include "revwalk.h"
#include "commit_list.h"
#include "merge.h"
#include "path.h"
#include "refs.h"
#include "object.h"
#include "iterator.h"
#include "refs.h"
#include "diff.h"
#include "diff_tree.h"
#include "checkout.h"

#include "git2/diff_tree.h"
#include "git2/types.h"
#include "git2/repository.h"
#include "git2/object.h"
#include "git2/commit.h"
#include "git2/merge.h"
#include "git2/refs.h"
#include "git2/reset.h"
#include "git2/checkout.h"
#include "git2/signature.h"
#include "git2/config.h"

#include "xdiff/xdiff.h"

/* Merge base computation */

int git_merge_base_many(git_oid *out, git_repository *repo, const git_oid input_array[], size_t length)
{
	git_revwalk *walk;
	git_vector list;
	git_commit_list *result = NULL;
	int error = -1;
	unsigned int i;
	git_commit_list_node *commit;

	assert(out && repo && input_array);

	if (length < 2) {
		giterr_set(GITERR_INVALID, "At least two commits are required to find an ancestor. Provided 'length' was %u.", length);
		return -1;
	}

	if (git_vector_init(&list, length - 1, NULL) < 0)
		return -1;

	if (git_revwalk_new(&walk, repo) < 0)
		goto cleanup;

	for (i = 1; i < length; i++) {
		commit = git_revwalk__commit_lookup(walk, &input_array[i]);
		if (commit == NULL)
			goto cleanup;

		git_vector_insert(&list, commit);
	}

	commit = git_revwalk__commit_lookup(walk, &input_array[0]);
	if (commit == NULL)
		goto cleanup;

	if (git_merge__bases_many(&result, walk, commit, &list) < 0)
		goto cleanup;

	if (!result) {
		error = GIT_ENOTFOUND;
		goto cleanup;
	}

	git_oid_cpy(out, &result->item->oid);

	error = 0;

cleanup:
	git_commit_list_free(&result);
	git_revwalk_free(walk);
	git_vector_free(&list);
	return error;
}

int git_merge_base(git_oid *out, git_repository *repo, const git_oid *one, const git_oid *two)
{
	git_revwalk *walk;
	git_vector list;
	git_commit_list *result = NULL;
	git_commit_list_node *commit;
	void *contents[1];

	if (git_revwalk_new(&walk, repo) < 0)
		return -1;

	commit = git_revwalk__commit_lookup(walk, two);
	if (commit == NULL)
		goto on_error;

	/* This is just one value, so we can do it on the stack */
	memset(&list, 0x0, sizeof(git_vector));
	contents[0] = commit;
	list.length = 1;
	list.contents = contents;

	commit = git_revwalk__commit_lookup(walk, one);
	if (commit == NULL)
		goto on_error;

	if (git_merge__bases_many(&result, walk, commit, &list) < 0)
		goto on_error;

	if (!result) {
		git_revwalk_free(walk);
		giterr_clear();
		return GIT_ENOTFOUND;
	}

	git_oid_cpy(out, &result->item->oid);
	git_commit_list_free(&result);
	git_revwalk_free(walk);

	return 0;

on_error:
	git_revwalk_free(walk);
	return -1;
}

static int interesting(git_pqueue *list)
{
	unsigned int i;
	/* element 0 isn't used - we need to start at 1 */
	for (i = 1; i < list->size; i++) {
		git_commit_list_node *commit = list->d[i];
		if ((commit->flags & STALE) == 0)
			return 1;
	}

	return 0;
}

int git_merge__bases_many(git_commit_list **out, git_revwalk *walk, git_commit_list_node *one, git_vector *twos)
{
	int error;
	unsigned int i;
	git_commit_list_node *two;
	git_commit_list *result = NULL, *tmp = NULL;
	git_pqueue list;

	/* if the commit is repeated, we have a our merge base already */
	git_vector_foreach(twos, i, two) {
		if (one == two)
			return git_commit_list_insert(one, out) ? 0 : -1;
	}

	if (git_pqueue_init(&list, twos->length * 2, git_commit_list_time_cmp) < 0)
		return -1;

	if (git_commit_list_parse(walk, one) < 0)
	    return -1;

	one->flags |= PARENT1;
	if (git_pqueue_insert(&list, one) < 0)
		return -1;

	git_vector_foreach(twos, i, two) {
		git_commit_list_parse(walk, two);
		two->flags |= PARENT2;
		if (git_pqueue_insert(&list, two) < 0)
			return -1;
	}

	/* as long as there are non-STALE commits */
	while (interesting(&list)) {
		git_commit_list_node *commit;
		int flags;

		commit = git_pqueue_pop(&list);

		flags = commit->flags & (PARENT1 | PARENT2 | STALE);
		if (flags == (PARENT1 | PARENT2)) {
			if (!(commit->flags & RESULT)) {
				commit->flags |= RESULT;
				if (git_commit_list_insert(commit, &result) == NULL)
					return -1;
			}
			/* we mark the parents of a merge stale */
			flags |= STALE;
		}

		for (i = 0; i < commit->out_degree; i++) {
			git_commit_list_node *p = commit->parents[i];
			if ((p->flags & flags) == flags)
				continue;

			if ((error = git_commit_list_parse(walk, p)) < 0)
				return error;

			p->flags |= flags;
			if (git_pqueue_insert(&list, p) < 0)
				return -1;
		}
	}

	git_pqueue_free(&list);

	/* filter out any stale commits in the results */
	tmp = result;
	result = NULL;

	while (tmp) {
		struct git_commit_list *next = tmp->next;
		if (!(tmp->item->flags & STALE))
			if (git_commit_list_insert_by_date(tmp->item, &result) == NULL)
				return -1;

		git__free(tmp);
		tmp = next;
	}

	*out = result;
	return 0;
}

/* Merge setup */

static int write_orig_head(git_repository *repo, const git_merge_head *our_head)
{
	git_filebuf orig_head_file = GIT_FILEBUF_INIT;
	git_buf orig_head_path = GIT_BUF_INIT;
	char orig_oid_str[GIT_OID_HEXSZ + 1];
	int error = 0;

	assert(repo && our_head);

	git_oid_tostr(orig_oid_str, GIT_OID_HEXSZ+1, &our_head->oid);

	if ((error = git_buf_joinpath(&orig_head_path, repo->path_repository, GIT_ORIG_HEAD_FILE)) == 0 &&
		(error = git_filebuf_open(&orig_head_file, orig_head_path.ptr, GIT_FILEBUF_FORCE)) == 0 &&
		(error = git_filebuf_printf(&orig_head_file, "%s\n", orig_oid_str)) == 0)
		error = git_filebuf_commit(&orig_head_file, MERGE_CONFIG_FILE_MODE);

	if (error < 0)
		git_filebuf_cleanup(&orig_head_file);

	git_buf_free(&orig_head_path);

	return error;
}

static int write_merge_head(git_repository *repo, const git_merge_head *their_heads[], size_t their_heads_len)
{
	git_filebuf merge_head_file = GIT_FILEBUF_INIT;
	git_buf merge_head_path = GIT_BUF_INIT;
	char merge_oid_str[GIT_OID_HEXSZ + 1];
	size_t i;
	int error = 0;

	assert(repo && their_heads);

	if ((error = git_buf_joinpath(&merge_head_path, repo->path_repository, GIT_MERGE_HEAD_FILE)) < 0 ||
		(error = git_filebuf_open(&merge_head_file, merge_head_path.ptr, GIT_FILEBUF_FORCE)) < 0)
		goto cleanup;

	for (i = 0; i < their_heads_len; i++) {
		git_oid_tostr(merge_oid_str, GIT_OID_HEXSZ+1, &their_heads[i]->oid);

		if ((error = git_filebuf_printf(&merge_head_file, "%s\n", merge_oid_str)) < 0)
			goto cleanup;
	}

	error = git_filebuf_commit(&merge_head_file, MERGE_CONFIG_FILE_MODE);

cleanup:
	if (error < 0)
		git_filebuf_cleanup(&merge_head_file);

	git_buf_free(&merge_head_path);

	return error;
}

static int write_merge_mode(git_repository *repo, unsigned int flags)
{
	git_filebuf merge_mode_file = GIT_FILEBUF_INIT;
	git_buf merge_mode_path = GIT_BUF_INIT;
	int error = 0;

	assert(repo);

	if ((error = git_buf_joinpath(&merge_mode_path, repo->path_repository, GIT_MERGE_MODE_FILE)) < 0 ||
		(error = git_filebuf_open(&merge_mode_file, merge_mode_path.ptr, GIT_FILEBUF_FORCE)) < 0)
		goto cleanup;

	/*
	 * TODO: no-ff is the only thing allowed here at present.  One would
	 * presume they would be space-delimited when there are more, but
	 * this needs to be revisited.
	 */
	
	if (flags & GIT_MERGE_NO_FASTFORWARD) {
		if ((error = git_filebuf_write(&merge_mode_file, "no-ff", 5)) < 0)
			goto cleanup;
	}

	error = git_filebuf_commit(&merge_mode_file, MERGE_CONFIG_FILE_MODE);

cleanup:
	if (error < 0)
		git_filebuf_cleanup(&merge_mode_file);

	git_buf_free(&merge_mode_path);

	return error;
}

static int write_merge_msg(git_repository *repo, const git_merge_head *their_heads[], size_t their_heads_len)
{
	git_filebuf merge_msg_file = GIT_FILEBUF_INIT;
	git_buf merge_msg_path = GIT_BUF_INIT;
	char merge_oid_str[GIT_OID_HEXSZ + 1];
	size_t i, j;
    bool *wrote;
	int error = 0;

	assert(repo && their_heads);

    if ((wrote = git__calloc(their_heads_len, sizeof(bool))) == NULL)
        return -1;
    
	if ((error = git_buf_joinpath(&merge_msg_path, repo->path_repository, GIT_MERGE_MSG_FILE)) < 0 ||
		(error = git_filebuf_open(&merge_msg_file, merge_msg_path.ptr, GIT_FILEBUF_FORCE)) < 0 ||
		(error = git_filebuf_write(&merge_msg_file, "Merge", 5)) < 0)
		goto cleanup;

    /*
     * This is to emulate the format of MERGE_MSG by core git.
     *
     * Yes.  Really.
     */
    for (i = 0; i < their_heads_len; i++) {
        if (wrote[i])
            continue;
        
        /* At the first branch, write all the branches */
        if (their_heads[i]->branch_name != NULL) {
            bool multiple_branches = 0;
            size_t last_branch_idx = i;
            
            for (j = i+1; j < their_heads_len; j++) {
                if (their_heads[j]->branch_name != NULL) {
                    multiple_branches = 1;
                    last_branch_idx = j;
                }
            }
            
            if ((error = git_filebuf_printf(&merge_msg_file, "%s %s", (i > 0) ? ";" : "", multiple_branches ? "branches" : "branch")) < 0)
                goto cleanup;
            
            for (j = i; j < their_heads_len; j++) {
                if (their_heads[j]->branch_name == NULL)
                    continue;
                
                if (j > i) {
                    if ((error = git_filebuf_printf(&merge_msg_file, "%s", (last_branch_idx == j) ? " and" : ",")) < 0)
                        goto cleanup;
                }
                
                if ((error = git_filebuf_printf(&merge_msg_file, " '%s'", their_heads[j]->branch_name)) < 0)
                    goto cleanup;
                
                wrote[j] = 1;
            }
        } else {
            git_oid_fmt(merge_oid_str, &their_heads[i]->oid);
            merge_oid_str[GIT_OID_HEXSZ] = '\0';
            
            if ((error = git_filebuf_printf(&merge_msg_file, "%s commit '%s'", (i > 0) ? ";" : "", merge_oid_str)) < 0)
                goto cleanup;
        }
    }

	if ((error = git_filebuf_printf(&merge_msg_file, "\n")) < 0 ||
		(error = git_filebuf_commit(&merge_msg_file, MERGE_CONFIG_FILE_MODE)) < 0)
		goto cleanup;

cleanup:
	if (error < 0)
		git_filebuf_cleanup(&merge_msg_file);

	git_buf_free(&merge_msg_path);
    git__free(wrote);

	return error;
}

int git_merge__setup(
	git_repository *repo,
	const git_merge_head *our_head,
    const git_merge_head *their_heads[],
	size_t their_heads_len,
	unsigned int flags)
{
	int error = 0;

	assert (repo && our_head && their_heads);
	
	if ((error = write_orig_head(repo, our_head)) == 0 &&
		(error = write_merge_head(repo, their_heads, their_heads_len)) == 0 &&
		(error = write_merge_mode(repo, flags)) == 0) {
		error = write_merge_msg(repo, their_heads, their_heads_len);
	}

	return error;
}

GIT_INLINE(int) merge_file_cmp(const git_diff_file *a, const git_diff_file *b)
{
	int value = 0;
    
    if (a->path == NULL)
        return (b->path == NULL) ? 0 : 1;
    
	if ((value = a->mode - b->mode) == 0 &&
		(value = git_oid_cmp(&a->oid, &b->oid)) == 0)
		value = strcmp(a->path, b->path);

	return value;
}

/* Xdiff (automerge/diff3) computation */

typedef struct {
	bool automergeable;
	
	const char *path;
	int mode;

	unsigned char *data;
	size_t len;
} merge_filediff_result;

#define MERGE_FILEDIFF_RESULT_INIT		{0}

static const char *merge_filediff_best_path(const git_diff_tree_delta *delta)
{
	if (!GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor)) {
		if (strcmp(delta->ours.file.path, delta->theirs.file.path) == 0)
			return delta->ours.file.path;
		
		return NULL;
	}
	
	if (strcmp(delta->ancestor.file.path, delta->ours.file.path) == 0)
		return delta->theirs.file.path;
	else if(strcmp(delta->ancestor.file.path, delta->theirs.file.path) == 0)
		return delta->ours.file.path;
	
	return NULL;
}

static int merge_filediff_best_mode(const git_diff_tree_delta *delta)
{
	/*
	 * If ancestor didn't exist and either ours or theirs is executable,
	 * assume executable.  Otherwise, if any mode changed from the ancestor,
	 * use that one.
	 */
	if (!GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor)) {
		if (delta->ours.file.mode == GIT_FILEMODE_BLOB_EXECUTABLE ||
			delta->theirs.file.mode == GIT_FILEMODE_BLOB_EXECUTABLE)
			return GIT_FILEMODE_BLOB_EXECUTABLE;
		
		return GIT_FILEMODE_BLOB;
	}
	
	if (delta->ancestor.file.mode == delta->ours.file.mode)
		return delta->theirs.file.mode;
	else if(delta->ancestor.file.mode == delta->theirs.file.mode)
		return delta->ours.file.mode;
	
	return 0;
}

static char *merge_filediff_entry_name(const git_merge_head *merge_head,
	const git_diff_tree_entry *entry,
	bool rename)
{
	char oid_str[GIT_OID_HEXSZ];
	git_buf name = GIT_BUF_INIT;
	
	assert(merge_head && entry);

	if (merge_head->branch_name)
		git_buf_puts(&name, merge_head->branch_name);
	else {
		git_oid_fmt(oid_str, &merge_head->oid);
		git_buf_put(&name, oid_str, GIT_OID_HEXSZ);
	}
	
	if (rename) {
		git_buf_putc(&name, ':');
		git_buf_puts(&name, entry->file.path);
	}
	
	return strdup(name.ptr);
}

static int merge_filediff_entry_names(char **our_path,
	char **their_path,
	const git_merge_head *merge_heads[],
	const git_diff_tree_delta *delta)
{
	bool rename;

	if (!merge_heads)
		return 0;

	/*
	 * If all the paths are identical, decorate the diff3 file with the branch
	 * names.  Otherwise, use branch_name:path
	 */
	rename = strcmp(delta->ours.file.path, delta->theirs.file.path) != 0;
	
	if ((*our_path = merge_filediff_entry_name(merge_heads[1], &delta->ours, rename)) == NULL ||
		(*their_path = merge_filediff_entry_name(merge_heads[2], &delta->theirs, rename)) == NULL)
		return -1;

	return 0;
}

static int merge_filediff(
	merge_filediff_result *result,
	git_odb *odb,
	const git_merge_head *merge_heads[],
	const git_diff_tree_delta *delta,
	unsigned int flags)
{
	git_odb_object *ancestor_odb = NULL, *our_odb = NULL, *their_odb = NULL;
	char *our_name = NULL, *their_name = NULL;
	mmfile_t ancestor_mmfile, our_mmfile, their_mmfile;
	xmparam_t xmparam;
	mmbuffer_t mmbuffer;
	int xdl_result;
	int error = 0;

	assert(result && odb && delta);
	
	memset(result, 0x0, sizeof(merge_filediff_result));
	
	/* Can't automerge unless ours and theirs exist */
	if (!GIT_DIFF_TREE_FILE_EXISTS(delta->ours) ||
		!GIT_DIFF_TREE_FILE_EXISTS(delta->theirs))
		return 0;

	/* Reject filename collisions */
	result->path = merge_filediff_best_path(delta);
	result->mode = merge_filediff_best_mode(delta);

	if (result->path == NULL || result->mode == 0)
		return 0;
	
	memset(&xmparam, 0x0, sizeof(xmparam_t));
	
	if (merge_heads &&
		(error = merge_filediff_entry_names(&our_name, &their_name, merge_heads, delta)) < 0)
		return -1;

	/* Ancestor isn't decorated in diff3, use NULL. */
	xmparam.ancestor = NULL;
	xmparam.file1 = our_name ? our_name : delta->ours.file.path;
	xmparam.file2 = their_name ? their_name : delta->theirs.file.path;

	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor)) {
		if ((error = git_odb_read(&ancestor_odb, odb, &delta->ancestor.file.oid)) < 0)
			goto done;
		
		ancestor_mmfile.size = git_odb_object_size(ancestor_odb);
		ancestor_mmfile.ptr = (char *)git_odb_object_data(ancestor_odb);
	} else
		memset(&ancestor_mmfile, 0x0, sizeof(mmfile_t));

	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ours)) {
		if ((error = git_odb_read(&our_odb, odb, &delta->ours.file.oid)) < 0)
			goto done;
		
		our_mmfile.size = git_odb_object_size(our_odb);
		our_mmfile.ptr = (char *)git_odb_object_data(our_odb);
	} else
		memset(&our_mmfile, 0x0, sizeof(mmfile_t));
	
	if (GIT_DIFF_TREE_FILE_EXISTS(delta->theirs)) {
		if ((error = git_odb_read(&their_odb, odb, &delta->theirs.file.oid)) < 0)
			goto done;
		
		their_mmfile.size = git_odb_object_size(their_odb);
		their_mmfile.ptr = (char *)git_odb_object_data(their_odb);
	} else
		memset(&their_mmfile, 0x0, sizeof(mmfile_t));
	
	if (flags & GIT_MERGE_RESOLVE_FAVOR_OURS)
		xmparam.favor = XDL_MERGE_FAVOR_OURS;

	if (flags & GIT_MERGE_RESOLVE_FAVOR_THEIRS)
		xmparam.favor = XDL_MERGE_FAVOR_THEIRS;

	if ((xdl_result = xdl_merge(&ancestor_mmfile, &our_mmfile, &their_mmfile, &xmparam, &mmbuffer)) < 0) {
		giterr_set(GITERR_MERGE, "Failed to perform automerge.");
		error = -1;
		goto done;
	}
	
	result->automergeable = (xdl_result == 0);
	result->data = (unsigned char *)mmbuffer.ptr;
	result->len = mmbuffer.size;
	
done:
	if (our_name)
		git__free(our_name);

	if (their_name)
		git__free(their_name);

	git_odb_object_free(ancestor_odb);
	git_odb_object_free(our_odb);
	git_odb_object_free(their_odb);

	return error;
}

static void merge_filediff_result_free(merge_filediff_result *result)
{
	/* xdiff uses malloc() not git_malloc, so we use free(), not git_free() */
	if (result->data != NULL)
		free(result->data);
}

/* Conflict resolution */

static int merge_file_index_remove(git_index *index, const git_diff_tree_delta *delta)
{
	if (!GIT_DIFF_TREE_FILE_EXISTS(delta->ours))
		return 0;

	return git_index_remove(index, delta->ours.file.path, 0);
}

static int merge_file_apply(git_index *index,
	const git_diff_tree_delta *delta,
	const git_diff_tree_entry *entry)
{
	git_index_entry index_entry;
	int error = 0;
	
	assert (index && entry);
	
	if (!GIT_DIFF_TREE_FILE_EXISTS(*entry))
		error = merge_file_index_remove(index, delta);
	else {
		memset(&index_entry, 0x0, sizeof(git_index_entry));
		
		index_entry.path = (char *)entry->file.path;
		index_entry.mode = entry->file.mode;
		index_entry.file_size = entry->file.size;
		git_oid_cpy(&index_entry.oid, &entry->file.oid);

		error = git_index_add(index, &index_entry);
	}
	
	return error;
}

static int merge_mark_conflict_resolved(git_index *index, const git_diff_tree_delta *delta)
{
    const char *path;
    assert(index && delta);
	
	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor))
		path = delta->ancestor.file.path;
	else if (GIT_DIFF_TREE_FILE_EXISTS(delta->ours))
		path = delta->ours.file.path;
	else if (GIT_DIFF_TREE_FILE_EXISTS(delta->theirs))
		path = delta->theirs.file.path;
	
	return git_index_reuc_add(index, path,
		delta->ancestor.file.mode, &delta->ancestor.file.oid,
		delta->ours.file.mode, &delta->ours.file.oid,
		delta->theirs.file.mode, &delta->theirs.file.oid);
}

static int merge_mark_conflict_unresolved(git_index *index, const git_diff_tree_delta *delta)
{
	bool ancestor_exists = 0, ours_exists = 0, theirs_exists = 0;
    git_index_entry ancestor_entry, our_entry, their_entry;
    int error = 0;

    assert(index && delta);
	
	if ((ancestor_exists = GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor))) {
		ancestor_exists = 1;
		
		memset(&ancestor_entry, 0x0, sizeof(git_index_entry));
		ancestor_entry.path = (char *)delta->ancestor.file.path;
		ancestor_entry.mode = delta->ancestor.file.mode;
		git_oid_cpy(&ancestor_entry.oid, &delta->ancestor.file.oid);
	}
	
	if ((ours_exists = GIT_DIFF_TREE_FILE_EXISTS(delta->ours))) {
		ours_exists = 1;
		
		memset(&our_entry, 0x0, sizeof(git_index_entry));
		our_entry.path = (char *)delta->ours.file.path;
		our_entry.mode = delta->ours.file.mode;
		git_oid_cpy(&our_entry.oid, &delta->ours.file.oid);
	}
	
	if ((theirs_exists = GIT_DIFF_TREE_FILE_EXISTS(delta->theirs))) {
		theirs_exists = 1;
		
		memset(&their_entry, 0x0, sizeof(git_index_entry));
		their_entry.path = (char *)delta->theirs.file.path;
		their_entry.mode = delta->theirs.file.mode;
		git_oid_cpy(&their_entry.oid, &delta->theirs.file.oid);
	}

	if ((error = merge_file_index_remove(index, delta)) >= 0)
		error = git_index_conflict_add(index,
			ancestor_exists ? &ancestor_entry : NULL,
			ours_exists ? &our_entry : NULL,
			theirs_exists ? &their_entry : NULL);
	
	return error;
}

static int merge_conflict_resolve_trivial(
	int *resolved,
	git_repository *repo,
	git_index *index,
	const git_diff_tree_delta *delta,
	unsigned int resolve_flags)
{
    int ancestor_empty, ours_empty, theirs_empty;
    int ours_changed, theirs_changed, ours_theirs_differ;
	git_diff_tree_entry const *result = NULL;
    int error = 0;
    
	GIT_UNUSED(resolve_flags);

    assert(resolved && repo && index && delta);
    
    *resolved = 0;
    
	/* TODO: reject non-files */

	ancestor_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor);
	ours_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->ours);
	theirs_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->theirs);
	
	ours_changed = (delta->ours.status != GIT_DELTA_UNMODIFIED);
	theirs_changed = (delta->theirs.status != GIT_DELTA_UNMODIFIED);
	ours_theirs_differ = ours_changed && theirs_changed &&
		merge_file_cmp(&delta->ours.file, &delta->theirs.file);
    
    /*
     * Note: with only one ancestor, some cases are not distinct:
     *
     * 16: ancest:anc1/anc2, head:anc1, remote:anc2 = result:no merge
     * 3: ancest:(empty)^, head:head, remote:(empty) = result:no merge
     * 2: ancest:(empty)^, head:(empty), remote:remote = result:no merge
     *
     * Note that the two cases that take D/F conflicts into account
     * specifically do not need to be explicitly tested, as D/F conflicts
     * would fail the *empty* test:
     *
     * 3ALT: ancest:(empty)+, head:head, remote:*empty* = result:head
     * 2ALT: ancest:(empty)+, head:*empty*, remote:remote = result:remote
     *
     * Note that many of these cases need not be explicitly tested, as
     * they simply degrade to "all different" cases (eg, 11):
     *
     * 4: ancest:(empty)^, head:head, remote:remote = result:no merge
     * 7: ancest:ancest+, head:(empty), remote:remote = result:no merge
     * 9: ancest:ancest+, head:head, remote:(empty) = result:no merge
     * 11: ancest:ancest+, head:head, remote:remote = result:no merge
     */
    
    /* 5ALT: ancest:*, head:head, remote:head = result:head */
    if (ours_changed && !ours_empty && !ours_theirs_differ)
		result = &delta->ours;
    /* 6: ancest:ancest+, head:(empty), remote:(empty) = result:no merge */
    else if (ours_changed && ours_empty && theirs_empty)
        *resolved = 0;
    /* 8: ancest:ancest^, head:(empty), remote:ancest = result:no merge */
    else if (ours_empty && !theirs_changed)
        *resolved = 0;
    /* 10: ancest:ancest^, head:ancest, remote:(empty) = result:no merge */
    else if (!ours_changed && theirs_empty)
        *resolved = 0;
    /* 13: ancest:ancest+, head:head, remote:ancest = result:head */
    else if (ours_changed && !theirs_changed)
		result = &delta->ours;
    /* 14: ancest:ancest+, head:ancest, remote:remote = result:remote */
    else if (!ours_changed && theirs_changed)
		result = &delta->theirs;
    else
        *resolved = 0;

    if (result != NULL && (error = merge_file_apply(index, delta, result)) >= 0)
        *resolved = 1;
    
	/* Note: trivial resolution does not update the REUC. */
	
    return error;
}

static int merge_conflict_resolve_removed(
	int *resolved,
	git_repository *repo,
	git_index *index,
	const git_diff_tree_delta *delta,
	unsigned int resolve_flags)
{
    int ours_empty, theirs_empty;
    int ours_changed, theirs_changed;
	git_diff_tree_entry const *result = NULL;
    int error = 0;

	GIT_UNUSED(resolve_flags);

    assert(resolved && repo && index && delta);

    *resolved = 0;
	
	if (resolve_flags & GIT_MERGE_RESOLVE_NO_REMOVED)
		return 0;

	/* TODO: reject non-files */
	
	ours_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->ours);
	theirs_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->theirs);

	ours_changed = (delta->ours.status != GIT_DELTA_UNMODIFIED);
	theirs_changed = (delta->theirs.status != GIT_DELTA_UNMODIFIED);
    
    /* Handle some cases that are not "trivial" but are, well, trivial. */
    
	/* Removed in both */
    if (ours_changed && ours_empty && theirs_empty)
		result = &delta->ours;
	/* Removed in ours */
    else if (ours_empty && !theirs_changed)
		result = &delta->ours;
	/* Removed in theirs */
    else if (!ours_changed && theirs_empty)
		result = &delta->theirs;
    
	if (result != NULL &&
		(error = merge_file_apply(index, delta, result)) >= 0 &&
		(error = merge_mark_conflict_resolved(index, delta)) >= 0)
        *resolved = 1;

    return error;
}

static int merge_conflict_resolve_automerge(
	int *resolved,
	git_repository *repo,
	git_index *index,
	const git_diff_tree_delta *delta,
	unsigned int resolve_flags)
{
	git_odb *odb = NULL;
	merge_filediff_result result = MERGE_FILEDIFF_RESULT_INIT;
	git_index_entry index_entry;
	git_oid automerge_oid;
	int error = 0;
	
	assert(resolved && repo && index && delta);
	
	*resolved = 0;
	
	if (resolve_flags & GIT_MERGE_RESOLVE_NO_AUTOMERGE)
		return 0;

	/* TODO: reject non-files */
	/* TODO: reject name conflicts */
	/* TODO: reject filemode conflicts */

	if ((error = git_repository_odb(&odb, repo)) < 0)
		goto done;

	if ((error = merge_filediff(&result, odb, NULL, delta, resolve_flags)) < 0 ||
		!result.automergeable ||
		(error = git_odb_write(&automerge_oid, odb, result.data, result.len, GIT_OBJ_BLOB)) < 0)
		goto done;
	
	memset(&index_entry, 0x0, sizeof(git_index_entry));

	index_entry.path = (char *)result.path;
	index_entry.file_size = result.len;
	index_entry.mode = result.mode;
	git_oid_cpy(&index_entry.oid, &automerge_oid);
	
	if ((error = git_index_add(index, &index_entry)) >= 0 &&
		(error = merge_mark_conflict_resolved(index, delta)) >= 0)
		*resolved = 1;

done:
	merge_filediff_result_free(&result);
	git_odb_free(odb);
	
	return error;
}

static int merge_conflict_resolve(
	int *out,
	git_repository *repo,
	git_index *index,
	const git_diff_tree_delta *delta,
	unsigned int resolve_flags)
{
	int resolved = 0;
	int error = 0;
	
	*out = 0;
	
	if ((error = merge_conflict_resolve_trivial(&resolved, repo, index, delta, resolve_flags)) < 0)
		goto done;
	
	if (!resolved && (error = merge_conflict_resolve_removed(&resolved, repo, index, delta, resolve_flags)) < 0)
		goto done;

	if (!resolved && (error = merge_conflict_resolve_automerge(&resolved, repo, index, delta, resolve_flags)) < 0)
		goto done;

	if (!resolved)
		error = merge_mark_conflict_unresolved(index, delta);
	
	*out = resolved;
	
done:
	return error;
}

static int merge_conflict_write_diff3(int *conflict_written,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_diff_tree_delta *delta,
	unsigned int flags)
{
	git_odb *odb = NULL;
	merge_filediff_result result = MERGE_FILEDIFF_RESULT_INIT;
	git_merge_head const *merge_heads[3] = { ancestor_head, our_head, their_head };
	git_buf workdir_path = GIT_BUF_INIT;
	git_filebuf output = GIT_FILEBUF_INIT;
	int error = 0;
	
	assert(conflict_written && repo && ancestor_head && our_head && their_head && delta);
	
	*conflict_written = 0;
	
	if (flags & GIT_MERGE_CONFLICT_NO_DIFF3)
		return 0;
	
	/* TODO: reject non-files */
	/* TODO: reject name conflicts */
	/* TODO: reject filemode conflicts */
	
	git_repository_odb(&odb, repo);
	
	if (!GIT_DIFF_TREE_FILE_EXISTS(delta->ours) || !GIT_DIFF_TREE_FILE_EXISTS(delta->theirs) ||
		(error = git_repository_odb(&odb, repo)) < 0 ||
		(error = merge_filediff(&result, odb, merge_heads, delta, 0)) < 0 ||
		result.path == NULL || result.mode == 0 ||
		(error = git_buf_joinpath(&workdir_path, git_repository_workdir(repo), result.path)) < 0 ||
		(error = git_filebuf_open(&output, workdir_path.ptr, GIT_FILEBUF_DO_NOT_BUFFER)) < 0 ||
		(error = git_filebuf_write(&output, result.data, result.len)) < 0 ||
		(error = git_filebuf_commit(&output, result.mode)) < 0)
		goto done;
	
	*conflict_written = 1;

done:
	merge_filediff_result_free(&result);
	git_odb_free(odb);
	git_buf_free(&workdir_path);
	
	return error;
}

static int merge_conflict_write_side(git_repository *repo,
	const git_merge_head *merge_head,
	const git_diff_tree_entry *entry)
{
	git_buf path = GIT_BUF_INIT;
	char oid_str[GIT_OID_HEXSZ];
	git_checkout_opts opts;
	int error = 0;
	
	assert(repo && merge_head && entry);
	
	memset(&opts, 0x0, sizeof(git_checkout_opts));

	/* TODO: what if this file exists? */

	git_buf_puts(&path, entry->file.path);
	git_buf_putc(&path, '~');
	
	if (merge_head->branch_name)
		git_buf_puts(&path, merge_head->branch_name);
	else {
		git_oid_fmt(oid_str, &merge_head->oid);
		git_buf_put(&path, oid_str, GIT_OID_HEXSZ);
	}
	
	opts.file_open_flags =  O_WRONLY | O_CREAT | O_TRUNC | O_EXCL;
	
	error = git_checkout_blob(repo, &entry->file.oid, git_buf_cstr(&path),
		entry->file.mode, &opts);

	git_buf_free(&path);
	
	return error;
}

static int merge_conflict_write_sides(int *conflict_written,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_diff_tree_delta *delta,
	unsigned int flags)
{
	int error = 0;
	
	GIT_UNUSED(flags);

	assert(conflict_written && repo && ancestor_head && our_head && their_head && delta);
	
	*conflict_written = 0;
	
	/* TODO: handle trees */
	
	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ours) &&
		(error = merge_conflict_write_side(repo, our_head, &delta->ours)) >= 0 &&
		GIT_DIFF_TREE_FILE_EXISTS(delta->theirs) &&
		(error = merge_conflict_write_side(repo, their_head, &delta->theirs)) >= 0)
		*conflict_written = 1;

	return error;
}

static int merge_conflict_write(int *out,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_diff_tree_delta *delta,
	unsigned int flags)
{
	int conflict_written = 0;
	int error = 0;

	assert(out && repo && ancestor_head && our_head && their_head && delta);
	
	*out = 0;

	if ((error = merge_conflict_write_diff3(&conflict_written, repo, ancestor_head,
		our_head, their_head, delta, flags)) < 0)
		goto done;

	if (!conflict_written)
		error = merge_conflict_write_sides(&conflict_written, repo, ancestor_head,
			our_head, their_head, delta, flags);

	*out = conflict_written;

done:
	return error;
}

/* Merge trees */

static int merge_trees(
	git_merge_result *result,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_trees_opts *opts)
{
	git_diff_tree_delta *delta;
	size_t i;
	int error = 0;

	if ((error = git_diff_tree(&result->diff_tree, repo, ancestor_tree, our_tree, their_tree, opts->diff_flags)) < 0)
		return error;
	
	git_vector_foreach(&result->diff_tree->deltas, i, delta) {
        int resolved = 0;
		
		if ((error = merge_conflict_resolve(&resolved, repo, index, delta, opts->resolve_flags)) < 0)
			return error;
		
        if (!resolved)
			git_vector_insert(&result->conflicts, delta);
	}

	return 0;
}

static int merge_trees_octopus(
	git_merge_result *result,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree **their_trees,
	size_t their_trees_len,
	const git_merge_trees_opts *opts)
{
	GIT_UNUSED(result);
	GIT_UNUSED(repo);
	GIT_UNUSED(index);
	GIT_UNUSED(ancestor_tree);
	GIT_UNUSED(our_tree);
	GIT_UNUSED(their_trees);
	GIT_UNUSED(their_trees_len);
	GIT_UNUSED(opts);
	
	giterr_set(GITERR_MERGE, "Merge octopus is not yet implemented.");
	return -1;
}

static int merge_trees_normalize_opts(
	git_merge_trees_opts *opts,
	const git_merge_trees_opts *given)
{
	if (given != NULL)
		memcpy(opts, given, sizeof(git_merge_trees_opts));
	else
		memset(opts, 0x0, sizeof(git_merge_trees_opts));

	return 0;
}

int git_merge_trees(
	git_merge_result **out,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_trees_opts *given_opts)
{
	git_merge_trees_opts opts;
	git_merge_result *result;
	int error = 0;

	assert(out && repo && index && ancestor_tree && our_tree && their_tree);
	
	*out = NULL;
	
	if ((error = merge_trees_normalize_opts(&opts, given_opts)) < 0)
		return error;
	
	result = git__calloc(1, sizeof(git_merge_result));
	GITERR_CHECK_ALLOC(result);
	
	if ((error = merge_trees(result, repo, index, ancestor_tree, our_tree, their_tree, &opts)) >= 0)
		*out = result;
	else
		git__free(result);
	
	return error;
}

/* Merge branches */

static int merge_ancestor_head(
	git_merge_head **ancestor_head,
	git_repository *repo,
	const git_merge_head *our_head,
	const git_merge_head **their_heads,
	size_t their_heads_len)
{
	git_oid *oids, ancestor_oid;
	size_t i;
	int error = 0;
	
	assert(repo && our_head && their_heads);
	
	oids = git__calloc(their_heads_len + 1, sizeof(git_oid));
	GITERR_CHECK_ALLOC(oids);
	
	git_oid_cpy(&oids[0], git_commit_id(our_head->commit));

	for (i = 0; i < their_heads_len; i++)
		git_oid_cpy(&oids[i + 1], &their_heads[i]->oid);
	
	if ((error = git_merge_base_many(&ancestor_oid, repo, oids, their_heads_len + 1)) < 0)
		goto on_error;

	return git_merge_head_from_oid(ancestor_head, repo, &ancestor_oid);

on_error:
	git__free(oids);
	return error;
}

GIT_INLINE(bool) merge_check_uptodate(
	git_merge_result *result,
	const git_merge_head *our_head,
	const git_merge_head *their_head)
{
	if (git_oid_cmp(&our_head->oid, &their_head->oid) == 0) {
		result->is_uptodate = 1;
		return true;
	}
	
	return false;
}

GIT_INLINE(bool) merge_check_fastforward(
	git_merge_result *result,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	unsigned int flags)
{
	if ((flags & GIT_MERGE_NO_FASTFORWARD) == 0 &&
		git_oid_cmp(&ancestor_head->oid, &our_head->oid) == 0) {
		result->is_fastforward = 1;
		git_oid_cpy(&result->fastforward_oid, &their_head->oid);
		
		return true;
	}
	
	return false;
}

static int merge_normalize_opts(
	git_merge_opts *opts,
	const git_merge_opts *given)
{
	int error = 0;
	unsigned int default_checkout_strategy = GIT_CHECKOUT_SAFE |
		GIT_CHECKOUT_UPDATE_MISSING |
		GIT_CHECKOUT_UPDATE_MODIFIED |
		GIT_CHECKOUT_UPDATE_UNMODIFIED |
		GIT_CHECKOUT_REMOVE_UNTRACKED |
		GIT_CHECKOUT_ALLOW_CONFLICTS;

	if (given != NULL) {
		memcpy(opts, given, sizeof(git_merge_opts));

		if (!opts->checkout_opts.checkout_strategy)
			opts->checkout_opts.checkout_strategy = default_checkout_strategy;
		
		error = merge_trees_normalize_opts(&opts->merge_trees_opts, &given->merge_trees_opts);
	} else {
		memset(opts, 0x0, sizeof(git_merge_opts));

		opts->checkout_opts.checkout_strategy = default_checkout_strategy;

		error = merge_trees_normalize_opts(&opts->merge_trees_opts, NULL);
	}

	return error;
}

int git_merge(
	git_merge_result **out,
	git_repository *repo,
	const git_merge_head **their_heads,
	size_t their_heads_len,
	const git_merge_opts *given_opts)
{
	git_merge_result *result;
	git_merge_opts opts;
	git_reference *our_ref = NULL;
	git_merge_head *ancestor_head = NULL, *our_head = NULL;
	git_tree *ancestor_tree = NULL, *our_tree = NULL, **their_trees = NULL;
	git_index *index;
	git_diff_tree_delta *delta;
	size_t i;
	int error = 0;

	assert(out && repo && their_heads);
	
	*out = NULL;
	
	result = git__calloc(1, sizeof(git_merge_result));
	GITERR_CHECK_ALLOC(result);
	
	their_trees = git__calloc(their_heads_len, sizeof(git_tree *));
	GITERR_CHECK_ALLOC(their_trees);
	
	if (merge_normalize_opts(&opts, given_opts) < 0)
		goto on_error;
	
	if ((error = git_repository__ensure_not_bare(repo, "merge")) < 0)
		goto on_error;
	
	if ((error = git_reference_lookup(&our_ref, repo, GIT_HEAD_FILE)) < 0 ||
		(error = git_merge_head_from_ref(&our_head, repo, our_ref)) < 0 ||
		(error = merge_ancestor_head(&ancestor_head, repo, our_head, their_heads, their_heads_len)) < 0)
		goto on_error;
	
	if (their_heads_len == 1 &&
		(merge_check_uptodate(result, our_head, their_heads[0]) ||
		merge_check_fastforward(result, ancestor_head, our_head, their_heads[0], opts.merge_flags))) {
		*out = result;
		goto done;
	}
	
	/* Write the merge files to the repository. */
	if ((error = git_merge__setup(repo, our_head, their_heads, their_heads_len, opts.merge_flags)) < 0)
		goto on_error;
	
	if ((error = git_commit_tree(&ancestor_tree, ancestor_head->commit)) < 0 ||
		(error = git_commit_tree(&our_tree, our_head->commit)) < 0)
		goto on_error;
	
	for (i = 0; i < their_heads_len; i++) {
		if ((error = git_commit_tree(&their_trees[i], their_heads[i]->commit)) < 0)
			goto on_error;
	}

	if ((error = git_repository_index__weakptr(&index, repo)) < 0)
		goto on_error;
	
	/* TODO: recursive */
	if (their_heads_len == 1)
		error = merge_trees(result, repo, index, ancestor_tree, our_tree,
			their_trees[0], &opts.merge_trees_opts);
	else
		error = merge_trees_octopus(result, repo, index, ancestor_tree, our_tree,
			(const git_tree **)their_trees, their_heads_len, &opts.merge_trees_opts);
	
	if (error < 0)
		goto on_error;
	
	if ((error = git_checkout_index(repo, index, &opts.checkout_opts)) < 0 ||
		(error = git_index_write(index)) < 0)
		goto on_error;
	
	if (their_heads_len == 1) {
		git_vector_foreach(&result->conflicts, i, delta) {
			int conflict_written = 0;
			
			merge_conflict_write(&conflict_written, repo, ancestor_head, our_head, their_heads[0], delta, opts.conflict_flags);
		}
	}
	
	*out = result;
	goto done;
	
on_error:
	git__free(result);

done:
	git_tree_free(ancestor_tree);
	git_tree_free(our_tree);
	
	for (i = 0; i < their_heads_len; i++)
		git_tree_free(their_trees[i]);
	
	git__free(their_trees);
	
	git_merge_head_free(our_head);
	git_merge_head_free(ancestor_head);
	
	git_reference_free(our_ref);

	return error;
}

int git_merge__cleanup(git_repository *repo)
{
	int error = 0;
	git_buf merge_head_path = GIT_BUF_INIT,
	merge_mode_path = GIT_BUF_INIT,
	merge_msg_path = GIT_BUF_INIT;
	
	assert(repo);
	
	if (git_buf_joinpath(&merge_head_path, repo->path_repository, GIT_MERGE_HEAD_FILE) < 0 ||
		git_buf_joinpath(&merge_mode_path, repo->path_repository, GIT_MERGE_MODE_FILE) < 0 ||
		git_buf_joinpath(&merge_mode_path, repo->path_repository, GIT_MERGE_MODE_FILE) < 0)
		return -1;
	
	if (git_path_isfile(merge_head_path.ptr)) {
		if ((error = p_unlink(merge_head_path.ptr)) < 0)
			goto cleanup;
	}
	
	if (git_path_isfile(merge_mode_path.ptr))
		(void)p_unlink(merge_mode_path.ptr);
	
	if (git_path_isfile(merge_msg_path.ptr))
		(void)p_unlink(merge_msg_path.ptr);
	
cleanup:
	git_buf_free(&merge_msg_path);
	git_buf_free(&merge_mode_path);
	git_buf_free(&merge_head_path);
	
	return error;
}

/* Merge result data */

int git_merge_result_is_uptodate(git_merge_result *merge_result)
{
	assert(merge_result);
	
	return merge_result->is_uptodate;
}

int git_merge_result_is_fastforward(git_merge_result *merge_result)
{
	assert(merge_result);

	return merge_result->is_fastforward;
}

int git_merge_result_fastforward_oid(git_oid *out, git_merge_result *merge_result)
{
	assert(out && merge_result);

	git_oid_cpy(out, &merge_result->fastforward_oid);
	return 0;
}

int git_merge_result_delta_foreach(git_merge_result *merge_result,
	git_diff_tree_delta_cb delta_cb,
	void *payload)
{
	git_diff_tree_delta *delta;
	size_t i;
	int error = 0;
	
	assert(merge_result && delta_cb);
	
	git_vector_foreach(&merge_result->conflicts, i, delta) {
		if (delta_cb(delta, payload) != 0) {
			error = GIT_EUSER;
			break;
		}
	}
	
	return error;
}

int git_merge_result_conflict_foreach(git_merge_result *merge_result,
	git_diff_tree_delta_cb conflict_cb,
	void *payload)
{
	git_diff_tree_delta *delta;
	size_t i;
	int error = 0;
	
	assert(merge_result && conflict_cb);
	
	git_vector_foreach(&merge_result->conflicts, i, delta) {
		if (conflict_cb(delta, payload) != 0) {
			error = GIT_EUSER;
			break;
		}
	}
	
	return error;
}

void git_merge_result_free(git_merge_result *merge_result)
{
	if (merge_result == NULL)
		return;
	
	git_vector_free(&merge_result->conflicts);
	
	git_diff_tree_list_free(merge_result->diff_tree);
	merge_result->diff_tree = NULL;

	git__free(merge_result);
}

/* git_merge_head functions */

static int merge_head_init(git_merge_head **out,
	git_repository *repo,
	const char *branch_name,
	const git_oid *oid)
{
    git_merge_head *head;
	int error = 0;
    
    assert(out && oid);
    
    *out = NULL;

    head = git__calloc(1, sizeof(git_merge_head));
    GITERR_CHECK_ALLOC(head);

    if (branch_name) {
        head->branch_name = git__strdup(branch_name);
        GITERR_CHECK_ALLOC(head->branch_name);
    }
    
    git_oid_cpy(&head->oid, oid);

	if ((error = git_commit_lookup(&head->commit, repo, &head->oid)) < 0) {
		git_merge_head_free(head);
		return error;
	}
    
    *out = head;
    return error;
}

int git_merge_head_from_ref(git_merge_head **out,
	git_repository *repo,
	git_reference *ref)
{
    git_reference *resolved;
    char const *ref_name = NULL;
    int error = 0;
    
    assert(out && ref);
    
    *out = NULL;
    
    if ((error = git_reference_resolve(&resolved, ref)) < 0)
        return error;
	
	ref_name = git_reference_name(ref);
	
	if (git__prefixcmp(ref_name, GIT_REFS_HEADS_DIR) == 0)
        ref_name += strlen(GIT_REFS_HEADS_DIR);

    error = merge_head_init(out, repo, ref_name, git_reference_target(resolved));

    git_reference_free(resolved);
    return error;
}

int git_merge_head_from_oid(git_merge_head **out,
	git_repository *repo,
	const git_oid *oid)
{
    return merge_head_init(out, repo, NULL, oid);
}

void git_merge_head_free(git_merge_head *head)
{
    if (head == NULL)
        return;

	if (head->commit != NULL)
		git_object_free((git_object *)head->commit);
    
    if (head->branch_name != NULL)
        git__free(head->branch_name);
    
    git__free(head);
}

