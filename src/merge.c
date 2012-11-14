/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "posix.h"
#include "repository.h"
#include "merge.h"
#include "path.h"
#include "refs.h"
#include "object.h"
#include "iterator.h"
#include "checkout.h"
#include "refs.h"
#include "diff.h"
#include "diff_tree.h"

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

static int merge_setup(
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

static int common_ancestor(
	git_merge_head **ancestor_head,
	git_repository *repo,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len)
{
	git_oid *oids, ancestor_oid;
	size_t i;
    int error = 0;

	assert(repo && our_head && their_heads);

	if ((oids = git__calloc(their_heads_len + 1, sizeof(git_oid))) == NULL)
		return -1;
    
    git_oid_cpy(&oids[0], git_commit_id(our_head->commit));

	for (i = 0; i < their_heads_len; i++)
		git_oid_cpy(&oids[i + 1], &their_heads[i]->oid);

	if ((error = git_merge_base_many(&ancestor_oid, repo, oids, their_heads_len + 1)) < 0)
        goto cleanup;

	return git_merge_head_from_oid(ancestor_head, repo, &ancestor_oid);

cleanup:
    git__free(oids);
    return error;
}

int git_merge(git_merge_result **out,
	git_repository *repo,
    const git_merge_head *their_heads[],
	size_t their_heads_len,
	unsigned int flags,
	git_merge_strategy merge_strategy,
	void *strategy_data)
{
	git_merge_result *result;
	git_reference *our_ref;
	git_merge_head *ancestor_head = NULL, *our_head = NULL;
	int strategy_success = 0;
	int error = 0;

	assert(out && repo && their_heads);

	*out = NULL;

	if(their_heads_len < 1) {
		giterr_set(GITERR_INVALID, "At least one commit must be merged.");
		return -1;
	}

	result = git__calloc(1, sizeof(git_merge_result));
	GITERR_CHECK_ALLOC(result);

	if ((error = git_reference_lookup(&our_ref, repo, GIT_HEAD_FILE)) < 0 ||
		(error = git_merge_head_from_ref(&our_head, repo, our_ref)) < 0)
		goto cleanup;
    
	if ((error = common_ancestor(&ancestor_head, repo, our_head, their_heads, their_heads_len)) < 0)
		goto cleanup;
    
    /* TODO: check for up-to-date? */

	/* Check for fast-forward. */
	if (their_heads_len == 1 && (flags & GIT_MERGE_NO_FASTFORWARD) == 0) {
		/* If we are our own best common ancestor, this is a fast-forward. */
		if (git_oid_cmp(&ancestor_head->oid, &our_head->oid) == 0)
		{
			result->is_fastforward = 1;
			git_oid_cpy(&result->fastforward_oid, &their_heads[0]->oid);

			goto cleanup;
		}
	}
    
	/* Set up the merge files */
	if ((error = merge_setup(repo, our_head, their_heads, their_heads_len, flags)) < 0)
		goto cleanup;

	/* Determine the best strategy if one was not provided. */
	if (merge_strategy == NULL && their_heads_len == 1)
		merge_strategy = git_merge_strategy_resolve;
	else if (merge_strategy == NULL)
		merge_strategy = git_merge_strategy_octopus;

	if((error = (*merge_strategy)(&strategy_success,
		repo,
		ancestor_head,
		our_head,
		(const git_merge_head **)their_heads,
		their_heads_len,
		strategy_data)) < 0)
		goto cleanup;

cleanup:
	git_merge_head_free(ancestor_head);
	git_merge_head_free(our_head);

	git_reference_free(our_ref);
    
	if (error == 0)
		*out = result;
	else {
		free(result);
		*out = NULL;
	}

	return error;
}

GIT_INLINE(int) merge_file_cmp(git_diff_file *a, git_diff_file *b)
{
	int value = 0;
    
    if (a->path == NULL)
        return (b->path == NULL) ? 0 : 1;
    
	if ((value = a->mode - b->mode) == 0 &&
		(value = git_oid_cmp(&a->oid, &b->oid)) == 0)
		value = strcmp(a->path, b->path);

	return value;
}

GIT_INLINE(int) merge_file_empty(git_diff_file *file)
{
    return file->path == NULL;
}

static int merge_remove_ours(git_repository *repo, git_index *index, git_diff_tree_delta *delta)
{
    git_buf path = GIT_BUF_INIT;
    int error = 0;
    
    if (delta->files[1].path == NULL)
        return 0;
    
    if ((error = git_buf_joinpath(&path, git_repository_workdir(repo), delta->files[1].path)) < 0 ||
        (error = p_unlink(path.ptr)) < 0)
        goto done;
    
    error = git_index_remove(index, delta->files[1].path, 0);
    
done:
    git_buf_free(&path);
    
    return error;
}

static int merge_file_apply(git_repository *repo, git_index *index, git_diff_tree_delta *delta, int idx)
{
	int error = 0;
    
    assert(repo && index && delta && idx >= 1 && idx <= 2);
    
    if (idx == 1 && delta->files[1].path != NULL)
        error = git_index_add_from_workdir(index, delta->files[1].path);
    else if (idx == 2 && delta->files[2].path == NULL)
        error = merge_remove_ours(repo, index, delta);
    else if(idx == 2) {
        if ((error = git_checkout_blob(repo, &delta->files[2])) >= 0)
            error = git_index_add_from_workdir(index, delta->files[2].path);
    }

	return error;
}

static int resolve_trivial(int *resolved, git_repository *repo, git_index *index, git_diff_tree_delta *delta)
{
    int ancestor_empty, ours_empty, theirs_empty;
    int ours_changed, theirs_changed, ours_theirs_changed;
    int result = 0;
    int error = 0;
    
    assert(resolved && repo && index && delta);
    
    *resolved = 0;
    
    ancestor_empty = (delta->files[0].path == NULL);
    ours_empty = (delta->files[1].path == NULL);
    theirs_empty = (delta->files[2].path == NULL);
    
    ours_changed = merge_file_cmp(&delta->files[0], &delta->files[1]);
    theirs_changed = merge_file_cmp(&delta->files[0], &delta->files[2]);
    ours_theirs_changed = merge_file_cmp(&delta->files[1], &delta->files[2]);
    
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
    if (ours_changed && !ours_empty && !ours_theirs_changed)
        result = 1;
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
        result = 1;
    /* 14: ancest:ancest+, head:ancest, remote:remote = result:remote */
    else if (!ours_changed && theirs_changed)
        result = 2;
    /* Should not happen */
    else
        *resolved = 0;

    if (result > 0 && (error = merge_file_apply(repo, index, delta, result)) >= 0)
        *resolved = 1;
    
    return error;
}

static int resolve_conflict_ours(int *resolved, git_repository *repo, git_index *index, git_diff_tree_delta *delta)
{
	assert(resolved && repo && index && delta);

	*resolved = 1;
	return merge_file_apply(repo, index, delta, 1);
}

static int resolve_conflict_theirs(int *resolved, git_repository *repo, git_index *index, git_diff_tree_delta *delta)
{
	assert(resolved && repo && index && delta);

	*resolved = 1;
    return merge_file_apply(repo, index, delta, 2);
}

static int resolve_conflict_simple(int *resolved, git_repository *repo, git_index *index, git_diff_tree_delta *delta)
{
    int ours_empty, theirs_empty;
    int ours_changed, theirs_changed, ours_theirs_changed;
    int result = 0;
    int error = 0;

    assert(resolved && repo && index && delta);
    
    *resolved = 0;
    
    ours_empty = (delta->files[1].path == NULL);
    theirs_empty = (delta->files[2].path == NULL);
    
    ours_changed = merge_file_cmp(&delta->files[0], &delta->files[1]);
    theirs_changed = merge_file_cmp(&delta->files[0], &delta->files[2]);
    ours_theirs_changed = merge_file_cmp(&delta->files[1], &delta->files[2]);
    
    /* Handle some cases that are not "trivial" but are, well, trivial. */
    
	/* Removed in both */
    if (ours_changed && ours_empty && theirs_empty)
        result = 1;
	/* Removed in ours */
    else if (ours_empty && !theirs_changed)
        result = 1;
	/* Removed in theirs */
    else if (!ours_changed && theirs_empty)
        result = 2;
    
    if (result > 0 && (error = merge_file_apply(repo, index, delta, result)) >= 0)
        *resolved = 1;

    return error;
}

typedef struct {
	bool automergeable;

	const char *path;
	int mode;

	mmbuffer_t mmbuffer;
} merge_conflict_automerge_data;

static int merge_conflict_calc_automerge_mmfile(
	mmfile_t **out,
	git_repository *repo,
	git_oid *oid)
{
    git_odb *odb;
    git_odb_object *blob;
    mmfile_t *mmfile;
    int error = 0;
    
    assert(out);

    mmfile = git__calloc(1, sizeof(mmfile_t));
    GITERR_CHECK_ALLOC(mmfile);
    
    if (oid == NULL) {
        mmfile->size = 0;
        mmfile->ptr = "";
    } else {
        if ((error = git_repository_odb(&odb, repo)) < 0 ||
            (error = git_odb_read(&blob, odb, oid)) < 0)
            goto done;
        
        mmfile->size = git_odb_object_size(blob);
        mmfile->ptr = (char *)git_odb_object_data(blob);
    }
    
    *out = mmfile;

done:
    git_odb_free(odb);
    return error;
}

static int merge_conflict_calc_automerge_data(
	merge_conflict_automerge_data **out,
	git_repository *repo,
	git_diff_tree_delta *delta)
{
	merge_conflict_automerge_data *automerge_data;
    xmparam_t xmparam;
    git_oid *ancestor_oid, *our_oid, *their_oid;
	char *ancestor_name = NULL, *our_name = NULL, *their_name = NULL;
    mmfile_t *ancestor_mmfile = NULL, *our_mmfile = NULL, *their_mmfile = NULL;
	int xdl_result;
	int error = 0;

	assert (out && repo && delta);

	*out = NULL;

	if ((automerge_data = git__calloc(1, sizeof(merge_conflict_automerge_data))) == NULL)
		return -1;

	/* TODO: handle mode conflicts and renames */
    automerge_data->path = (delta->files[0].path != NULL) ?
		delta->files[0].path : delta->files[1].path;
    automerge_data->mode = (delta->files[0].path != NULL) ?
		delta->files[0].mode : delta->files[1].mode;
    
    /* Do the auto merge */
    memset(&xmparam, 0x0, sizeof(xmparam_t));

	/*
	 * TODO:
	 * If all filenames are equal, we set the names to the branch name.  If
	 * they differ, we use branch_hane:path.
	 */

    xmparam.ancestor = delta->files[0].path == NULL ? NULL : delta->files[0].path;
    xmparam.file1 = delta->files[1].path == NULL ? NULL : delta->files[1].path;
    xmparam.file2 = delta->files[2].path == NULL ? NULL : delta->files[2].path;
    
    ancestor_oid = delta->files[0].path == NULL ? NULL : &delta->files[0].oid;
    our_oid = delta->files[1].path == NULL ? NULL : &delta->files[1].oid;
    their_oid = delta->files[2].path == NULL ? NULL : &delta->files[2].oid;

    if ((error = merge_conflict_calc_automerge_mmfile(&ancestor_mmfile, repo, ancestor_oid)) < 0 ||
        (error = merge_conflict_calc_automerge_mmfile(&our_mmfile, repo, our_oid)) < 0 ||
        (error = merge_conflict_calc_automerge_mmfile(&their_mmfile, repo, their_oid)) < 0)
        goto done;

	if ((xdl_result = xdl_merge(ancestor_mmfile, our_mmfile, their_mmfile, &xmparam, &automerge_data->mmbuffer)) < 0) {
		giterr_set(GITERR_MERGE, "Failed to perform automerge.");
		error = -1;
		goto done;
	}

	automerge_data->automergeable = (xdl_result == 0);

	*out = automerge_data;
    
done:
    if (ancestor_mmfile != NULL)
        git__free(ancestor_mmfile);
    
    if (our_mmfile != NULL)
        git__free(our_mmfile);
    
    if (their_mmfile != NULL)
        git__free(their_mmfile);

	if (ancestor_name != NULL)
		git__free(ancestor_name);
	
	if (our_name != NULL)
		git__free(our_name);
	
	if (their_name != NULL)
		git__free(their_name);

	return error;
}

static int merge_conflict_write_automerge_data(
	git_repository *repo,
	merge_conflict_automerge_data *automerge_data)
{
    git_buf workdir_path = GIT_BUF_INIT;
    git_filebuf output = GIT_FILEBUF_INIT;
    int error = 0;

	assert(repo && automerge_data);

    if ((error = git_buf_joinpath(&workdir_path, git_repository_workdir(repo), automerge_data->path)) >= 0 &&
        (error = git_filebuf_open(&output, workdir_path.ptr, GIT_FILEBUF_DO_NOT_BUFFER)) >= 0 &&
        (error = git_filebuf_write(&output, automerge_data->mmbuffer.ptr, automerge_data->mmbuffer.size)) >= 0)
        error = git_filebuf_commit(&output, automerge_data->mode);

    git_buf_free(&workdir_path);
    
	return error;
}

static int merge_conflict_apply_automerge_result(
	git_repository *repo,
	git_index *index,
	merge_conflict_automerge_data *automerge_data)
{
	int error = 0;

	if ((error = merge_conflict_write_automerge_data(repo, automerge_data)) >= 0)
		error = git_index_add_from_workdir(index, automerge_data->path);

	return error;
}

static void merge_conflict_free_automerge_data(
	merge_conflict_automerge_data *automerge_data)
{
	if (automerge_data == NULL)
		return;

	git__free(automerge_data);
}

static int merge_mark_conflict_resolved(git_index *index, git_diff_tree_delta *delta)
{
    const char *path;
    bool added[3] = { 0 };
    int mode[3];
    git_oid *oid[3];
    size_t i, j;
    int error = 0;
    
    assert(index && delta);
    
    for (i = 0; i < 3; i++) {
        if (added[i] || (path = delta->files[i].path) == NULL)
            continue;
        
        path = delta->files[i].path;
        
        for (j = 0; j < 3; j++) {
            if (j < i) {
                mode[j] = 0;
                oid[j] = NULL;
            } else {
                mode[j] = delta->files[j].mode;
                oid[j] = (mode[j] > 0) ? &delta->files[j].oid : NULL;
                added[j] = 1;
            }
        }

        if ((error = git_index_reuc_add(index, path, mode[0], oid[0], mode[1], oid[1], mode[2], oid[2])) < 0)
            goto done;
    }
    
done:
    return error;
}

static int merge_mark_conflict_unresolved(git_index *index, git_diff_tree_delta *delta)
{
    bool exists[3] = { 0 };
    git_index_entry conflict_entry[3];
    size_t i;
    
    assert(index && delta);
    
    for (i = 0; i < 3; i++) {
        if (delta->files[i].path == NULL)
            continue;
        
        exists[i] = 1;
        
        memset(&conflict_entry[i], 0x0, sizeof(git_index_entry));

        conflict_entry[i].path = (char *)delta->files[i].path;
        conflict_entry[i].mode = delta->files[i].mode;
        
        git_oid_cpy(&conflict_entry[i].oid, &delta->files[i].oid);
    }

	return git_index_conflict_add(index,
		exists[0] ? &conflict_entry[0] : NULL,
        exists[1] ? &conflict_entry[1] : NULL,
		exists[2] ? &conflict_entry[2] : NULL);
}

int git_merge_strategy_resolve(
	int *out,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	void *data)
{
	git_index *index = NULL;
    git_tree *trees[3];
    git_tree *ancestor_tree = NULL, *our_tree = NULL, *their_tree = NULL;
	git_diff_tree_list *diff_tree;
	git_diff_tree_delta *delta;
	git_merge_strategy_resolve_options *options;
	merge_conflict_automerge_data *automerge_data = NULL;
	int (*resolve_cb)(int *resolved, git_repository *repo, git_index *index,
		git_diff_tree_delta *delta) = NULL;
    bool do_simple = 1, do_automerge = 1, do_diff3_file = 1;
	size_t i;
	int error = 0;

	assert(repo && ancestor_head && our_head && their_heads);

	options = (git_merge_strategy_resolve_options *)data;

	*out = 1;

	if (their_heads_len != 1)	{
		giterr_set(GITERR_INVALID, "Merge strategy: ours requires exactly one head.");
		return -1;
	}

	if (options != NULL && (options->flags & GIT_MERGE_STRATEGY_RESOLVE_NO_SIMPLE))
		do_simple = 0;
    
    if (options != NULL && (options->flags & GIT_MERGE_STRATEGY_RESOLVE_NO_AUTOMERGE))
        do_automerge = 0;
    
    if (!do_automerge || (options != NULL && (options->flags & GIT_MERGE_STRATEGY_RESOLVE_NO_DIFF3_FILE)))
        do_diff3_file = 0;

	if (options != NULL &&
		options->resolver == GIT_MERGE_STRATEGY_RESOLVE_OURS)
		resolve_cb = resolve_conflict_ours;
	else if (options != NULL &&
		options->resolver == GIT_MERGE_STRATEGY_RESOLVE_THEIRS)
		resolve_cb = resolve_conflict_theirs;

	if ((error = git_repository_index(&index, repo)) < 0)
		goto done;

	if ((error = git_commit_tree(&ancestor_tree, (git_commit *)ancestor_head->commit)) < 0 ||
		(error = git_commit_tree(&our_tree, (git_commit *)our_head->commit)) < 0 ||
		(error = git_commit_tree(&their_tree, (git_commit *)their_heads[0]->commit)) < 0)
		goto done;

    trees[0] = ancestor_tree;
    trees[1] = our_tree;
    trees[2] = their_tree;

    if ((error = git_diff_trees(&diff_tree, repo, trees, 3, 0)) < 0)
        goto done;

	git_vector_foreach(&diff_tree->deltas, i, delta) {
        int resolved = 0;

		assert(delta->files);
        
        /* 
         * Handle "trivial" differences specially.  These are not quite
         * conflicts and are therefore not recorded in the REUC.
         */
        if ((error = resolve_trivial(&resolved, repo, index, delta)) < 0)
            goto done;

        /* Handle conflicts */
        if (!resolved) {
            /* Try to handle some simple differences. */
			if (do_simple && 
            	(error = resolve_conflict_simple(&resolved, repo, index, delta)) < 0)
                goto done;

			/* Determine the mergeability for automerge or writing diff3 */
			if (!resolved &&
				(do_automerge || do_diff3_file) &&
				(error = merge_conflict_calc_automerge_data(&automerge_data, repo, delta)) < 0)
					goto done;

			/* Try automerge unless configured otherwise */
			if (!resolved && do_automerge && automerge_data->automergeable) {
				if ((error = merge_conflict_apply_automerge_result(repo, index, automerge_data)) < 0)
					goto done;

				resolved = 1;
			}

			/* Fall back to other resolver(s) */
			if (!resolved && resolve_cb != NULL &&
				(error = resolve_cb(&resolved, repo, index, delta)) < 0)
				goto done;

			/* If this is resolved, mark it as such */
			if (resolved)
				error = merge_mark_conflict_resolved(index, delta);
			else {
				/* Remove the file from the workdir and the index */
				if ((error = merge_remove_ours(repo, index, delta)) < 0)
					goto done;

				/* Optionally write the diff3 output to the workdir */
				if (do_diff3_file)
					error = merge_conflict_write_automerge_data(repo, automerge_data);
			}

			if (error < 0)
				goto done;
        }

        /* Still not resolved, mark it as such. */
        if (! resolved)
            merge_mark_conflict_unresolved(index, delta);
	}

	git_index_write(index);

done:
	merge_conflict_free_automerge_data(automerge_data);
    git_object_free((git_object *)ancestor_tree);
    git_object_free((git_object *)our_tree);
    git_object_free((git_object *)their_tree);
	git_index_free(index);

	return error;
}

int git_merge_strategy_octopus(
	int *success,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	void *data)
{
	assert(repo && ancestor_head && our_head && their_heads);

	if(their_heads_len < 2) {
		giterr_set(GITERR_INVALID, "Merge strategy: octopus requires at least two heads.");
		return -1;
	}

	GIT_UNUSED(repo);
	GIT_UNUSED(ancestor_head);
	GIT_UNUSED(our_head);
	GIT_UNUSED(their_heads);
	GIT_UNUSED(data);

	*success = 0;

	giterr_set(GITERR_MERGE, "Merge strategy: octopus is not yet implemented.");
	return -1;
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


void git_merge_result_free(git_merge_result *merge_result)
{
	if (merge_result == NULL)
		return;

	git__free(merge_result);
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
    char *ref_name = NULL;
    int error = 0;
    
    assert(out && ref);
    
    *out = NULL;
    
    if ((error = git_reference_resolve(&resolved, ref)) < 0)
        return error;
    
    if (git__prefixcmp(git_reference_name(ref), GIT_REFS_HEADS_DIR) == 0) {
        ref_name = (char *)git_reference_name(ref) + strlen(GIT_REFS_HEADS_DIR);
    }

    error = merge_head_init(out, repo, ref_name, git_reference_oid(resolved));

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
