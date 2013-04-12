/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "posix.h"
#include "buffer.h"
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
#include "checkout.h"
#include "tree.h"
#include "merge_file.h"
#include "merge_branches.h"

#include "git2/types.h"
#include "git2/repository.h"
#include "git2/object.h"
#include "git2/commit.h"
#include "git2/merge.h"
#include "git2/merge_branches.h"
#include "git2/refs.h"
#include "git2/reset.h"
#include "git2/checkout.h"
#include "git2/signature.h"
#include "git2/config.h"
#include "git2/tree.h"

/* TODO: remove */
#define GIT_MERGE_INDEX_ENTRY_EXISTS(X)	((X).mode != 0)

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

	if ((error = git_buf_joinpath(&merge_head_path, repo->path_repository, GIT_MERGE_HEAD_FILE)) < 0)
		return error;

	if ((error = git_filebuf_open(&merge_head_file, merge_head_path.ptr, GIT_FILEBUF_FORCE)) < 0)
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

/* Conflict handling */

static char *merge_filediff_entry_name(
	const git_merge_head *merge_head,
	const git_index_entry *file,
	bool rename)
{
	char oid_str[GIT_OID_HEXSZ];
	git_buf name = GIT_BUF_INIT;

	assert(merge_head && file);

	if (merge_head->branch_name)
		git_buf_puts(&name, merge_head->branch_name);
	else {
		git_oid_fmt(oid_str, &merge_head->oid);
		git_buf_put(&name, oid_str, GIT_OID_HEXSZ);
	}
   
	if (rename) {
		git_buf_putc(&name, ':');
		git_buf_puts(&name, file->path);
	}

	return name.ptr;
}

static int merge_filediff_entry_names(char **our_path,
	char **their_path,
	const git_merge_head *merge_heads[],
	const git_merge_index_conflict *conflict)
{
	bool rename;

	*our_path = NULL;
	*their_path = NULL;

	if (!merge_heads)
		return 0;

	/*
	 * If all the paths are identical, decorate the diff3 file with the branch
	 * names.  Otherwise, use branch_name:path
	 */
	rename = GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) &&
		GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) &&
		strcmp(conflict->our_entry.path, conflict->their_entry.path) != 0;

	if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) &&
		(*our_path = merge_filediff_entry_name(merge_heads[1], &conflict->our_entry, rename)) == NULL)
		return -1;

	if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) &&
		(*their_path = merge_filediff_entry_name(merge_heads[2], &conflict->their_entry, rename)) == NULL)
		return -1;

	return 0;
}

static int merge_conflict_path_with_head(
	git_buf *out,
	const char *path,
	const git_merge_head *merge_head)
{
	char oid_str[GIT_OID_HEXSZ];
	int error = 0;
	
	if ((error = git_buf_puts(out, path)) < 0 ||
		(error = git_buf_putc(out, '~')) < 0)
		return error;
	
	if (merge_head->branch_name)
		error = git_buf_puts(out, merge_head->branch_name);
	else {
		git_oid_fmt(oid_str, &merge_head->oid);
		error = git_buf_put(out, oid_str, GIT_OID_HEXSZ);
	}
	
	return error;
}

static int merge_conflict_write_diff3(
	int *conflict_written,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_merge_index_conflict *conflict,
	unsigned int flags)
{
	git_merge_file_input ancestor = GIT_MERGE_FILE_INPUT_INIT,
		ours = GIT_MERGE_FILE_INPUT_INIT,
		theirs = GIT_MERGE_FILE_INPUT_INIT;
	git_merge_file_result result = GIT_MERGE_FILE_RESULT_INIT;
	char *our_label = NULL, *their_label = NULL;
	git_merge_head const *merge_heads[3] = { ancestor_head, our_head, their_head };
	git_buf workdir_path = GIT_BUF_INIT, path_with_head = GIT_BUF_INIT;
	git_filebuf output = GIT_FILEBUF_INIT;
	const char *path;
	int error = 0;
	
	assert(conflict_written && repo && our_head && their_head && conflict);
	
	*conflict_written = 0;
	
	if (flags & GIT_MERGE_CONFLICT_NO_DIFF3)
		return 0;

	/* Reject link/file conflicts. */
	if ((S_ISLNK(conflict->ancestor_entry.mode) ^ S_ISLNK(conflict->our_entry.mode)) ||
		(S_ISLNK(conflict->ancestor_entry.mode) ^ S_ISLNK(conflict->their_entry.mode)))
		return 0;
	
	/* Reject D/F conflicts */
	if (conflict->type == GIT_MERGE_CONFLICT_DIRECTORY_FILE ||
		conflict->type == GIT_MERGE_CONFLICT_RENAMED_ADDED)
		return 0;

	/* TODO: reject name conflicts? */
	
	/* TODO: mkpath2file mode */
	if (!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ||
		!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) ||
		(error = git_merge_file_input_from_index_entry(&ancestor, repo, &conflict->ancestor_entry)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&ours, repo, &conflict->our_entry)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&theirs, repo, &conflict->their_entry)) < 0 ||
		(error = merge_filediff_entry_names(&our_label, &their_label, merge_heads, conflict)) < 0)
		goto done;

	ancestor.label = NULL;
	ours.label = our_label;
	theirs.label = their_label;
	
	if ((error = git_merge_files(&result, &ancestor, &ours, &theirs, 0)) < 0 ||
		result.path == NULL || result.mode == 0)
		goto done;

	/* Rename 2->1 conflicts need the branch name appended */
	if (conflict->type == GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1) {
		if ((error = merge_conflict_path_with_head(&path_with_head, result.path,
			(strcmp(result.path, conflict->our_entry.path) == 0 ? our_head : their_head))) < 0)
			goto done;
		
		path = git_buf_cstr(&path_with_head);
	} else
		path = result.path;

	if ((error = git_buf_joinpath(&workdir_path, git_repository_workdir(repo), path)) < 0 ||
		(error = git_futils_mkpath2file(workdir_path.ptr, 0755) < 0) ||
		(error = git_filebuf_open(&output, workdir_path.ptr, GIT_FILEBUF_DO_NOT_BUFFER)) < 0 ||
		(error = git_filebuf_write(&output, result.data, result.len)) < 0 ||
		(error = git_filebuf_commit(&output, result.mode)) < 0)
		goto done;
	
	*conflict_written = 1;
	
done:
	git__free(our_label);
	git__free(their_label);

	git_merge_file_input_free((git_merge_file_input *)&ancestor);
	git_merge_file_input_free((git_merge_file_input *)&ours);
	git_merge_file_input_free((git_merge_file_input *)&theirs);
	git_merge_file_result_free(&result);
	git_buf_free(&workdir_path);
	git_buf_free(&path_with_head);
	
	return error;
}

static int merge_conflict_write_file(
	git_repository *repo,
	const git_index_entry *entry,
	const char *path)
{
    git_config *cfg;
    git_checkout_opts checkout_opts = GIT_CHECKOUT_OPTS_INIT;
    git_buf checkout_path = GIT_BUF_INIT;
    int can_symlink;
    struct stat st;
    int error;

    checkout_opts.checkout_strategy |= GIT_CHECKOUT_NO_REFRESH;
    checkout_opts.file_open_flags = O_RDWR|O_CREAT;
    checkout_opts.dir_mode = 0755;

	if (path == NULL)
        path = entry->path;
	
    if ((error = git_buf_joinpath(&checkout_path, git_repository_workdir(repo), path)) < 0)
        goto done;
	
    if ((error = git_repository_config__weakptr(&cfg, repo)) < 0)
        return error;
	
    /* TODO: this is horribly mediocre */
    error = git_config_get_bool(&can_symlink, cfg, "core.symlinks");
    if (error < 0) {
        if (error != GIT_ENOTFOUND)
            goto done;
		
        /* If "core.symlinks" is not found anywhere, default to true. */
        can_symlink = true;
        giterr_clear();
        error = 0;
    }
	
	error = git_checkout_blob(repo, &entry->oid, git_buf_cstr(&checkout_path),
		entry->mode, &st, can_symlink, &checkout_opts);
	
done:
    return error;
}

static int merge_conflict_write_side(
	git_repository *repo,
	const git_merge_head *merge_head,
	const git_merge_index_conflict *conflict,
	const git_index_entry *entry,
	unsigned int flags)
{
	const char *path = entry->path;
	git_buf path_with_head = GIT_BUF_INIT;
	int error = 0;
	
	assert(repo && merge_head && entry);
	
	/* TODO: what if this file exists? */

	/* 
	 * Mutate the name if we're D/F conflicted, rename/add conflicted
	 * or if we didn't write a diff3 file.
	 */
	if (conflict->type == GIT_MERGE_CONFLICT_RENAMED_ADDED ||
		conflict->type == GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1 ||
		conflict->type == GIT_MERGE_CONFLICT_DIRECTORY_FILE ||
		(flags & GIT_MERGE_CONFLICT_NO_DIFF3)) {
		if ((error = merge_conflict_path_with_head(&path_with_head, entry->path, merge_head)) < 0)
			return error;
		
		path = git_buf_cstr(&path_with_head);
	}

	error = merge_conflict_write_file(repo, entry, path);

	git_buf_free(&path_with_head);
	
	return error;
}

static int merge_conflict_write_sides(
	int *conflict_written,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_merge_index_conflict *conflict,
	unsigned int flags)
{
	int error = 0;

	GIT_UNUSED(ancestor_head);
	
	assert(conflict_written && repo && our_head && their_head && conflict);
	
	*conflict_written = 0;

	if (flags & GIT_MERGE_CONFLICT_NO_SIDES)
		return 0;
	
	if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) &&
		(error = merge_conflict_write_side(repo, our_head, conflict, &conflict->our_entry, flags)) < 0)
		goto done;
	
	if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry) &&
		(error = merge_conflict_write_side(repo, their_head, conflict, &conflict->their_entry, flags)) < 0)
		goto done;

done:
	if (error >= 0)
		*conflict_written = 1;

	return error;
}

static int merge_conflict_write_modifydelete_file(
	int *conflict_written,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_merge_index_conflict *conflict,
	unsigned int flags)
{
	int error = 0;
	const git_index_entry *entry;
	const char *path;

	assert(conflict_written && repo && ancestor_head && our_head && their_head && conflict);
   
	*conflict_written = 0;

	if (flags & GIT_MERGE_CONFLICT_NO_MODIFYDELETE_FILE)
		return 0;
	
	if (conflict->type != GIT_MERGE_CONFLICT_MODIFIED_DELETED &&
		conflict->type != GIT_MERGE_CONFLICT_RENAMED_DELETED)
		return 0;

	if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry)) {
		entry = &conflict->our_entry;
		path = conflict->our_entry.path;
	} else if(GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry)) {
		entry = &conflict->their_entry;
		path = conflict->their_entry.path;
	} else {
		/* TODO: Should never happen.  Error. */
		return 0;
	}

	if ((error = merge_conflict_write_file(repo, entry, path)) == 0)
		*conflict_written = 1;

	return error;
}

static int merge_conflict_write_ours(
   int *conflict_written,
   git_repository *repo,
   const git_merge_head *ancestor_head,
   const git_merge_head *our_head,
   const git_merge_head *their_head,
   const git_merge_index_conflict *conflict,
   unsigned int flags)
{
	int error = 0;

	assert(conflict_written && repo && ancestor_head && our_head &&
		their_head && conflict);
   
	*conflict_written = 0;

	if (! (flags & GIT_MERGE_CONFLICT_KEEP_OURS))
		return 0;

	if (!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry))
		return 0;

	if ((error = merge_conflict_write_file(repo, &conflict->our_entry,
		conflict->our_entry.path)) == 0)
		*conflict_written = 1;

	return error;
}

int merge_conflict_write(int *out,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_merge_index_conflict *conflict,
	unsigned int flags)
{
	int conflict_written = 0;
	int error = 0;

	assert(out && repo && our_head && their_head && conflict);
	
	*out = 0;

	error = merge_conflict_write_diff3(&conflict_written, repo, ancestor_head,
		our_head, their_head, conflict, flags);

	if (!conflict_written && !error)
		error = merge_conflict_write_sides(&conflict_written, repo,
			ancestor_head, our_head, their_head, conflict, flags);

	if (!conflict_written && !error)
		error = merge_conflict_write_modifydelete_file(&conflict_written,
			repo, ancestor_head, our_head, their_head, conflict, flags);

	if (!conflict_written && !error)
		error = merge_conflict_write_ours(&conflict_written, repo,
			ancestor_head, our_head, their_head, conflict, flags);

	if (!error)
		*out = conflict_written;

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

	error = git_merge_head_from_oid(ancestor_head, repo, &ancestor_oid);

on_error:
	git__free(oids);
	return error;
}

GIT_INLINE(bool) merge_check_uptodate(
	git_merge_result *result,
	const git_merge_head *ancestor_head,
	const git_merge_head *their_head)
{
	if (git_oid_cmp(&ancestor_head->oid, &their_head->oid) == 0) {
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
	git_repository *repo,
	git_merge_opts *opts,
	const git_merge_opts *given)
{
	int error = 0;
	unsigned int default_checkout_strategy = GIT_CHECKOUT_SAFE_CREATE |
		GIT_CHECKOUT_FORCE |
		GIT_CHECKOUT_REMOVE_UNTRACKED |
		GIT_CHECKOUT_ALLOW_CONFLICTS |
		GIT_CHECKOUT_MAINTAIN_REUC;

	GIT_UNUSED(repo);
	
	if (given != NULL) {
		memcpy(opts, given, sizeof(git_merge_opts));

		if (!opts->checkout_opts.checkout_strategy)
			opts->checkout_opts.checkout_strategy = default_checkout_strategy;
	} else {
		git_merge_opts default_opts = GIT_MERGE_OPTS_INIT;
		memcpy(opts, &default_opts, sizeof(git_merge_opts));
		
		opts->checkout_opts.checkout_strategy = default_checkout_strategy;
	}

	return error;
}

static int merge_indexes(git_repository *repo, git_index *index_new)
{
	int error = 0;
	size_t i;
	git_tree *head_tree = NULL;
	git_index *index_repo = NULL;
	unsigned int index_repo_caps = 0;
	git_iterator *iter_head = NULL, *iter_repo = NULL, *iter_new = NULL;
	const git_index_entry *e;
	const git_index_name_entry *name;
	git_index_reuc_entry *reuc;
	git_diff_list *merged_list = NULL, *index_dirty_list = NULL, *wd_dirty_list = NULL;
	git_diff_delta *delta;
	git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
	git_vector paths = GIT_VECTOR_INIT;

	if ((error = git_repository_head_tree(&head_tree, repo)) < 0 ||
		(error = git_repository_index(&index_repo, repo)) < 0)
		goto done;

	/* Set the index to case sensitive to handle the merge */
	index_repo_caps = git_index_caps(index_repo);
    
    if ((error = git_index_set_caps(index_repo, (index_repo_caps & ~GIT_INDEXCAP_IGNORE_CASE))) < 0)
        goto done;

	if ((error = git_iterator_for_tree(&iter_head, head_tree, GIT_ITERATOR_DONT_IGNORE_CASE, NULL, NULL)) < 0 ||
		(error = git_iterator_for_index(&iter_new, index_new, GIT_ITERATOR_DONT_IGNORE_CASE, NULL, NULL)) < 0)
		goto done;

	/* Determine paths affected by this merge */
	if ((error = git_diff__from_iterators(&merged_list, repo, iter_head, iter_new, &opts)) < 0)
		goto done;

	git_vector_foreach(&merged_list->deltas, i, delta) {
		git_vector_insert(&paths, (void *)delta->new_file.path);
	}

	for (i = 0; i < git_index_entrycount(index_new); i++) {
		e = git_index_get_byindex(index_new, i);
		
		if (git_index_entry_stage(e) != 0 &&
			(git_vector_last(&paths) == NULL ||
			strcmp(git_vector_last(&paths), e->path) != 0))
			git_vector_insert(&paths, e->path);
	}

	/* Ensure there are no local changes to these paths */
	opts.pathspec.count = paths.length;
	opts.pathspec.strings = (char **)paths.contents;

	git_diff_tree_to_index(&index_dirty_list, repo, head_tree, index_repo, &opts);
	git_diff_tree_to_workdir(&wd_dirty_list, repo, head_tree, &opts);

	if (index_dirty_list->deltas.length > 0 || wd_dirty_list->deltas.length > 0) {
		size_t count = index_dirty_list->deltas.length + wd_dirty_list->deltas.length;
		
		giterr_set(GITERR_MERGE, "%d uncommitted change%s would be overwritten by merge",
			count, (count != 1) ? "s" : "");

		error = GIT_EMERGECONFLICT;
		goto done;
	}

	/* Update the new index */
	git_vector_foreach(&merged_list->deltas, i, delta) {
		if ((e = git_index_get_bypath(index_new, delta->new_file.path, 0)) != NULL)
			error = git_index_add(index_repo, e);
		else
			error = git_index_remove(index_repo, delta->new_file.path, 0);
	}

	/* Add conflicts */
	for (i = 0; i < git_index_entrycount(index_new); i++)
	{
		e = git_index_get_byindex(index_new, i);
		
		if (git_index_entry_stage(e) != 0 &&
			(error = git_index_add(index_repo, e)) < 0)
			goto done;
	}

	/* Add name entries */
	for (i = 0; i < git_index_name_entrycount(index_new); i++)
	{
		name = git_index_name_get_byindex(index_new, i);

		if ((error = git_index_name_add(index_repo, name->ancestor, name->ours, name->theirs)) < 0)
			goto done;
	}

	/* Add the reuc */
	for (i = 0; i < git_index_reuc_entrycount(index_new); i++)
	{
		reuc = (git_index_reuc_entry *)git_index_reuc_get_byindex(index_new, i);

		if ((error = git_index_reuc_add(index_repo, reuc->path,
			reuc->mode[0], &reuc->oid[0],
			reuc->mode[1], &reuc->oid[1],
			reuc->mode[2], &reuc->oid[2])) < 0)
			goto done;
	}

done:
	if (index_repo != NULL)
        git_index_set_caps(index_repo, index_repo_caps);

	git_tree_free(head_tree);
	git_vector_free(&paths);
	git_diff_list_free(wd_dirty_list);
	git_diff_list_free(index_dirty_list);
	git_diff_list_free(merged_list);
	git_iterator_free(iter_repo);
	git_iterator_free(iter_head);
	git_iterator_free(iter_new);
	git_index_free(index_repo);

	return error;
}

static int merge_trees_octopus(
	git_index **result,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree **their_trees,
	size_t their_trees_len,
	const git_merge_tree_opts *opts)
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

int merge_trees(
				git_index **out,
				git_repository *repo,
				const git_tree *ancestor_tree,
				const git_tree *our_tree,
				const git_tree *their_tree,
				const git_merge_tree_opts *opts);

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
	git_index *index_new = NULL, *index_repo = NULL;
	git_merge_index_conflict *conflict;
	size_t i;
	int error = 0;

	assert(out && repo && their_heads);
	
	*out = NULL;
	
	result = git__calloc(1, sizeof(git_merge_result));
	GITERR_CHECK_ALLOC(result);
	
	their_trees = git__calloc(their_heads_len, sizeof(git_tree *));
	GITERR_CHECK_ALLOC(their_trees);
	
	if (merge_normalize_opts(repo, &opts, given_opts) < 0)
		goto on_error;
	
	if ((error = git_repository__ensure_not_bare(repo, "merge")) < 0)
		goto on_error;
	
	if ((error = git_reference_lookup(&our_ref, repo, GIT_HEAD_FILE)) < 0 ||
		(error = git_merge_head_from_ref(&our_head, repo, our_ref)) < 0)
		goto on_error;
	
	if ((error = merge_ancestor_head(&ancestor_head, repo, our_head, their_heads, their_heads_len)) < 0 &&
		error != GIT_ENOTFOUND)
		goto on_error;
	
	if (their_heads_len == 1 &&
		ancestor_head != NULL &&
		(merge_check_uptodate(result, ancestor_head, their_heads[0]) ||
		merge_check_fastforward(result, ancestor_head, our_head, their_heads[0], opts.merge_flags))) {
		*out = result;
		goto done;
	}

	/* If FASTFORWARD_ONLY is specified, fail. */
	if ((opts.merge_flags & GIT_MERGE_FASTFORWARD_ONLY) ==
		GIT_MERGE_FASTFORWARD_ONLY) {
		giterr_set(GITERR_MERGE, "Not a fast-forward.");
		error = GIT_ENONFASTFORWARD;
		goto on_error;
	}
	
	/* Write the merge files to the repository. */
	if ((error = git_merge__setup(repo, our_head, their_heads, their_heads_len, opts.merge_flags)) < 0)
		goto on_error;
	
	if (ancestor_head != NULL &&
		(error = git_commit_tree(&ancestor_tree, ancestor_head->commit)) < 0)
			goto on_error;

	if ((error = git_commit_tree(&our_tree, our_head->commit)) < 0)
		goto on_error;

	for (i = 0; i < their_heads_len; i++) {
		if ((error = git_commit_tree(&their_trees[i], their_heads[i]->commit)) < 0)
			goto on_error;
	}

	/* TODO: recursive, octopus, etc... */
	
	if ((error = git_merge_trees(&index_new, repo, ancestor_tree, our_tree, their_trees[0], &opts.merge_tree_opts)) < 0 ||
		(error = merge_indexes(repo, index_new)) < 0 ||
		(error = git_repository_index(&index_repo, repo)) < 0 ||
		(error = git_checkout_index(repo, index_repo, &opts.checkout_opts)) < 0)
		goto on_error;

	if (their_heads_len == 1) {
		git_vector_foreach(&merge_index->conflicts, i, conflict) {
			int conflict_written = 0;
			
			if ((error = merge_conflict_write(&conflict_written, repo,
				ancestor_head, our_head, their_heads[0], conflict, opts.conflict_flags)) < 0)
				goto on_error;
		}
	}
	
	result->index = index_new;
	
	*out = result;
	goto done;
	
on_error:
	git__free(result);

done:
	git_index_free(index_new);
	git_index_free(index_repo);

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

void git_merge_result_free(git_merge_result *merge_result)
{
	if (merge_result == NULL)
		return;
	
	git_index_free(merge_result->index);
	merge_result->index = NULL;
	
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
