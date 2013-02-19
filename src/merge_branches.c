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
#include "diff_tree.h"
#include "checkout.h"
#include "tree.h"
#include "merge_file.h"

#include "git2/diff_tree.h"
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

	return name.ptr;
}

static int merge_filediff_entry_names(char **our_path,
	char **their_path,
	const git_merge_head *merge_heads[],
	const git_diff_tree_delta *delta)
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
	rename = GIT_DIFF_TREE_FILE_EXISTS(delta->ours) &&
		GIT_DIFF_TREE_FILE_EXISTS(delta->theirs) &&
		strcmp(delta->ours.file.path, delta->theirs.file.path) != 0;

	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ours) &&
		(*our_path = merge_filediff_entry_name(merge_heads[1], &delta->ours, rename)) == NULL)
		return -1;

	if (GIT_DIFF_TREE_FILE_EXISTS(delta->theirs) &&
		(*their_path = merge_filediff_entry_name(merge_heads[2], &delta->theirs, rename)) == NULL)
		return -1;

	return 0;
}

static int merge_conflict_write_diff3(
	int *conflict_written,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_diff_tree_delta *delta,
	unsigned int flags)
{
	git_merge_file_input ancestor = GIT_MERGE_FILE_INPUT_INIT,
		ours = GIT_MERGE_FILE_INPUT_INIT,
		theirs = GIT_MERGE_FILE_INPUT_INIT;
	git_merge_file_result result = GIT_MERGE_FILE_RESULT_INIT;
	char *our_label = NULL, *their_label = NULL;
	git_merge_head const *merge_heads[3] = { ancestor_head, our_head, their_head };
	git_buf workdir_path = GIT_BUF_INIT;
	git_filebuf output = GIT_FILEBUF_INIT;
	int error = 0;
	
	assert(conflict_written && repo && ancestor_head && our_head && their_head && delta);
	
	*conflict_written = 0;
	
	if (flags & GIT_MERGE_CONFLICT_NO_DIFF3)
		return 0;

	/* Reject link/file conflicts. */
	if ((S_ISLNK(delta->ancestor.file.mode) ^ S_ISLNK(delta->ours.file.mode)) ||
		(S_ISLNK(delta->ancestor.file.mode) ^ S_ISLNK(delta->theirs.file.mode)))
		return 0;
	
	/* Reject D/F conflicts */
	if (delta->df_conflict == GIT_DIFF_TREE_DF_DIRECTORY_FILE)
		return 0;

	/* TODO: reject name conflicts? */
	
	/* TODO: mkpath2file mode */
	if (!GIT_DIFF_TREE_FILE_EXISTS(delta->ours) ||
		!GIT_DIFF_TREE_FILE_EXISTS(delta->theirs) ||
		(error = git_merge_file_input_from_diff_tree_entry((git_merge_file_input *)&ancestor, repo, &delta->ancestor)) < 0 ||
		(error = git_merge_file_input_from_diff_tree_entry((git_merge_file_input *)&ours, repo, &delta->ours)) < 0 ||
		(error = git_merge_file_input_from_diff_tree_entry((git_merge_file_input *)&theirs, repo, &delta->theirs)) < 0 ||
		(error = merge_filediff_entry_names(&our_label, &their_label, merge_heads, delta)) < 0)
		goto done;

	ancestor.label = NULL;
	ours.label = our_label;
	theirs.label = their_label;
	
	if ((error = git_merge_files(&result, (git_merge_file_input *)&ancestor, (git_merge_file_input *)&ours, (git_merge_file_input *)&theirs, 0)) < 0 ||
		result.path == NULL || result.mode == 0 ||
		(error = git_buf_joinpath(&workdir_path, git_repository_workdir(repo), result.path)) < 0 ||
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
	
	return error;
}

static int merge_conflict_write_file(
	git_repository *repo,
	const git_diff_tree_entry *entry,
	const char *path)
{
	git_checkout_opts checkout_opts = GIT_CHECKOUT_OPTS_INIT;
	git_checkout_data checkout_data;
	struct stat st;
	git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;
	int error;

	opts.file_open_flags =  O_WRONLY | O_CREAT | O_TRUNC | O_EXCL;
	
	if (path == NULL)
		path = entry->file.path;

	git_checkout_data_init(&checkout_data, repo, NULL, &checkout_opts);

	git_buf_truncate(&checkout_data.path, checkout_data.workdir_len);
	if (git_buf_puts(&checkout_data.path, path) < 0)
		return -1;

	error = git_checkout_blob(&st, &checkout_data, &entry->file.oid, git_buf_cstr(&checkout_data.path), entry->file.mode);

	git_checkout_data_clear(&checkout_data);

	return error;
}

static int merge_conflict_write_side(
	git_repository *repo,
	const git_merge_head *merge_head,
	const git_diff_tree_delta *delta,
	const git_diff_tree_entry *entry,
	unsigned int flags)
{
	const char *path = entry->file.path;
	git_buf path_with_branch = GIT_BUF_INIT;
	char oid_str[GIT_OID_HEXSZ];
	int error = 0;
	
	assert(repo && merge_head && entry);
	
	/* TODO: what if this file exists? */

	/* 
	 * Mutate the name if we're D/F conflicted or if we didn't write a diff3
	 * file.
	 */
	if (delta->df_conflict == GIT_DIFF_TREE_DF_DIRECTORY_FILE ||
		(flags & GIT_MERGE_CONFLICT_NO_DIFF3)) {
		git_buf_puts(&path_with_branch, entry->file.path);
		git_buf_putc(&path_with_branch, '~');
		
		if (merge_head->branch_name)
			git_buf_puts(&path_with_branch, merge_head->branch_name);
		else {
			git_oid_fmt(oid_str, &merge_head->oid);
			git_buf_put(&path_with_branch, oid_str, GIT_OID_HEXSZ);
		}
		
		path = git_buf_cstr(&path_with_branch);
	}

	error = merge_conflict_write_file(repo, entry, path);

	git_buf_free(&path_with_branch);
	
	return error;
}

static int merge_conflict_write_sides(
	int *conflict_written,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_head,
	const git_diff_tree_delta *delta,
	unsigned int flags)
{
	int error = 0;
	
	assert(conflict_written && repo && ancestor_head && our_head && their_head && delta);
	
	*conflict_written = 0;

	if (flags & GIT_MERGE_CONFLICT_NO_SIDES)
		return 0;
	
	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ours) &&
		(error = merge_conflict_write_side(repo, our_head, delta, &delta->ours, flags)) < 0)
		goto done;
	
	if (GIT_DIFF_TREE_FILE_EXISTS(delta->theirs) &&
		(error = merge_conflict_write_side(repo, their_head, delta, &delta->theirs, flags)) < 0)
		goto done;

done:
	if (error >= 0)
		*conflict_written = 1;

	return error;
}

int merge_conflict_write(int *out,
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

int merge_trees_normalize_opts(
	git_merge_trees_opts *opts,
	const git_merge_trees_opts *given);

static int merge_normalize_opts(
	git_merge_opts *opts,
	const git_merge_opts *given)
{
	int error = 0;
	unsigned int default_checkout_strategy = GIT_CHECKOUT_SAFE_CREATE |
		GIT_CHECKOUT_FORCE |
		GIT_CHECKOUT_REMOVE_UNTRACKED |
		GIT_CHECKOUT_ALLOW_CONFLICTS;

	if (given != NULL) {
		memcpy(opts, given, sizeof(git_merge_opts));

		if (!opts->checkout_opts.checkout_strategy)
			opts->checkout_opts.checkout_strategy = default_checkout_strategy;

		error = merge_trees_normalize_opts(&opts->merge_trees_opts, &given->merge_trees_opts);
	} else {
		git_merge_opts default_opts = GIT_MERGE_OPTS_INIT;
		memcpy(opts, &default_opts, sizeof(git_merge_opts));
		
		opts->checkout_opts.checkout_strategy = default_checkout_strategy;

		error = merge_trees_normalize_opts(&opts->merge_trees_opts, NULL);
	}

	return error;
}

static int merge_fake_head(git_merge_head **_head, git_tree **_tree, git_repository *repo)
{
	git_merge_head *head;
	git_tree *tree;
	
	head = git__calloc(1, sizeof(git_merge_head));
	GITERR_CHECK_ALLOC(head);

	tree = git__calloc(1, sizeof(git_tree));
	GITERR_CHECK_ALLOC(tree);
	
	git_atomic_inc(&tree->object.cached.refcount);
	tree->object.type = GIT_OBJ_TREE;
	tree->object.repo = repo;
	
	*_head = head;
	*_tree = tree;

	return 0;
}

static int merge_index(git_repository *repo, git_index *index_new)
{
	int error = 0;
	size_t i;
	git_index *index_repo = NULL;
	const git_index_entry *e;
	git_index_reuc_entry *reuc;

	if ((error = git_repository_index(&index_repo, repo)) < 0)
		return error;

	git_index_clear(index_repo);

	for (i = 0; i < git_index_entrycount(index_new); i++)
	{
		e = git_index_get_byindex(index_new, i);

		if ((error = git_index_add(index_repo, e)) < 0)
			goto on_error;
	}

	for (i = 0; i < git_index_reuc_entrycount(index_new); i++)
	{
		reuc = (git_index_reuc_entry *)git_index_reuc_get_byindex(index_new, i);

		if ((error = git_index_reuc_add(index_repo, reuc->path,
			reuc->mode[0], &reuc->oid[0],
			reuc->mode[1], &reuc->oid[1],
			reuc->mode[2], &reuc->oid[2])) < 0)
			goto on_error;
	}

on_error:
	git_index_free(index_repo);

	return error;
}

int merge_conflict_write(int *out,
	 git_repository *repo,
	 const git_merge_head *ancestor_head,
	 const git_merge_head *our_head,
	 const git_merge_head *their_head,
	 const git_diff_tree_delta *delta,
	 unsigned int flags);

int merge_trees(
	git_merge_result *result,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_trees_opts *opts);

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
	
	if (ancestor_head == NULL) {
		if ((error = merge_fake_head(&ancestor_head, &ancestor_tree, repo)) < 0)
			goto on_error;
	} else {
		if ((error = git_commit_tree(&ancestor_tree, ancestor_head->commit)) < 0)
			goto on_error;
	}

	if ((error = git_commit_tree(&our_tree, our_head->commit)) < 0)
		goto on_error;

	for (i = 0; i < their_heads_len; i++) {
		if ((error = git_commit_tree(&their_trees[i], their_heads[i]->commit)) < 0)
			goto on_error;
	}

	if ((error = git_index_new(&index_new)) < 0 ||
		(error = git_index_read_tree(index_new, our_tree)) < 0)
		goto on_error;

	/* TODO: recursive */
	if (their_heads_len == 1)
		error = merge_trees(result, repo, index_new, ancestor_tree, our_tree,
			their_trees[0], &opts.merge_trees_opts);
	else
		error = merge_trees_octopus(result, repo, index_new, ancestor_tree, our_tree,
			(const git_tree **)their_trees, their_heads_len, &opts.merge_trees_opts);
	
	if (error < 0)
		goto on_error;

	if ((error = merge_index(repo, index_new)) < 0 ||
		(error = git_repository_index(&index_repo, repo)) < 0 ||
		(error = git_checkout_index(repo, index_repo, &opts.checkout_opts)) < 0)
		goto on_error;

	if (their_heads_len == 1) {
		git_vector_foreach(&result->conflicts, i, delta) {
			int conflict_written = 0;
			
			if ((error = merge_conflict_write(&conflict_written, repo,
				ancestor_head, our_head, their_heads[0], delta, opts.conflict_flags)) < 0)
				goto on_error;
		}
	}
	
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
