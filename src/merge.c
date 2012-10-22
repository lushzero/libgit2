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
#include "diff.h"
#include "checkout.h"

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

int git_merge_inprogress(int *out, git_repository *repo)
{
	int error = 0;
	git_buf merge_head_path = GIT_BUF_INIT;

	assert(repo);

	if ((error = git_buf_joinpath(&merge_head_path, repo->path_repository, MERGE_HEAD_FILE)) == 0)
		*out = git_path_exists(merge_head_path.ptr);

	git_buf_free(&merge_head_path);
	return error;
}

static int write_orig_head(git_repository *repo, const git_commit *our_commit)
{
	git_filebuf orig_head_file = GIT_FILEBUF_INIT;
	git_buf orig_head_path = GIT_BUF_INIT;
	char orig_oid_str[GIT_OID_HEXSZ + 1];
	int error = 0;

	assert(repo && our_commit);

	git_oid_tostr(orig_oid_str, GIT_OID_HEXSZ+1, git_commit_id((git_commit *)our_commit));

	if ((error = git_buf_joinpath(&orig_head_path, repo->path_repository, ORIG_HEAD_FILE)) == 0 &&
		(error = git_filebuf_open(&orig_head_file, orig_head_path.ptr, GIT_FILEBUF_FORCE)) == 0 &&
		(error = git_filebuf_printf(&orig_head_file, "%s\n", orig_oid_str)) == 0)
		error = git_filebuf_commit(&orig_head_file, MERGE_CONFIG_FILE_MODE);

	if (error < 0)
		git_filebuf_cleanup(&orig_head_file);

	git_buf_free(&orig_head_path);

	return error;
}

static int write_merge_head(git_repository *repo, const git_commit *their_commits[], size_t their_commits_length)
{
	git_filebuf merge_head_file = GIT_FILEBUF_INIT;
	git_buf merge_head_path = GIT_BUF_INIT;
	char merge_oid_str[GIT_OID_HEXSZ + 1];
	size_t i;
	int error = 0;

	assert(repo && their_commits);

	if ((error = git_buf_joinpath(&merge_head_path, repo->path_repository, MERGE_HEAD_FILE)) < 0 ||
		(error = git_filebuf_open(&merge_head_file, merge_head_path.ptr, GIT_FILEBUF_FORCE)) < 0)
		goto cleanup;

	for (i = 0; i < their_commits_length; i++) {
		git_oid_tostr(merge_oid_str, GIT_OID_HEXSZ+1, git_commit_id((git_commit *)their_commits[i]));

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

	if ((error = git_buf_joinpath(&merge_mode_path, repo->path_repository, MERGE_MODE_FILE)) < 0 ||
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

/* TODO: we actually need to propogate ref names here to set merge_msg correctly. */
static int write_merge_msg(git_repository *repo, const git_commit *their_commits[], size_t their_commits_length)
{
	git_filebuf merge_msg_file = GIT_FILEBUF_INIT;
	git_buf merge_msg_path = GIT_BUF_INIT;
	char merge_oid_str[GIT_OID_HEXSZ + 1];
	size_t i;
	int error = 0;

	assert(repo && their_commits);

	if ((error = git_buf_joinpath(&merge_msg_path, repo->path_repository, MERGE_MSG_FILE)) < 0 ||
		(error = git_filebuf_open(&merge_msg_file, merge_msg_path.ptr, GIT_FILEBUF_FORCE)) < 0 ||
		(error = git_filebuf_write(&merge_msg_file, "Merge", 5)) < 0)
		goto cleanup;

	for (i = 0; i < their_commits_length; i++) {
		git_oid_tostr(merge_oid_str, GIT_OID_HEXSZ+1, git_commit_id((git_commit *)their_commits[i]));

		if ((error = git_filebuf_printf(&merge_msg_file, "%s commit '%s'", (i > 0) ? ";" : "", merge_oid_str)) < 0)
			goto cleanup;
	}

	if ((error = git_filebuf_printf(&merge_msg_file, "\n")) < 0 ||
		(error = git_filebuf_commit(&merge_msg_file, MERGE_CONFIG_FILE_MODE)) < 0)
		goto cleanup;

cleanup:
	if (error < 0)
		git_filebuf_cleanup(&merge_msg_file);

	git_buf_free(&merge_msg_path);

	return error;
}

static int merge_setup(
	git_repository *repo,
	const git_commit *our_commit,
	const git_commit *their_commits[],
	size_t their_commits_length,
	unsigned int flags)
{
	int error = 0;

	assert (repo && our_commit && their_commits);

	if ((error = write_orig_head(repo, our_commit)) == 0 &&
		(error = write_merge_head(repo, their_commits, their_commits_length)) == 0 &&
		(error = write_merge_mode(repo, flags)) == 0) {
		error = write_merge_msg(repo, their_commits, their_commits_length);
	}

	return error;
}

static int common_ancestor(
	git_commit **ancestor_commit,
	git_repository *repo,
	git_commit *our_commit,
	const git_commit *their_commits[],
	size_t their_commits_length)
{
	git_oid *oids, ancestor_oid;
	size_t i;

	assert(repo && our_commit && their_commits);

	if ((oids = git__calloc(their_commits_length + 1, sizeof(git_oid))) == NULL)
		return -1;

	git_oid_cpy(&oids[0], git_commit_id(our_commit));

	for (i = 0; i < their_commits_length; i++)
		git_oid_cpy(&oids[i + 1], git_commit_id((git_commit *)their_commits[i]));

	git_merge_base_many(&ancestor_oid, repo, oids, their_commits_length + 1);

	return git_object_lookup((git_object **)ancestor_commit, repo, &ancestor_oid, GIT_OBJ_COMMIT);
}

int git_merge(git_merge_result **out,
	git_repository *repo,
	const git_commit *their_commits[],
	size_t their_commits_length,
	int (*merge_strategy)(int *success, git_repository *repo, const git_commit *our_commit, const git_commit *ancestor_commit, const git_commit *their_commits[], size_t their_commits_length, void *data),
	unsigned int flags,
	void *strategy_data)
{
	git_merge_result *result;
	git_oid our_oid;
	git_commit *our_commit = NULL, *ancestor_commit = NULL;
	int strategy_success = 0;
	int error = 0;

	assert(out && repo && their_commits);

	*out = NULL;

	if(their_commits_length < 1) {
		giterr_set(GITERR_INVALID, "At least one commit must be merged.");
		return -1;
	}

	result = git__calloc(1, sizeof(git_merge_result));
	GITERR_CHECK_ALLOC(result);

	if ((error = git_reference_name_to_oid(&our_oid, repo, GIT_HEAD_FILE)) < 0 ||
		(error = git_object_lookup((git_object **)&our_commit, repo, &our_oid, GIT_OBJ_COMMIT)) < 0)
		goto cleanup;

	if ((error = common_ancestor(&ancestor_commit, repo, our_commit, their_commits, their_commits_length)) < 0)
		goto cleanup;

	/* Check for fast-forward. */
	if (their_commits_length == 1 && (flags & GIT_MERGE_NO_FASTFORWARD) == 0) {
		/* If we are our own best common ancestor, this is a fast-forward. */
		if (git_oid_cmp(git_commit_id(ancestor_commit), git_commit_id(our_commit)) == 0)
		{
			result->is_fastforward = 1;
			git_oid_cpy(&result->fastforward_oid, git_commit_id((git_commit *)their_commits[0]));

			goto cleanup;
		}
	}

	/* Set up the merge files */
	if ((error = merge_setup(repo, our_commit, their_commits, their_commits_length, flags)) < 0)
		goto cleanup;

	/* Determine the best strategy if one was not provided. */
	if (merge_strategy == NULL && their_commits_length == 1)
		merge_strategy = git_merge_strategy_resolve;
	else if (merge_strategy == NULL)
		merge_strategy = git_merge_strategy_octopus;

	if((error = (*merge_strategy)(&strategy_success, repo, our_commit, ancestor_commit, their_commits, their_commits_length, strategy_data)) < 0)
		goto cleanup;

cleanup:
	git_object_free((git_object *)our_commit);
	git_object_free((git_object *)ancestor_commit);

	if (error == 0)
	{
		*out = result;
	}
	else
	{
		free(result);
		*out = NULL;
	}

	return error;
}

static int merge_file_cmp(git_diff_file *a, git_diff_file *b)
{
	int value = 0;

	if ((value = a->size - b->size) == 0 &&
		(value = a->flags - b->flags) == 0 &&
		(value = a->mode - b->mode) == 0 &&
		(value = git_oid_cmp(&a->oid, &b->oid)) == 0 &&
		(value = ((a->path == NULL) ^ (b->path == NULL))) == 0)
		value = (a->path == NULL) ? 0 : strcmp(a->path, b->path);

	return value;
}

static int merge_file_apply(git_repository *repo, git_index *index, git_diff_file *file)
{
	git_checkout_opts opts;
	git_buf path = GIT_BUF_INIT;
	int error = 0;

	memset(&opts, 0x0, sizeof(git_checkout_opts));
	opts.checkout_strategy = GIT_CHECKOUT_DEFAULT;
	opts.dir_mode = GIT_DIR_MODE;
	opts.file_mode = file->mode;
	opts.file_open_flags = O_CREAT | O_TRUNC | O_WRONLY;

	if ((error = git_buf_joinpath(&path, git_repository_workdir(repo), file->path)) < 0)
		goto done;

	if (file->path == NULL && git_oid_iszero(&file->oid))
		error = p_unlink(path.ptr);
	else
		error = git_checkout_blob(repo, &file->oid, path.ptr, file->mode, true, &opts);

	if (!error)
		error = git_index_add(index, file->path, 1);

done:
	git_buf_free(&path);

	return error;
}

static int resolve_conflict_none(int *resolved, git_repository *repo, git_index *index, git_diff_many_delta *delta)
{
	assert (repo && index && delta);

	*resolved = 0;
	return 0;
}

static int resolve_conflict_ours(int *resolved, git_repository *repo, git_index *index, git_diff_many_delta *delta)
{
	assert (repo && index && delta);

	*resolved = 1;
	return merge_file_apply(repo, index, &delta->files[1]);
}

static int resolve_conflict_theirs(int *resolved, git_repository *repo, git_index *index, git_diff_many_delta *delta)
{
	assert (repo && index && delta);

	*resolved = 1;
	return merge_file_apply(repo, index, &delta->files[2]);
}

static int resolve_conflict_automerge(int *resolved, git_repository *repo, git_index *index, git_diff_many_delta *delta)
{
	assert (repo && index && delta);

	*resolved = 0;
	return 0;
}

int git_merge_strategy_resolve(
	int *out,
	git_repository *repo,
	const git_commit *our_commit,
	const git_commit *ancestor_commit,
	const git_commit *their_commits[],
	size_t their_commits_length,
	void *data)
{
	git_index *index = NULL;
	git_iterator *iterators[3] = { NULL, NULL, NULL };
	git_iterator *ancestor_iter = NULL, *our_iter = NULL, *their_iter = NULL;
	git_tree *ancestor_tree = NULL, *our_tree = NULL, *their_tree = NULL;
	git_diff_many_list *diff_many;
	git_diff_many_delta *delta;
	git_merge_strategy_resolve_options *options;
	int (*resolve_cb)(int *resolved, git_repository *repo, git_index *index,
		git_diff_many_delta *delta) = resolve_conflict_automerge;
	size_t i;
	int error = 0;

	assert(repo && our_commit && ancestor_commit && their_commits);

	options = (git_merge_strategy_resolve_options *)data;

	*out = 1;

	if (their_commits_length != 1)	{
		giterr_set(GITERR_INVALID, "Merge strategy: ours requires exactly one head.");
		return -1;
	}

	if (options != NULL &&
		options->resolver == GIT_MERGE_STRATEGY_RESOLVE_NONE)
		resolve_cb = resolve_conflict_none;
	else if (options != NULL &&
		options->resolver == GIT_MERGE_STRATEGY_RESOLVE_OURS)
		resolve_cb = resolve_conflict_ours;
	else if (options != NULL &&
		options->resolver == GIT_MERGE_STRATEGY_RESOLVE_THEIRS)
		resolve_cb = resolve_conflict_theirs;

	if ((error = git_repository_index(&index, repo)) < 0)
		goto done;

	if ((error = git_commit_tree(&ancestor_tree, (git_commit *)ancestor_commit)) < 0 ||
		(error = git_commit_tree(&our_tree, (git_commit *)our_commit)) < 0 ||
		(error = git_commit_tree(&their_tree, (git_commit *)their_commits[0])) < 0)
		goto done;

	if ((error = git_iterator_for_tree(&ancestor_iter, repo, ancestor_tree)) < 0 ||
		(error = git_iterator_for_tree(&our_iter, repo, our_tree)) < 0 ||
		(error = git_iterator_for_tree(&their_iter, repo, their_tree)) < 0)
		goto done;

	iterators[0] = ancestor_iter;
	iterators[1] = our_iter;
	iterators[2] = their_iter;

	git_diff_many_from_iterators(&diff_many, repo, iterators, 3);

	git_vector_foreach(&diff_many->deltas, i, delta) {
		int ours_changed, theirs_changed, resolved = 1;

		assert(delta->files);

		ours_changed = merge_file_cmp(&delta->files[0], &delta->files[1]);
		theirs_changed = merge_file_cmp(&delta->files[0], &delta->files[2]);

		assert (ours_changed || theirs_changed);

		if (ours_changed && theirs_changed) {
			if ((error = resolve_cb(&resolved, repo, index, delta)) < 0)
				goto done;

			if (! resolved)
				*out = 0;
		}
		else if (ours_changed) {
			if ((error = merge_file_apply(repo, index, &delta->files[1])) < 0)
				goto done;
		}
		else if (theirs_changed) {
			if ((error = merge_file_apply(repo, index, &delta->files[2])) < 0)
				goto done;
		}
	}

	git_index_write(index);

done:
	git_iterator_free(ancestor_iter);
	git_iterator_free(our_iter);
	git_iterator_free(their_iter);
	git_index_free(index);

	return error;
}

int git_merge_strategy_octopus(
	int *success,
	git_repository *repo,
	const git_commit *our_commit,
	const git_commit *ancestor_commit,
	const git_commit *their_commits[],
	size_t their_commits_length,
	void *data)
{
	assert(repo && our_commit && ancestor_commit && their_commits);

	if(their_commits_length < 2) {
		giterr_set(GITERR_INVALID, "Merge strategy: octopus requires at least two heads.");
		return -1;
	}

	*success = 1;

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

int git_merge_abort(git_repository *repo)
{
	int error = 0;
	int inprogress;
	git_oid head_oid;
	git_object *head_object = NULL;

	assert(repo);

	if ((error = git_merge_inprogress(&inprogress, repo)) < 0)
		goto cleanup;

	if (!inprogress)
	{
		error = -1;
		goto cleanup;
	}

	if ((error = git_reference_name_to_oid(&head_oid, repo, GIT_HEAD_FILE)) < 0)
		goto cleanup;

	if ((error = git_object_lookup(&head_object, repo, &head_oid, GIT_OBJ_COMMIT)) < 0)
		goto cleanup;

	if ((error = git_reset(repo, head_object, GIT_RESET_HARD)) < 0)
		goto cleanup;

cleanup:
	if (head_object != NULL)
		git_object_free(head_object);

	return error;
}

int merge_cleanup(git_repository *repo)
{
	int error = 0;
	git_buf merge_head_path = GIT_BUF_INIT,
		merge_mode_path = GIT_BUF_INIT,
		merge_msg_path = GIT_BUF_INIT;

	assert(repo);

	if ((error = git_buf_joinpath(&merge_head_path, repo->path_repository, MERGE_HEAD_FILE)) < 0)
		goto cleanup;

	if ((error = git_buf_joinpath(&merge_mode_path, repo->path_repository, MERGE_MODE_FILE)) < 0)
		goto cleanup;

	if ((error = git_buf_joinpath(&merge_msg_path, repo->path_repository, MERGE_MSG_FILE)) < 0)
		goto cleanup;

	if (git_path_exists(merge_head_path.ptr))
	{
		if ((error = p_unlink(merge_head_path.ptr)) < 0)
			goto cleanup;
	}

	if (git_path_exists(merge_mode_path.ptr))
		(void)p_unlink(merge_mode_path.ptr);

	if (git_path_exists(merge_msg_path.ptr))
		(void)p_unlink(merge_msg_path.ptr);

cleanup:
	git_buf_free(&merge_msg_path);
	git_buf_free(&merge_mode_path);
	git_buf_free(&merge_head_path);

	return error;
}
