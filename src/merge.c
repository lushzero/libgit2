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
#include "git2/tree.h"

int git_repository_merge_cleanup(git_repository *repo)
{
	int error = 0;
	git_buf merge_head_path = GIT_BUF_INIT,
		merge_mode_path = GIT_BUF_INIT,
		merge_msg_path = GIT_BUF_INIT;

	assert(repo);

	if (git_buf_joinpath(&merge_head_path, repo->path_repository, GIT_MERGE_HEAD_FILE) < 0 ||
		git_buf_joinpath(&merge_mode_path, repo->path_repository, GIT_MERGE_MODE_FILE) < 0 ||
		git_buf_joinpath(&merge_msg_path, repo->path_repository, GIT_MERGE_MSG_FILE) < 0)
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

int git_repository_mergehead_foreach(git_repository *repo,
	git_repository_mergehead_foreach_cb cb,
	void *payload)
{
	git_buf merge_head_path = GIT_BUF_INIT, merge_head_file = GIT_BUF_INIT;
	char *buffer, *line;
	size_t line_num = 1;
	git_oid oid;
	int error = 0;

	assert(repo && cb);

	if ((error = git_buf_joinpath(&merge_head_path, repo->path_repository,
		GIT_MERGE_HEAD_FILE)) < 0)
		return error;

	if ((error = git_futils_readbuffer(&merge_head_file,
		git_buf_cstr(&merge_head_path))) < 0)
		goto cleanup;

	buffer = merge_head_file.ptr;

	while ((line = git__strsep(&buffer, "\n")) != NULL) {
		if (strlen(line) != GIT_OID_HEXSZ) {
			giterr_set(GITERR_INVALID, "Unable to parse OID - invalid length");
			error = -1;
			goto cleanup;
		}

		if ((error = git_oid_fromstr(&oid, line)) < 0)
			goto cleanup;

		if (cb(&oid, payload) < 0) {
			error = GIT_EUSER;
			goto cleanup;
		}

		++line_num;
	}

	if (*buffer) {
		giterr_set(GITERR_MERGE, "No EOL at line %d", line_num);
		error = -1;
		goto cleanup;
	}

cleanup:
	git_buf_free(&merge_head_path);
	git_buf_free(&merge_head_file);

	return error;
}

GIT_INLINE(int) index_entry_cmp(const git_index_entry *a, const git_index_entry *b)
{
	int value = 0;

	if (a->path == NULL)
		return (b->path == NULL) ? 0 : 1;

	if ((value = a->mode - b->mode) == 0 &&
		(value = git_oid_cmp(&a->oid, &b->oid)) == 0)
		value = strcmp(a->path, b->path);

	return value;
}

/* Conflict resolution */

static int merge_file_index_remove(git_index *index, const git_merge_index_conflict *delta)
{
	if (!GIT_DIFF_TREE_FILE_EXISTS(delta->our_entry))
		return 0;

	return git_index_remove(index, delta->our_entry.path, 0);
}

static int merge_file_apply(git_index *index,
	const git_merge_index_conflict *delta,
	const git_index_entry *entry)
{
	int error = 0;
	
	assert (index && entry);
	
	if (!GIT_DIFF_TREE_FILE_EXISTS(*entry))
		error = merge_file_index_remove(index, delta);
	else
		error = git_index_add(index, entry);
	
	return error;
}

static int merge_mark_conflict_resolved(git_index *index, const git_merge_index_conflict *delta)
{
	const char *path;
	assert(index && delta);
	
	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor_entry))
		path = delta->ancestor_entry.path;
	else if (GIT_DIFF_TREE_FILE_EXISTS(delta->our_entry))
		path = delta->our_entry.path;
	else if (GIT_DIFF_TREE_FILE_EXISTS(delta->their_entry))
		path = delta->their_entry.path;
	else {
		giterr_set(GITERR_INVALID, "Given delta is not a conflict");
		return -1;
	}
	
	return git_index_reuc_add(index, path,
		delta->ancestor_entry.mode, &delta->ancestor_entry.oid,
		delta->our_entry.mode, &delta->our_entry.oid,
		delta->their_entry.mode, &delta->their_entry.oid);
}

static int merge_mark_conflict_unresolved(git_index *index, const git_merge_index_conflict *delta)
{
	bool ancestor_exists = 0, ours_exists = 0, theirs_exists = 0;
	git_index_entry ancestor_entry, our_entry, their_entry;
	int error = 0;

	assert(index && delta);
	
	if ((ancestor_exists = GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor_entry))) {
		memset(&ancestor_entry, 0x0, sizeof(git_index_entry));
		ancestor_entry.path = (char *)delta->ancestor_entry.path;
		ancestor_entry.mode = delta->ancestor_entry.mode;
		git_oid_cpy(&ancestor_entry.oid, &delta->ancestor_entry.oid);
	}
	
	if ((ours_exists = GIT_DIFF_TREE_FILE_EXISTS(delta->our_entry))) {
		memset(&our_entry, 0x0, sizeof(git_index_entry));
		our_entry.path = (char *)delta->our_entry.path;
		our_entry.mode = delta->our_entry.mode;
		git_oid_cpy(&our_entry.oid, &delta->our_entry.oid);
	}
	
	if ((theirs_exists = GIT_DIFF_TREE_FILE_EXISTS(delta->their_entry))) {
		memset(&their_entry, 0x0, sizeof(git_index_entry));
		their_entry.path = (char *)delta->their_entry.path;
		their_entry.mode = delta->their_entry.mode;
		git_oid_cpy(&their_entry.oid, &delta->their_entry.oid);
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
	const git_merge_index_conflict *delta)
{
	int ancestor_empty, ours_empty, theirs_empty;
	int ours_changed, theirs_changed, ours_theirs_differ;
	git_index_entry const *result = NULL;
	int error = 0;

	assert(resolved && repo && index && delta);

	*resolved = 0;

	if (delta->conflict == GIT_MERGE_CONFLICT_DIRECTORY_FILE)
		return 0;

	ancestor_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor_entry);
	ours_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->our_entry);
	theirs_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->their_entry);
	
	ours_changed = (delta->our_status != GIT_DELTA_UNMODIFIED);
	theirs_changed = (delta->their_status != GIT_DELTA_UNMODIFIED);
	ours_theirs_differ = ours_changed && theirs_changed &&
		index_entry_cmp(&delta->our_entry, &delta->their_entry);

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
		result = &delta->our_entry;
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
		result = &delta->our_entry;
	/* 14: ancest:ancest+, head:ancest, remote:remote = result:remote */
	else if (!ours_changed && theirs_changed)
		result = &delta->their_entry;
	else
		*resolved = 0;

	if (result != NULL && (error = merge_file_apply(index, delta, result)) >= 0)
		*resolved = 1;

	/* Note: trivial resolution does not update the REUC. */
	
	return error;
}

static int merge_conflict_resolve_one_removed(
	int *resolved,
	git_repository *repo,
	git_index *index,
	const git_merge_index_conflict *delta)
{
	int ours_empty, theirs_empty;
	int ours_changed, theirs_changed;
	git_index_entry const *result = NULL;
	int error = 0;

	assert(resolved && repo && index && delta);

	*resolved = 0;

	if (delta->conflict == GIT_MERGE_CONFLICT_DIRECTORY_FILE)
		return 0;

	ours_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->our_entry);
	theirs_empty = !GIT_DIFF_TREE_FILE_EXISTS(delta->their_entry);

	ours_changed = (delta->our_status != GIT_DELTA_UNMODIFIED);
	theirs_changed = (delta->their_status != GIT_DELTA_UNMODIFIED);

	/* Handle some cases that are not "trivial" but are, well, trivial. */

	/* Removed in both */
	if (ours_changed && ours_empty && theirs_empty)
		result = &delta->our_entry;
	/* Removed in ours */
	else if (ours_empty && !theirs_changed)
		result = &delta->our_entry;
	/* Removed in theirs */
	else if (!ours_changed && theirs_empty)
		result = &delta->their_entry;

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
	const git_merge_index_conflict *delta,
	unsigned int automerge_flags)
{
	git_merge_file_input ancestor = GIT_MERGE_FILE_INPUT_INIT,
		ours = GIT_MERGE_FILE_INPUT_INIT,
		theirs = GIT_MERGE_FILE_INPUT_INIT;
	git_merge_file_result result = GIT_MERGE_FILE_RESULT_INIT;
	git_index_entry index_entry;
	git_odb *odb = NULL;
	git_oid automerge_oid;
	int error = 0;
	
	assert(resolved && repo && index && delta);
	
	*resolved = 0;
	
	if (automerge_flags == GIT_MERGE_AUTOMERGE_NONE)
		return 0;

	/* Reject D/F conflicts */
	if (delta->conflict == GIT_MERGE_CONFLICT_DIRECTORY_FILE)
		return 0;

	/* Reject link/file conflicts. */
	if ((S_ISLNK(delta->ancestor_entry.mode) ^ S_ISLNK(delta->our_entry.mode)) ||
		(S_ISLNK(delta->ancestor_entry.mode) ^ S_ISLNK(delta->their_entry.mode)))
		return 0;

	/* Reject name conflicts */
	if (GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor_entry) &&
		((GIT_DIFF_TREE_FILE_EXISTS(delta->our_entry) &&
		strcmp(delta->ancestor_entry.path, delta->our_entry.path) != 0) ||
		(GIT_DIFF_TREE_FILE_EXISTS(delta->their_entry) &&
		strcmp(delta->ancestor_entry.path, delta->their_entry.path) != 0)))
		return 0;

	if ((error = git_repository_odb(&odb, repo)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&ancestor, repo, &delta->ancestor_entry)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&ours, repo, &delta->our_entry)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&theirs, repo, &delta->their_entry)) < 0 ||
		(error = git_merge_files(&result, &ancestor, &ours, &theirs, automerge_flags)) < 0 ||
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
	git_merge_file_input_free(&ancestor);
	git_merge_file_input_free(&ours);
	git_merge_file_input_free(&theirs);
	git_merge_file_result_free(&result);
	git_odb_free(odb);
	
	return error;
}

static int merge_conflict_resolve(
	int *out,
	git_repository *repo,
	git_index *index,
	const git_merge_index_conflict *delta,
	unsigned int automerge_flags)
{
	int resolved = 0;
	int error = 0;
	
	*out = 0;
	
	if ((error = merge_conflict_resolve_trivial(&resolved, repo, index, delta)) < 0)
		goto done;

	if (automerge_flags != GIT_MERGE_AUTOMERGE_NONE) {
		if (!resolved && (error = merge_conflict_resolve_one_removed(&resolved, repo, index, delta)) < 0)
			goto done;

		if (!resolved && (error = merge_conflict_resolve_automerge(&resolved, repo, index, delta, automerge_flags)) < 0)
			goto done;
	}

	if (!resolved)
		error = merge_mark_conflict_unresolved(index, delta);
	
	*out = resolved;
	
done:
	return error;
}

/* Merge trees */

/* TODO: staticify */
int merge_trees(
	struct git_merge_tree_result *result,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *opts)
{
	git_merge_index_conflict *delta;
	size_t i;
	int error = 0;

	if ((error = git_diff_trees(&result->diff_tree, repo, ancestor_tree, our_tree, their_tree, opts)) < 0)
		return error;
	
	git_vector_foreach(&result->diff_tree->deltas, i, delta) {
		int resolved = 0;
		
		if ((error = merge_conflict_resolve(&resolved, repo, index, delta, opts->automerge_flags)) < 0)
			return error;
		
		if (!resolved)
			git_vector_insert(&result->conflicts, delta);
	}

	return 0;
}

/* TODO: staticify */
int merge_tree_normalize_opts(
	git_repository *repo,
	git_merge_tree_opts *opts,
	const git_merge_tree_opts *given)
{
	git_config *cfg = NULL;
	int error = 0;
	
	assert(repo && opts);
	
	if ((error = git_repository_config__weakptr(&cfg, repo)) < 0)
		return error;
	
	if (given != NULL)
		memcpy(opts, given, sizeof(git_merge_tree_opts));
	else {
		git_merge_tree_opts init = GIT_MERGE_TREE_OPTS_INIT;
		memcpy(opts, &init, sizeof(init));
		
		opts->flags = GIT_MERGE_TREE_FIND_RENAMES;
		opts->rename_threshold = GIT_MERGE_TREE_RENAME_THRESHOLD;
	}
	
	if (!opts->target_limit) {
		int32_t limit = 0;
		
		opts->target_limit = GIT_MERGE_TREE_TARGET_LIMIT;
		
		if (git_config_get_int32(&limit, cfg, "merge.renameLimit") < 0) {
			giterr_clear();
			
			if (git_config_get_int32(&limit, cfg, "diff.renameLimit") < 0)
				giterr_clear();
		}
		
		if (limit > 0)
			opts->target_limit = limit;
	}
	
	return 0;
}

int git_merge_trees(
	struct git_merge_tree_result **out,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *given_opts)
{
	git_merge_tree_opts opts;
	struct git_merge_tree_result *result;
	int error = 0;

	assert(out && repo && index && ancestor_tree && our_tree && their_tree);
	
	*out = NULL;
	
	if ((error = merge_tree_normalize_opts(repo, &opts, given_opts)) < 0)
		return error;
	
	result = git__calloc(1, sizeof(struct git_merge_tree_result));
	GITERR_CHECK_ALLOC(result);
	
	if ((error = merge_trees(result, repo, index, ancestor_tree, our_tree, their_tree, &opts)) >= 0)
		*out = result;
	else
		git__free(result);
	
	return error;
}

void git_merge_tree_result_free(struct git_merge_tree_result *merge_tree_result)
{
	if (merge_tree_result == NULL)
		return;
	
	git_vector_free(&merge_tree_result->conflicts);
	
	git_merge_index_free(merge_tree_result->diff_tree);
	merge_tree_result->diff_tree = NULL;
	
	git__free(merge_tree_result);
}
