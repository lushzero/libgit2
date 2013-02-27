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

#define GIT_MERGE_INDEX_ENTRY_EXISTS(X)	((X).mode != 0)

typedef enum {
	TREE_IDX_ANCESTOR = 0,
	TREE_IDX_OURS = 1,
	TREE_IDX_THEIRS = 2
} merge_tree_index_t;

/* Tracks D/F conflicts */
struct merge_index_df_data {
	const char *df_path;
	const char *prev_path;
	git_merge_index_conflict *prev_conflict;
};


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

static int merge_conflict_resolve_trivial(
	int *resolved,
	git_merge_index *merge_index,
	const git_merge_index_conflict *conflict)
{
	int ancestor_empty, ours_empty, theirs_empty;
	int ours_changed, theirs_changed, ours_theirs_differ;
	git_index_entry const *result = NULL;
	int error = 0;

	assert(resolved && merge_index && conflict);

	*resolved = 0;

	if (conflict->type == GIT_MERGE_CONFLICT_DIRECTORY_FILE ||
		conflict->type == GIT_MERGE_CONFLICT_RENAMED_ADDED)
		return 0;
	
	if (conflict->our_status == GIT_DELTA_RENAMED ||
		conflict->their_status == GIT_DELTA_RENAMED)
		return 0;

	ancestor_empty = !GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry);
	ours_empty = !GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry);
	theirs_empty = !GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry);
	
	ours_changed = (conflict->our_status != GIT_DELTA_UNMODIFIED);
	theirs_changed = (conflict->their_status != GIT_DELTA_UNMODIFIED);
	ours_theirs_differ = ours_changed && theirs_changed &&
		index_entry_cmp(&conflict->our_entry, &conflict->their_entry);

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
		result = &conflict->our_entry;
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
		result = &conflict->our_entry;
	/* 14: ancest:ancest+, head:ancest, remote:remote = result:remote */
	else if (!ours_changed && theirs_changed)
		result = &conflict->their_entry;
	else
		*resolved = 0;

	if (result != NULL &&
		GIT_MERGE_INDEX_ENTRY_EXISTS(*result) &&
		(error = git_vector_insert(&merge_index->staged, (void *)result)) >= 0)
		*resolved = 1;

	/* Note: trivial resolution does not update the REUC. */
	
	return error;
}

static int merge_conflict_resolve_one_removed(
	int *resolved,
	git_merge_index *merge_index,
	const git_merge_index_conflict *conflict)
{
	int ours_empty, theirs_empty;
	int ours_changed, theirs_changed;
	int error = 0;

	assert(resolved && merge_index && conflict);

	*resolved = 0;

	if (conflict->type == GIT_MERGE_CONFLICT_DIRECTORY_FILE)
		return 0;

	ours_empty = !GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry);
	theirs_empty = !GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry);

	ours_changed = (conflict->our_status != GIT_DELTA_UNMODIFIED);
	theirs_changed = (conflict->their_status != GIT_DELTA_UNMODIFIED);

	/* Removed in both */
	if (ours_changed && ours_empty && theirs_empty)
		*resolved = 1;
	/* Removed in ours */
	else if (ours_empty && !theirs_changed)
		*resolved = 1;
	/* Removed in theirs */
	else if (!ours_changed && theirs_empty)
		*resolved = 1;

	if (*resolved)
		git_vector_insert(&merge_index->resolved, (git_merge_index_conflict *)conflict);

	return error;
}


static int merge_conflict_resolve_one_renamed(
	int *resolved,
	git_merge_index *merge_index,
	const git_merge_index_conflict *conflict)
{
	int ours_renamed, theirs_renamed;
	int ours_changed, theirs_changed;
	git_index_entry *merged;
	int error = 0;
	
	assert(resolved && merge_index && conflict);
	
	*resolved = 0;

	if (!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) ||
		!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry))
		return 0;

	ours_renamed = (conflict->our_status == GIT_DELTA_RENAMED);
	theirs_renamed = (conflict->their_status == GIT_DELTA_RENAMED);
	
	if (!ours_renamed && !theirs_renamed)
		return 0;

	/* Reject one file in a 2->1 conflict */
	if (conflict->type == GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1 ||
		conflict->type == GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2)
		return 0;

	ours_changed = (git_oid_cmp(&conflict->ancestor_entry.oid, &conflict->our_entry.oid) != 0);
	theirs_changed = (git_oid_cmp(&conflict->ancestor_entry.oid, &conflict->their_entry.oid) != 0);
	
	/* if both are modified (and not to a common target) require a merge */
	if (ours_changed && theirs_changed &&
		git_oid_cmp(&conflict->our_entry.oid, &conflict->their_entry.oid) != 0)
		return 0;

	if ((merged = git_pool_malloc(&merge_index->pool, sizeof(git_index_entry))) == NULL)
		return -1;
	
	if (ours_changed)
		memcpy(merged, &conflict->our_entry, sizeof(git_index_entry));
	else
		memcpy(merged, &conflict->their_entry, sizeof(git_index_entry));

	if (ours_renamed)
		merged->path = conflict->our_entry.path;
	else
		merged->path = conflict->their_entry.path;
	
	*resolved = 1;
	
	git_vector_insert(&merge_index->staged, merged);
	git_vector_insert(&merge_index->resolved, (git_merge_index_conflict *)conflict);
	
	return error;
}

static int merge_conflict_resolve_automerge(
	int *resolved,
	git_merge_index *merge_index,
	const git_merge_index_conflict *conflict,
	unsigned int automerge_flags)
{
	git_merge_file_input ancestor = GIT_MERGE_FILE_INPUT_INIT,
		ours = GIT_MERGE_FILE_INPUT_INIT,
		theirs = GIT_MERGE_FILE_INPUT_INIT;
	git_merge_file_result result = GIT_MERGE_FILE_RESULT_INIT;
	git_index_entry *index_entry;
	git_odb *odb = NULL;
	git_oid automerge_oid;
	int error = 0;
	
	assert(resolved && merge_index && conflict);
	
	*resolved = 0;
	
	if (automerge_flags == GIT_MERGE_AUTOMERGE_NONE)
		return 0;

	/* Reject D/F conflicts */
	if (conflict->type == GIT_MERGE_CONFLICT_DIRECTORY_FILE)
		return 0;

	/* Reject link/file conflicts. */
	if ((S_ISLNK(conflict->ancestor_entry.mode) ^ S_ISLNK(conflict->our_entry.mode)) ||
		(S_ISLNK(conflict->ancestor_entry.mode) ^ S_ISLNK(conflict->their_entry.mode)))
		return 0;

	/* Reject name conflicts */
	if (conflict->type == GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1)
		return 0;

	if ((conflict->our_status & GIT_DELTA_RENAMED) == GIT_DELTA_RENAMED &&
		(conflict->their_status & GIT_DELTA_RENAMED) == GIT_DELTA_RENAMED &&
		strcmp(conflict->ancestor_entry.path, conflict->their_entry.path) != 0)
		return 0;

	if ((error = git_repository_odb(&odb, merge_index->repo)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&ancestor, merge_index->repo, &conflict->ancestor_entry)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&ours, merge_index->repo, &conflict->our_entry)) < 0 ||
		(error = git_merge_file_input_from_index_entry(&theirs, merge_index->repo, &conflict->their_entry)) < 0 ||
		(error = git_merge_files(&result, &ancestor, &ours, &theirs, automerge_flags)) < 0 ||
		!result.automergeable ||
		(error = git_odb_write(&automerge_oid, odb, result.data, result.len, GIT_OBJ_BLOB)) < 0)
		goto done;
	
	if ((index_entry = git_pool_malloc(&merge_index->pool, sizeof(git_index_entry))) == NULL)
	GITERR_CHECK_ALLOC(index_entry);

	index_entry->path = git_pool_strdup(&merge_index->pool, result.path);
	GITERR_CHECK_ALLOC(index_entry->path);

	index_entry->file_size = result.len;
	index_entry->mode = result.mode;
	git_oid_cpy(&index_entry->oid, &automerge_oid);
	
	git_vector_insert(&merge_index->staged, index_entry);
	git_vector_insert(&merge_index->resolved, (git_merge_index_conflict *)conflict);

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
	git_merge_index *merge_index,
	const git_merge_index_conflict *conflict,
	unsigned int automerge_flags)
{
	int resolved = 0;
	int error = 0;
	
	*out = 0;
	
	if ((error = merge_conflict_resolve_trivial(&resolved, merge_index, conflict)) < 0)
		goto done;

	if (automerge_flags != GIT_MERGE_AUTOMERGE_NONE) {
		if (!resolved && (error = merge_conflict_resolve_one_removed(&resolved, merge_index, conflict)) < 0)
			goto done;
		
		if (!resolved && (error = merge_conflict_resolve_one_renamed(&resolved, merge_index, conflict)) < 0)
			goto done;

		if (!resolved && (error = merge_conflict_resolve_automerge(&resolved, merge_index, conflict, automerge_flags)) < 0)
			goto done;
	}

	*out = resolved;
	
done:
	return error;
}

/* Rename detection and coalescing */

struct merge_index_similarity {
	unsigned char similarity;
	size_t other_idx;
};

static unsigned char index_entry_similarity_exact(
	git_index_entry *a,
	git_index_entry *b)
{
	if (git_oid_cmp(&a->oid, &b->oid) == 0)
		return 100;
	
	return 0;
}

static void merge_index_mark_similarity(
	git_merge_index *merge_index,
	struct merge_index_similarity *similarity_ours,
	struct merge_index_similarity *similarity_theirs,
	unsigned char (*similarity_fn)(git_index_entry *, git_index_entry *))
{
	size_t i, j;
	git_merge_index_conflict *conflict_src, *conflict_tgt;
	unsigned char similarity;
	
	git_vector_foreach(&merge_index->conflicts, i, conflict_src) {
		/* Items can be the source of a rename iff they have an item in the
		 * ancestor slot and lack an item in the ours or theirs slot. */
		if (!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict_src->ancestor_entry) ||
			(GIT_MERGE_INDEX_ENTRY_EXISTS(conflict_src->our_entry) &&
			 GIT_MERGE_INDEX_ENTRY_EXISTS(conflict_src->their_entry)))
			continue;
		
		git_vector_foreach(&merge_index->conflicts, j, conflict_tgt) {
			if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->ancestor_entry))
				continue;
			
			if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->our_entry)) {
				similarity = similarity_fn(&conflict_src->ancestor_entry, &conflict_tgt->our_entry);
				
				if (similarity > similarity_ours[i].similarity &&
					similarity > similarity_ours[j].similarity) {
					/* Clear previous best similarity */
					if (similarity_ours[i].similarity > 0)
						similarity_theirs[similarity_ours[i].other_idx].similarity = 0;
					
					if (similarity_ours[j].similarity > 0)
						similarity_theirs[similarity_ours[j].other_idx].similarity = 0;
					
					similarity_ours[i].similarity = similarity;
					similarity_ours[i].other_idx = j;
					
					similarity_ours[j].similarity = similarity;
					similarity_ours[j].other_idx = i;
				}
			}
			
			if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict_tgt->their_entry)) {
				similarity = similarity_fn(&conflict_src->ancestor_entry, &conflict_tgt->their_entry);
				
				if (similarity > similarity_theirs[i].similarity &&
					similarity > similarity_theirs[j].similarity) {
					/* Clear previous best similarity */
					if (similarity_theirs[i].similarity > 0)
						similarity_ours[similarity_theirs[i].other_idx].similarity = 0;
					
					if (similarity_theirs[j].similarity > 0)
						similarity_ours[similarity_theirs[j].other_idx].similarity = 0;
					
					similarity_theirs[i].similarity = similarity;
					similarity_theirs[i].other_idx = j;
					
					similarity_theirs[j].similarity = similarity;
					similarity_theirs[j].other_idx = i;
				}
			}
		}
	}
}

/*
 * Rename conflicts:
 *
 *      Ancestor   Ours   Theirs
 *
 * 0a   A          A      A        No rename
 *  b   A          A*     A        No rename (ours was rewritten)
 *  c   A          A      A*       No rename (theirs rewritten)
 * 1a   A          A      B[A]     Rename or rename/edit
 *  b   A          B[A]   A        (automergeable)
 * 2    A          B[A]   B[A]     Both renamed (automergeable)
 * 3a   A          B[A]            Rename/delete
 *  b   A                 B[A]      (same)
 * 4a   A          B[A]   B        Rename/add [B~ours B~theirs]
 *  b   A          B      B[A]      (same)
 * 5    A          B[A]   C[A]     Both renamed ("1 -> 2")
 * 6    A          C[A]            Both renamed ("2 -> 1")
 *      B                 C[B]     [C~ours C~theirs]    (automergeable)
 */
static void merge_index_mark_rename_conflict(
	git_merge_index *merge_index,
	struct merge_index_similarity *similarity_ours,
	bool ours_renamed,
	size_t ours_source_idx,
	struct merge_index_similarity *similarity_theirs,
	bool theirs_renamed,
	size_t theirs_source_idx,
	git_merge_index_conflict *target,
	const git_merge_tree_opts *opts)
{
	git_merge_index_conflict *ours_source = NULL;
	git_merge_index_conflict *theirs_source = NULL;
	
	if (ours_renamed)
		ours_source = merge_index->conflicts.contents[ours_source_idx];
	
	if (theirs_renamed)
		theirs_source = merge_index->conflicts.contents[theirs_source_idx];
	
	/* Detect 2->1 conflicts */
	if (ours_renamed && theirs_renamed) {
		/* Both renamed to the same target name. */
		if (ours_source_idx == theirs_source_idx)
			ours_source->type = GIT_MERGE_CONFLICT_BOTH_RENAMED;
		else {
			ours_source->type = GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1;
			theirs_source->type = GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1;
		}
	} else if (ours_renamed) {
		/* If our source was also renamed in theirs, this is a 1->2 */
		if (similarity_theirs[ours_source_idx].similarity >= opts->rename_threshold)
			ours_source->type = GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2;
		
		else if (GIT_MERGE_INDEX_ENTRY_EXISTS(target->their_entry)) {
			ours_source->type = GIT_MERGE_CONFLICT_RENAMED_ADDED;
			target->type = GIT_MERGE_CONFLICT_RENAMED_ADDED;
		}
		
		else if (!GIT_MERGE_INDEX_ENTRY_EXISTS(ours_source->their_entry))
			ours_source->type = GIT_MERGE_CONFLICT_RENAMED_DELETED;
		
		else if (ours_source->type == GIT_MERGE_CONFLICT_MODIFIED_DELETED)
			ours_source->type = GIT_MERGE_CONFLICT_RENAMED_MODIFIED;
	} else if (theirs_renamed) {
		/* If their source was also renamed in ours, this is a 1->2 */
		if (similarity_ours[theirs_source_idx].similarity >= opts->rename_threshold)
			theirs_source->type = GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2;
		
		else if (GIT_MERGE_INDEX_ENTRY_EXISTS(target->our_entry)) {
			theirs_source->type = GIT_MERGE_CONFLICT_RENAMED_ADDED;
			target->type = GIT_MERGE_CONFLICT_RENAMED_ADDED;
		}
		
		else if (!GIT_MERGE_INDEX_ENTRY_EXISTS(theirs_source->our_entry))
			theirs_source->type = GIT_MERGE_CONFLICT_RENAMED_DELETED;
		
		else if (theirs_source->type == GIT_MERGE_CONFLICT_MODIFIED_DELETED)
			theirs_source->type = GIT_MERGE_CONFLICT_RENAMED_MODIFIED;
	}
}

GIT_INLINE(void) merge_index_coalesce_rename(
	git_index_entry *source_entry,
	git_delta_t *source_status,
	git_index_entry *target_entry,
	git_delta_t *target_status)
{
	/* Coalesce the rename target into the rename source. */
	memcpy(source_entry, target_entry, sizeof(git_index_entry));
	*source_status = GIT_DELTA_RENAMED;
	
	memset(target_entry, 0x0, sizeof(git_index_entry));
	*target_status = GIT_DELTA_UNMODIFIED;
}

static void merge_index_coalesce_renames(
	git_merge_index *merge_index,
	struct merge_index_similarity *similarity_ours,
	struct merge_index_similarity *similarity_theirs,
	const git_merge_tree_opts *opts)
{
	size_t i;
	bool ours_renamed = 0, theirs_renamed = 0;
	size_t ours_source_idx = 0, theirs_source_idx = 0;
	git_merge_index_conflict *ours_source, *theirs_source, *target;
	
	for (i = 0; i < merge_index->conflicts.length; i++) {
		target = merge_index->conflicts.contents[i];
		
		ours_renamed = 0;
		theirs_renamed = 0;
		
		if (GIT_MERGE_INDEX_ENTRY_EXISTS(target->our_entry) &&
			similarity_ours[i].similarity >= opts->rename_threshold) {
			ours_source_idx = similarity_ours[i].other_idx;
			
			ours_source = merge_index->conflicts.contents[ours_source_idx];
			
			merge_index_coalesce_rename(
				&ours_source->our_entry,
				&ours_source->our_status,
				&target->our_entry,
				&target->our_status);
			
			similarity_ours[ours_source_idx].similarity = 0;
			similarity_ours[i].similarity = 0;
			
			ours_renamed = 1;
		}
		
		/* insufficient to determine direction */
		if (GIT_MERGE_INDEX_ENTRY_EXISTS(target->their_entry) &&
			similarity_theirs[i].similarity >= opts->rename_threshold) {
			theirs_source_idx = similarity_theirs[i].other_idx;
			
			theirs_source = merge_index->conflicts.contents[theirs_source_idx];
			
			merge_index_coalesce_rename(
				&theirs_source->their_entry,
				&theirs_source->their_status,
				&target->their_entry,
				&target->their_status);
			
			similarity_theirs[theirs_source_idx].similarity = 0;
			similarity_theirs[i].similarity = 0;
			
			theirs_renamed = 1;
		}
		
		merge_index_mark_rename_conflict(merge_index,
			similarity_ours, ours_renamed, ours_source_idx,
			similarity_theirs, theirs_renamed, theirs_source_idx,
			target, opts);
	}
}

static int merge_index_conflict_empty(const git_vector *conflicts, size_t idx)
{
	git_merge_index_conflict *conflict = conflicts->contents[idx];
	
	return (!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry) &&
		!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry) &&
		!GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry));
}

int git_merge_index__find_renames(
	git_merge_index *merge_index,
	const git_merge_tree_opts *opts)
{
	struct merge_index_similarity *similarity_ours, *similarity_theirs;
	int error = 0;
	
	assert(merge_index && opts);
	
	if ((opts->flags & GIT_MERGE_TREE_FIND_RENAMES) == 0)
		return 0;
	
	similarity_ours = git__calloc(merge_index->conflicts.length,
		sizeof(struct merge_index_similarity));
	GITERR_CHECK_ALLOC(similarity_ours);
	
	similarity_theirs = git__calloc(merge_index->conflicts.length,
		sizeof(struct merge_index_similarity));
	GITERR_CHECK_ALLOC(similarity_theirs);
	
	/* Calculate similarity between items that were deleted from the ancestor
	 * and added in the other branch.
	 */
	merge_index_mark_similarity(merge_index, similarity_ours, similarity_theirs,
		index_entry_similarity_exact);
	
	/* For entries that are appropriately similar, merge the new name's entry
	 * into the old name.
	 */
	merge_index_coalesce_renames(merge_index,
		similarity_ours, similarity_theirs, opts);
	
	/* And remove any entries that were merged and are now empty. */
	git_vector_remove_matching(&merge_index->conflicts,
		merge_index_conflict_empty);
	
	git__free(similarity_ours);
	git__free(similarity_theirs);
	
	return error;
}

/* Directory/file conflict handling */

GIT_INLINE(const char *) merge_index_conflict_path(
	const git_merge_index_conflict *conflict)
{
	if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->ancestor_entry))
		return conflict->ancestor_entry.path;
	else if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->our_entry))
		return conflict->our_entry.path;
	else if (GIT_MERGE_INDEX_ENTRY_EXISTS(conflict->their_entry))
		return conflict->their_entry.path;
	
	return NULL;
}

GIT_INLINE(bool) merge_index_conflict_added_or_modified(
	const git_merge_index_conflict *conflict)
{
	if (conflict->our_status == GIT_DELTA_ADDED ||
		conflict->our_status == GIT_DELTA_MODIFIED ||
		conflict->their_status == GIT_DELTA_ADDED ||
		conflict->their_status == GIT_DELTA_MODIFIED)
		return true;
	
	return false;
}

GIT_INLINE(bool) path_is_prefixed(const char *parent, const char *child)
{
	size_t child_len = strlen(child);
	size_t parent_len = strlen(parent);
	
	if (child_len < parent_len ||
		strncmp(parent, child, parent_len) != 0)
		return 0;
	
	return (child[parent_len] == '/');
}

GIT_INLINE(int) merge_index_conflict_detect_df(
	struct merge_index_df_data *df_data,
	git_merge_index_conflict *conflict)
{
	const char *cur_path = merge_index_conflict_path(conflict);
	
	/* Determine if this is a D/F conflict or the child of one */
	if (df_data->df_path &&
		path_is_prefixed(df_data->df_path, cur_path))
		conflict->type = GIT_MERGE_CONFLICT_DF_CHILD;
	else if(df_data->df_path)
		df_data->df_path = NULL;
	else if (df_data->prev_path &&
		merge_index_conflict_added_or_modified(df_data->prev_conflict) &&
		merge_index_conflict_added_or_modified(conflict) &&
		path_is_prefixed(df_data->prev_path, cur_path)) {
		conflict->type = GIT_MERGE_CONFLICT_DF_CHILD;
		
		df_data->prev_conflict->type = GIT_MERGE_CONFLICT_DIRECTORY_FILE;
		df_data->df_path = df_data->prev_path;
	}
	
	df_data->prev_path = cur_path;
	df_data->prev_conflict = conflict;
	
	return 0;
}

/* Conflict handling */

GIT_INLINE(int) merge_index_conflict_detect_type(
	git_merge_index_conflict *conflict)
{
	if (conflict->our_status == GIT_DELTA_ADDED &&
		conflict->their_status == GIT_DELTA_ADDED)
		conflict->type = GIT_MERGE_CONFLICT_BOTH_ADDED;
	else if (conflict->our_status == GIT_DELTA_MODIFIED &&
			 conflict->their_status == GIT_DELTA_MODIFIED)
		conflict->type = GIT_MERGE_CONFLICT_BOTH_MODIFIED;
	else if (conflict->our_status == GIT_DELTA_DELETED &&
			 conflict->their_status == GIT_DELTA_DELETED)
		conflict->type = GIT_MERGE_CONFLICT_BOTH_DELETED;
	else if (conflict->our_status == GIT_DELTA_MODIFIED &&
			 conflict->their_status == GIT_DELTA_DELETED)
		conflict->type = GIT_MERGE_CONFLICT_MODIFIED_DELETED;
	else if (conflict->our_status == GIT_DELTA_DELETED &&
			 conflict->their_status == GIT_DELTA_MODIFIED)
		conflict->type = GIT_MERGE_CONFLICT_MODIFIED_DELETED;
	else
		conflict->type = GIT_MERGE_CONFLICT_NONE;
	
	return 0;
}

GIT_INLINE(int) index_entry_dup(
	git_index_entry *out,
	git_pool *pool,
	const git_index_entry *src)
{
	if (src != NULL) {
		memcpy(out, src, sizeof(git_index_entry));
		
		if ((out->path = git_pool_strdup(pool, src->path)) == NULL)
			return -1;
	}
	
	return 0;
}

GIT_INLINE(int) merge_index_conflict_entry_status(
	const git_index_entry *ancestor,
	const git_index_entry *other)
{
	if (ancestor == NULL && other == NULL)
		return GIT_DELTA_UNMODIFIED;
	else if (ancestor == NULL && other != NULL)
		return GIT_DELTA_ADDED;
	else if (ancestor != NULL && other == NULL)
		return GIT_DELTA_DELETED;
	else if (S_ISDIR(ancestor->mode) ^ S_ISDIR(other->mode))
		return GIT_DELTA_TYPECHANGE;
	else if(S_ISLNK(ancestor->mode) ^ S_ISLNK(other->mode))
		return GIT_DELTA_TYPECHANGE;
	else if (git_oid_cmp(&ancestor->oid, &other->oid) ||
			 ancestor->mode != other->mode)
		return GIT_DELTA_MODIFIED;
	
	return GIT_DELTA_UNMODIFIED;
}

static git_merge_index_conflict *merge_index_conflict_from_entries(
	git_merge_index *merge_index,
	const git_index_entry **entries)
{
	git_merge_index_conflict *conflict;
	git_pool *pool = &merge_index->pool;
	
	if ((conflict = git_pool_malloc(pool, sizeof(git_merge_index_conflict))) == NULL)
		return NULL;
	
	if (index_entry_dup(&conflict->ancestor_entry, pool, entries[TREE_IDX_ANCESTOR]) < 0 ||
		index_entry_dup(&conflict->our_entry, pool, entries[TREE_IDX_OURS]) < 0 ||
		index_entry_dup(&conflict->their_entry, pool, entries[TREE_IDX_THEIRS]) < 0)
		return NULL;
	
	conflict->our_status = merge_index_conflict_entry_status(
		entries[TREE_IDX_ANCESTOR], entries[TREE_IDX_OURS]);
	conflict->their_status = merge_index_conflict_entry_status(
		entries[TREE_IDX_ANCESTOR], entries[TREE_IDX_THEIRS]);
	
	return conflict;
}

/* Merge trees */

static int merge_index_insert_conflict(
	git_merge_index *merge_index,
	struct merge_index_df_data *merge_df_data,
	const git_index_entry *tree_items[3])
{
	git_merge_index_conflict *merge_index_conflict;
	
	if ((merge_index_conflict = merge_index_conflict_from_entries(merge_index, tree_items)) == NULL ||
		merge_index_conflict_detect_type(merge_index_conflict) < 0 ||
		merge_index_conflict_detect_df(merge_df_data, merge_index_conflict) < 0 ||
		git_vector_insert(&merge_index->conflicts, merge_index_conflict) < 0)
		return -1;
	
	return 0;
}

static int merge_index_insert_unmodified(
	git_merge_index *merge_index,
	const git_index_entry *tree_items[3])
{
	int error = 0;
	git_index_entry *entry;
	
	entry = git_pool_malloc(&merge_index->pool, sizeof(git_index_entry));
	GITERR_CHECK_ALLOC(entry);
	
	if ((error = index_entry_dup(entry, &merge_index->pool, tree_items[0])) >= 0)
		error = git_vector_insert(&merge_index->staged, entry);
	
	return error;
}

int git_merge_index__find_differences(
	git_merge_index *merge_index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree)
{
	git_iterator *iterators[3] = {0};
	git_index_entry const *items[3] = {0}, *best_cur_item, *cur_items[3];
	git_vector_cmp entry_compare = git_index_entry__cmp;
	struct merge_index_df_data df_data = {0};
	int cur_item_modified;
	size_t i;
	int error = 0;
	
	assert(merge_index && our_tree && their_tree);
	
	if (ancestor_tree)
		error = git_iterator_for_tree(&iterators[TREE_IDX_ANCESTOR], (git_tree *)ancestor_tree);
	else
		error = git_iterator_for_nothing(&iterators[TREE_IDX_ANCESTOR], 0);
	
	if (error < 0)
		goto done;
	
	if ((error = git_iterator_for_tree(&iterators[TREE_IDX_OURS], (git_tree *)our_tree)) < 0 ||
		(error = git_iterator_for_tree(&iterators[TREE_IDX_THEIRS], (git_tree *)their_tree)) < 0)
		goto done;
	
	/* Set up the iterators */
	for (i = 0; i < 3; i++) {
		if ((error = git_iterator_current(iterators[i], &items[i])) < 0)
			goto done;
	}
	
	while (true) {
		memset(cur_items, 0x0, sizeof(git_index_entry *) * 3);
		best_cur_item = NULL;
		cur_item_modified = 0;
		
		/* Find the next path(s) to consume from each iterator */
		for (i = 0; i < 3; i++) {
			if (items[i] == NULL) {
				cur_item_modified = 1;
				continue;
			}
			
			if (best_cur_item == NULL) {
				best_cur_item = items[i];
				cur_items[i] = items[i];
			} else {
				int path_diff = entry_compare(items[i], best_cur_item);
				
				if (path_diff < 0) {
					/*
					 * Found an item that sorts before our current item, make
					 * our current item this one.
					 */
					memset(cur_items, 0x0, sizeof(git_index_entry *) * 3);
					cur_item_modified = 1;
					best_cur_item = items[i];
					cur_items[i] = items[i];
				} else if (path_diff > 0) {
					/* No entry for the current item, this is modified */
					cur_item_modified = 1;
				} else if (path_diff == 0) {
					cur_items[i] = items[i];
					
					if (!cur_item_modified)
						cur_item_modified = index_entry_cmp(best_cur_item, items[i]);
				}
			}
		}
		
		if (best_cur_item == NULL)
			break;
		
		if (cur_item_modified)
			error = merge_index_insert_conflict(merge_index, &df_data, cur_items);
		else
			error = merge_index_insert_unmodified(merge_index, cur_items);
		
		/* Advance each iterator that participated */
		for (i = 0; i < 3; i++) {
			if (cur_items[i] != NULL &&
				(error = git_iterator_advance(iterators[i], &items[i])) < 0)
				goto done;
		}
	}
	
done:
	for (i = 0; i < 3; i++)
		git_iterator_free(iterators[i]);
	
	return error;
}

git_merge_index *git_merge_index__alloc(git_repository *repo)
{
	git_merge_index *merge_index = git__calloc(1, sizeof(git_merge_index));
	
	if (merge_index == NULL)
		return NULL;
	
	merge_index->repo = repo;
	
	if (git_vector_init(&merge_index->staged, 0, NULL) < 0 ||
		git_vector_init(&merge_index->conflicts, 0, NULL) < 0 ||
		git_vector_init(&merge_index->resolved, 0, NULL) < 0 ||
		git_pool_init(&merge_index->pool, 1, 0) < 0)
		return NULL;
	
	return merge_index;
}

static int merge_tree_normalize_opts(
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
	git_merge_index **out,
	git_repository *repo,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *given_opts)
{
	git_merge_index *merge_index;
	git_merge_tree_opts opts;
	git_merge_index_conflict *conflict;
	git_vector changes;
	size_t i;
	int error = 0;

	assert(out && repo && our_tree && their_tree);

	*out = NULL;
	
	if ((error = merge_tree_normalize_opts(repo, &opts, given_opts)) < 0)
		return error;

	merge_index = git_merge_index__alloc(repo);
	GITERR_CHECK_ALLOC(merge_index);
	
	if ((error = git_merge_index__find_differences(merge_index, ancestor_tree, our_tree, their_tree)) < 0 ||
		(error = git_merge_index__find_renames(merge_index, &opts)) < 0)
		goto on_error;
	
	memcpy(&changes, &merge_index->conflicts, sizeof(git_vector));
	git_vector_clear(&merge_index->conflicts);
	
	git_vector_foreach(&changes, i, conflict) {
		int resolved = 0;
		
		if ((error = merge_conflict_resolve(&resolved, merge_index, conflict, opts.automerge_flags)) < 0)
			goto on_error;
		
		if (!resolved)
			git_vector_insert(&merge_index->conflicts, conflict);
	}
	
	*out = merge_index;
	return 0;
	
on_error:
	git_merge_index_free(merge_index);
	
	return error;
}

static int merge_index_insert_reuc(
	git_index *index,
	size_t idx,
	const git_index_entry *entry)
{
	const git_index_reuc_entry *reuc;
	int mode[3] = { 0, 0, 0 };
	git_oid const *oid[3] = { NULL, NULL, NULL };
	size_t i;

	if (!GIT_MERGE_INDEX_ENTRY_EXISTS(*entry))
		return 0;

	if ((reuc = git_index_reuc_get_bypath(index, entry->path)) != NULL) {
		for (i = 0; i < 3; i++) {
			mode[i] = reuc->mode[i];
			oid[i] = &reuc->oid[i];
		}
	}

	mode[idx] = entry->mode;
	oid[idx] = &entry->oid;

	return git_index_reuc_add(index, entry->path,
		mode[0], oid[0], mode[1], oid[1], mode[2], oid[2]);
}

static const git_index_entry *index_conflict_side(
	const git_merge_index_conflict *conflict,
	const git_index_entry *side)
{
	if (!GIT_MERGE_INDEX_ENTRY_EXISTS(*side))
		return NULL;
	
	/*
	 * Core git does not necessarily write all sides of a conflict.  This
	 * is for compatibility.
	 */
	
	/* 
	 * Only the common destination filename is written in a rename 2->1
	 * conflict.
	 */
	if (conflict->type == GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1) {
		if (side == &conflict->ancestor_entry)
			return NULL;
		
		if (side == &conflict->our_entry && conflict->our_status != GIT_DELTA_RENAMED)
			return NULL;
		
		if (side == &conflict->their_entry && conflict->their_status != GIT_DELTA_RENAMED)
			return NULL;
	}
	
	/*
	 * Only the destination filename is written in a rename/add conflict.
	 */
	if (conflict->type == GIT_MERGE_CONFLICT_RENAMED_ADDED) {
		if (side == &conflict->ancestor_entry)
			return NULL;

		if (side == &conflict->our_entry && conflict->our_status != GIT_DELTA_RENAMED)
			return NULL;
		
		if (side == &conflict->their_entry && conflict->their_status != GIT_DELTA_RENAMED)
			return NULL;
	}
	
	/* The ancestor is not written in a rename/delete conflict. */
	if (conflict->type == GIT_MERGE_CONFLICT_RENAMED_DELETED &&
		side == &conflict->ancestor_entry)
		return NULL;

	return side;
}

int git_index_from_merge_index(git_index **out, git_merge_index *merge_index)
{
	git_index *index;
	size_t i;
	git_index_entry *entry;
	git_merge_index_conflict *conflict;
	int error = 0;
	
	*out = NULL;
	
	if ((error = git_index_new(&index)) < 0)
		return error;
	
	git_vector_foreach(&merge_index->staged, i, entry) {
		if ((error = git_index_add(index, entry)) < 0)
			goto on_error;
	}
	
	git_vector_foreach(&merge_index->conflicts, i, conflict) {
		const git_index_entry *ancestor =
			index_conflict_side(conflict, &conflict->ancestor_entry);

		const git_index_entry *ours =
			index_conflict_side(conflict, &conflict->our_entry);

		const git_index_entry *theirs =
			index_conflict_side(conflict, &conflict->their_entry);

		if ((error = git_index_conflict_add(index, ancestor, ours, theirs)) < 0)
			goto on_error;
	}
	
	/* Add each entry in the resolved conflict to the REUC independently, since
	 * the paths may differ due to renames. */
	git_vector_foreach(&merge_index->resolved, i, conflict) {
		const git_index_entry *ancestor =
			index_conflict_side(conflict, &conflict->ancestor_entry);

		const git_index_entry *ours =
			index_conflict_side(conflict, &conflict->our_entry);

		const git_index_entry *theirs =
			index_conflict_side(conflict, &conflict->their_entry);

		if (ancestor != NULL &&
			(error = merge_index_insert_reuc(index, TREE_IDX_ANCESTOR, ancestor)) < 0)
				goto on_error;

		if (ours != NULL &&
			(error = merge_index_insert_reuc(index, TREE_IDX_OURS, ours)) < 0)
			goto on_error;

		if (theirs != NULL &&
			(error = merge_index_insert_reuc(index, TREE_IDX_THEIRS, theirs)) < 0)
			goto on_error;
	}
	
	*out = index;
	return 0;

on_error:
	git_index_free(index);

	return error;
}

int git_merge_index_has_conflicts(git_merge_index *merge_index)
{
	assert(merge_index);

	return (merge_index->conflicts.length > 0);
}

int git_merge_index_conflict_foreach(
	git_merge_index *merge_index,
	git_merge_conflict_foreach_cb conflict_cb,
	void *payload)
{
	git_merge_index_conflict *conflict;
	size_t i;
	int error = 0;
	
	assert(merge_index && conflict_cb);
	
	git_vector_foreach(&merge_index->conflicts, i, conflict) {
		if (conflict_cb(conflict->type,
			&conflict->ancestor_entry, &conflict->our_entry,
			&conflict->their_entry, payload) != 0) {
			error = GIT_EUSER;
			break;
		}
	}
	
	return error;
}

void git_merge_index_free(git_merge_index *merge_index)
{
	if (!merge_index)
		return;
	
	git_vector_free(&merge_index->staged);
	git_vector_free(&merge_index->conflicts);
	git_vector_free(&merge_index->resolved);
	git_pool_clear(&merge_index->pool);
	git__free(merge_index);
}
