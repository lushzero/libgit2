/*
 * Copyright (C) 2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "iterator.h"
#include "diff.h"
#include "diff_tree.h"

#include "git2/diff_tree.h"
#include "git2/oid.h"
#include "git2/config.h"

/**
 * Three-way tree differencing
 */

typedef enum {
	INDEX_ANCESTOR = 0,
	INDEX_OURS = 1,
	INDEX_THEIRS = 2
} diff_tree_threeway_index;

struct diff_tree_threeway_data {
	git_diff_tree_list *diff_tree;
	
	const char *df_path;
	const char *prev_path;
	git_diff_tree_delta *prev_delta_tree;
};

static git_diff_tree_list *diff_tree__list_alloc(git_repository *repo)
{
	git_diff_tree_list *diff_tree =
		git__calloc(1, sizeof(git_diff_tree_list));
	
	if (diff_tree == NULL)
		return NULL;
	
	diff_tree->repo = repo;
	
	if (git_vector_init(&diff_tree->deltas, 0, git_diff_delta__cmp) < 0 ||
		git_pool_init(&diff_tree->pool, 1, 0) < 0)
		return NULL;
	
	return diff_tree;
}

GIT_INLINE(const char *) diff_tree__path(const git_diff_tree_delta *delta_tree)
{
	if (GIT_DIFF_TREE_FILE_EXISTS(delta_tree->ancestor_file))
		return delta_tree->ancestor_file.path;
	else if (GIT_DIFF_TREE_FILE_EXISTS(delta_tree->our_file))
		return delta_tree->our_file.path;
	else if (GIT_DIFF_TREE_FILE_EXISTS(delta_tree->their_file))
		return delta_tree->their_file.path;
	
	return NULL;
}

GIT_INLINE(bool) diff_tree__delta_added_or_modified(
	const git_diff_tree_delta *delta_tree)
{
	if (delta_tree->our_status == GIT_DELTA_ADDED ||
		delta_tree->our_status == GIT_DELTA_MODIFIED ||
		delta_tree->their_status == GIT_DELTA_ADDED ||
		delta_tree->their_status == GIT_DELTA_MODIFIED)
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

GIT_INLINE(int) diff_tree__compute_df_conflict(
	struct diff_tree_threeway_data *threeway_data,
	git_diff_tree_delta *delta_tree)
{
	const char *cur_path = diff_tree__path(delta_tree);
	
	/* Determine if this is a D/F conflict or the child of one */
	if (threeway_data->df_path &&
		path_is_prefixed(threeway_data->df_path, cur_path))
		delta_tree->conflict = GIT_MERGE_CONFLICT_DF_CHILD;
	else if(threeway_data->df_path)
		threeway_data->df_path = NULL;
	else if (threeway_data->prev_path &&
		diff_tree__delta_added_or_modified(threeway_data->prev_delta_tree) &&
		diff_tree__delta_added_or_modified(delta_tree) &&
		path_is_prefixed(threeway_data->prev_path, cur_path)) {
		delta_tree->conflict = GIT_MERGE_CONFLICT_DF_CHILD;
		
		threeway_data->prev_delta_tree->conflict = GIT_MERGE_CONFLICT_DIRECTORY_FILE;
		threeway_data->df_path = threeway_data->prev_path;
	}

	threeway_data->prev_path = cur_path;
	threeway_data->prev_delta_tree = delta_tree;
	
	return 0;
}

GIT_INLINE(int) diff_tree__compute_conflict(
	git_diff_tree_delta *delta_tree)
{
	if (delta_tree->our_status == GIT_DELTA_ADDED &&
		delta_tree->their_status == GIT_DELTA_ADDED)
		delta_tree->conflict = GIT_MERGE_CONFLICT_BOTH_ADDED;
	else if (delta_tree->our_status == GIT_DELTA_MODIFIED &&
		delta_tree->their_status == GIT_DELTA_MODIFIED)
		delta_tree->conflict = GIT_MERGE_CONFLICT_BOTH_MODIFIED;
	else if (delta_tree->our_status == GIT_DELTA_DELETED &&
		delta_tree->their_status == GIT_DELTA_DELETED)
		delta_tree->conflict = GIT_MERGE_CONFLICT_BOTH_DELETED;
	else if (delta_tree->our_status == GIT_DELTA_MODIFIED &&
		delta_tree->their_status == GIT_DELTA_DELETED)
		delta_tree->conflict = GIT_MERGE_CONFLICT_MODIFIED_DELETED;
	else if (delta_tree->our_status == GIT_DELTA_DELETED &&
		delta_tree->their_status == GIT_DELTA_MODIFIED)
		delta_tree->conflict = GIT_MERGE_CONFLICT_MODIFIED_DELETED;
	else
		delta_tree->conflict = GIT_MERGE_CONFLICT_NONE;

	return 0;
}

GIT_INLINE(int) diff_file_from_index_entry(
	git_diff_file *out,
	git_pool *pool,
	const git_index_entry *index_entry)
{
	if (index_entry == NULL)
		return 0;

	if ((out->path = git_pool_strdup(pool, index_entry->path)) == NULL)
		return -1;

	git_oid_cpy(&out->oid, &index_entry->oid);
	out->size = index_entry->file_size;
	out->mode = index_entry->mode;
	out->flags |= GIT_DIFF_FILE_VALID_OID;

	return 0;
}

GIT_INLINE(int) diff_status_from_index_entries(
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

static git_diff_tree_delta *diff_tree__delta_from_entries(
	struct diff_tree_threeway_data *threeway_data,
	const git_index_entry **entries)
{
	git_diff_tree_delta *delta_tree;
	git_pool *pool = &threeway_data->diff_tree->pool;
	
	if ((delta_tree = git_pool_malloc(pool, sizeof(git_diff_tree_delta))) == NULL)
		return NULL;

	if (diff_file_from_index_entry(&delta_tree->ancestor_file, pool, entries[INDEX_ANCESTOR]) < 0 ||
		diff_file_from_index_entry(&delta_tree->our_file, pool, entries[INDEX_OURS]) < 0 ||
		diff_file_from_index_entry(&delta_tree->their_file, pool, entries[INDEX_THEIRS]) < 0)
		return NULL;

	delta_tree->our_status = diff_status_from_index_entries(entries[INDEX_ANCESTOR], entries[INDEX_OURS]);
	delta_tree->their_status = diff_status_from_index_entries(entries[INDEX_ANCESTOR], entries[INDEX_THEIRS]);

	return delta_tree;
}

static int diff_tree__create_delta(const git_index_entry **tree_items, void *payload)
{
	struct diff_tree_threeway_data *threeway_data = payload;
	git_diff_tree_delta *delta_tree;
	
	assert(tree_items && threeway_data);
	
	if ((delta_tree = diff_tree__delta_from_entries(threeway_data, tree_items)) == NULL ||
		diff_tree__compute_conflict(delta_tree) < 0 ||
		diff_tree__compute_df_conflict(threeway_data, delta_tree) < 0 ||
		git_vector_insert(&threeway_data->diff_tree->deltas, delta_tree) < 0)
		return -1;
	
	return 0;
}

struct diff_tree_similarity {
	unsigned char similarity;
	size_t other_idx;
};

static unsigned char diff_tree__similarity_exact(
	git_diff_file *a,
	git_diff_file *b)
{
	if (git_oid_cmp(&a->oid, &b->oid) == 0)
		return 100;

	return 0;
}

static void diff_tree__mark_similarity(
	git_diff_tree_list *diff_tree,
	struct diff_tree_similarity *similarity_ours,
	struct diff_tree_similarity *similarity_theirs,
	unsigned char (*similarity_fn)(git_diff_file *, git_diff_file *))
{
	size_t i, j;
	git_diff_tree_delta *delta_source, *delta_target;
	unsigned char similarity;
	
	git_vector_foreach(&diff_tree->deltas, i, delta_source) {
		/* Items can be the source of a rename iff they have an item in the
		 * ancestor slot and lack an item in the ours or theirs slot. */
		if (!GIT_DIFF_TREE_FILE_EXISTS(delta_source->ancestor_file) ||
			(GIT_DIFF_TREE_FILE_EXISTS(delta_source->our_file) &&
			 GIT_DIFF_TREE_FILE_EXISTS(delta_source->their_file)))
			continue;

		git_vector_foreach(&diff_tree->deltas, j, delta_target) {
			if (GIT_DIFF_TREE_FILE_EXISTS(delta_target->ancestor_file))
				continue;
			
			if (GIT_DIFF_TREE_FILE_EXISTS(delta_target->our_file)) {
				similarity = similarity_fn(&delta_source->ancestor_file, &delta_target->our_file);
	
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
			
			if (GIT_DIFF_TREE_FILE_EXISTS(delta_target->their_file)) {
				similarity = similarity_fn(&delta_source->ancestor_file, &delta_target->their_file);
				
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
static void diff_tree__mark_rename_conflict(
	git_diff_tree_list *diff_tree,
	struct diff_tree_similarity *similarity_ours,
	bool ours_renamed,
	size_t ours_source_idx,
	struct diff_tree_similarity *similarity_theirs,
	bool theirs_renamed,
	size_t theirs_source_idx,
	git_diff_tree_delta *target,
	const git_merge_tree_opts *opts)
{
	git_diff_tree_delta *ours_source = NULL;
	git_diff_tree_delta *theirs_source = NULL;

	if (ours_renamed)
		ours_source = diff_tree->deltas.contents[ours_source_idx];
	
	if (theirs_renamed)
		theirs_source = diff_tree->deltas.contents[theirs_source_idx];

	/* Detect 2->1 conflicts */
	if (ours_renamed && theirs_renamed) {
		/* Both renamed to the same target name. */
		if (ours_source_idx == theirs_source_idx)
			ours_source->conflict = GIT_MERGE_CONFLICT_BOTH_RENAMED;
		else {
			ours_source->conflict = GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1;
			theirs_source->conflict = GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1;
		}
	} else if (ours_renamed) {
		/* If our source was also renamed in theirs, this is a 1->2 */
		if (similarity_theirs[ours_source_idx].similarity >= opts->rename_threshold)
			ours_source->conflict = GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2;
		
		else if (GIT_DIFF_TREE_FILE_EXISTS(target->their_file)) {
			ours_source->conflict = GIT_MERGE_CONFLICT_RENAMED_ADDED;
			target->conflict = GIT_MERGE_CONFLICT_RENAMED_ADDED;
		}
		
		else if (!GIT_DIFF_TREE_FILE_EXISTS(ours_source->their_file))
			ours_source->conflict = GIT_MERGE_CONFLICT_RENAMED_DELETED;
		
		else if (ours_source->conflict == GIT_MERGE_CONFLICT_MODIFIED_DELETED)
			ours_source->conflict = GIT_MERGE_CONFLICT_RENAMED_MODIFIED;
	} else if (theirs_renamed) {
		/* If their source was also renamed in ours, this is a 1->2 */
		if (similarity_ours[theirs_source_idx].similarity >= opts->rename_threshold)
			theirs_source->conflict = GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2;
		
		else if (GIT_DIFF_TREE_FILE_EXISTS(target->our_file)) {
			theirs_source->conflict = GIT_MERGE_CONFLICT_RENAMED_ADDED;
			target->conflict = GIT_MERGE_CONFLICT_RENAMED_ADDED;
		}
		
		else if (!GIT_DIFF_TREE_FILE_EXISTS(theirs_source->our_file))
			theirs_source->conflict = GIT_MERGE_CONFLICT_RENAMED_DELETED;
		
		else if (theirs_source->conflict == GIT_MERGE_CONFLICT_MODIFIED_DELETED)
			theirs_source->conflict = GIT_MERGE_CONFLICT_RENAMED_MODIFIED;
	}
}

GIT_INLINE(void) diff_tree__coalesce_rename(
	git_diff_file *source_file,
	git_delta_t *source_status,
	git_diff_file *target_file,
	git_delta_t *target_status)
{
	/* Coalesce the rename target into the rename source. */
	memcpy(source_file, target_file, sizeof(git_diff_file));
	*source_status = GIT_DELTA_RENAMED;
	
	memset(target_file, 0x0, sizeof(git_diff_file));
	*target_status = GIT_DELTA_UNMODIFIED;
}

static void diff_tree__coalesce_renames(
	git_diff_tree_list *diff_tree,
	struct diff_tree_similarity *similarity_ours,
	struct diff_tree_similarity *similarity_theirs,
	const git_merge_tree_opts *opts)
{
	size_t i;
	bool ours_renamed = 0, theirs_renamed = 0;
	size_t ours_source_idx = 0, theirs_source_idx = 0;
	git_diff_tree_delta *ours_source, *theirs_source, *target;

	for (i = 0; i < diff_tree->deltas.length; i++) {		
		target = diff_tree->deltas.contents[i];
		
		ours_renamed = 0;
		theirs_renamed = 0;

		if (GIT_DIFF_TREE_FILE_EXISTS(target->our_file) &&
			similarity_ours[i].similarity >= opts->rename_threshold) {
			ours_source_idx = similarity_ours[i].other_idx;
			
			ours_source = diff_tree->deltas.contents[ours_source_idx];
			
			diff_tree__coalesce_rename(
				&ours_source->our_file,
				&ours_source->our_status,
				&target->our_file,
				&target->our_status);

			similarity_ours[ours_source_idx].similarity = 0;
			similarity_ours[i].similarity = 0;

			ours_renamed = 1;
		}
		
		/* insufficient to determine direction */
		if (GIT_DIFF_TREE_FILE_EXISTS(target->their_file) &&
			similarity_theirs[i].similarity >= opts->rename_threshold) {
			theirs_source_idx = similarity_theirs[i].other_idx;
			
			theirs_source = diff_tree->deltas.contents[theirs_source_idx];

			diff_tree__coalesce_rename(
				&theirs_source->their_file,
				&theirs_source->their_status,
				&target->their_file,
				&target->their_status);

			similarity_theirs[theirs_source_idx].similarity = 0;
			similarity_theirs[i].similarity = 0;

			theirs_renamed = 1;
		}
		
		diff_tree__mark_rename_conflict(diff_tree,
			similarity_ours, ours_renamed, ours_source_idx,
			similarity_theirs, theirs_renamed, theirs_source_idx,
			target, opts);
	}
}

static int diff_tree__is_empty(const git_vector *deltas, size_t idx)
{
	git_diff_tree_delta *delta = deltas->contents[idx];
	
	return (!GIT_DIFF_TREE_FILE_EXISTS(delta->ancestor_file) &&
		!GIT_DIFF_TREE_FILE_EXISTS(delta->our_file) &&
		!GIT_DIFF_TREE_FILE_EXISTS(delta->their_file));
}

static int diff_tree__find_renames(
	git_diff_tree_list *diff_tree,
	const git_merge_tree_opts *opts)
{
	struct diff_tree_similarity *similarity_ours, *similarity_theirs;
	int error = 0;

	assert(diff_tree && opts);

	if (!opts || (opts->flags & GIT_MERGE_TREE_FIND_RENAMES) == 0)
		return 0;

	similarity_ours = git__calloc(diff_tree->deltas.length, sizeof(struct diff_tree_similarity));
	GITERR_CHECK_ALLOC(similarity_ours);

	similarity_theirs = git__calloc(diff_tree->deltas.length, sizeof(struct diff_tree_similarity));
	GITERR_CHECK_ALLOC(similarity_theirs);

	/* Find exact renames (identical ids) */
	diff_tree__mark_similarity(diff_tree, similarity_ours, similarity_theirs,
		diff_tree__similarity_exact);
	
	diff_tree__coalesce_renames(diff_tree, similarity_ours, similarity_theirs, opts);

	git_vector_remove_matching(&diff_tree->deltas, diff_tree__is_empty);

	git__free(similarity_ours);
	git__free(similarity_theirs);

	return error;
}

GIT_INLINE(int) index_entry_cmp(const git_index_entry *a, const git_index_entry *b)
{
	int diff;
	
	assert (a && b);
	
	/* Ignore tree changes */
	if (S_ISDIR(a->mode) && S_ISDIR(b->mode))
		return 0;
	
	if ((diff = a->mode - b->mode) == 0)
		diff = git_oid_cmp(&a->oid, &b->oid);
	
	return diff;
}

static int diff_trees(
	git_repository *repo,
	const git_tree *trees[3],
	git_diff_tree_many_cb callback,
	void *payload)
{
	git_iterator *iterators[3] = {0};
	git_index_entry const *items[3] = {0}, *best_cur_item, *cur_items[3];
	git_vector_cmp entry_compare = git_index_entry__cmp;
	int cur_item_modified;
	size_t i;
	int error = 0;
	
	assert(repo && trees && callback);
	
	/* Set up the iterators */
	for (i = 0; i < 3; i++) {
		if ((error = git_iterator_for_tree(&iterators[i], (git_tree *)trees[i])) < 0 ||
			(error = git_iterator_current(iterators[i], &items[i])) < 0)
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
		
		if (cur_item_modified) {
			if (callback((const git_index_entry **)cur_items, payload)) {
				error = GIT_EUSER;
				goto done;
			}
		}
		
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

int git_diff_trees(git_diff_tree_list **out,
	git_repository *repo,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *opts)
{
	struct diff_tree_threeway_data threeway_data;
	git_diff_tree_list *diff_tree;
	git_tree const *trees[3];
	int error = 0;
	
	assert(out && repo && ancestor_tree && our_tree && their_tree && opts);
	
	*out = NULL;

	diff_tree = diff_tree__list_alloc(repo);
	GITERR_CHECK_ALLOC(diff_tree);
	
	memset(&threeway_data, 0x0, sizeof(struct diff_tree_threeway_data));
	threeway_data.diff_tree = diff_tree;
	
	trees[INDEX_ANCESTOR] = ancestor_tree;
	trees[INDEX_OURS] = our_tree;
	trees[INDEX_THEIRS] = their_tree;
	
	if ((error = diff_trees(repo, trees, diff_tree__create_delta, &threeway_data)) < 0 ||
		(error = diff_tree__find_renames(diff_tree, opts)) < 0)
		git_diff_tree_list_free(diff_tree);
	
	if (error >= 0)
		*out = diff_tree;

	return error;
}

int git_diff_tree_foreach(
	git_diff_tree_list *diff_tree,
	git_diff_tree_delta_cb callback,
	void *payload)
{
	git_diff_tree_delta *delta;
	size_t i;
	int error = 0;
	
	assert (diff_tree && callback);
	
	git_vector_foreach(&diff_tree->deltas, i, delta) {
		if (callback(delta, payload) != 0) {
			error = GIT_EUSER;
			break;
		}
	}
	
	return error;
}

void git_diff_tree_list_free(git_diff_tree_list *diff_tree)
{
	if (!diff_tree)
		return;
	
	git_vector_free(&diff_tree->deltas);
	git_pool_clear(&diff_tree->pool);
	git__free(diff_tree);
}
