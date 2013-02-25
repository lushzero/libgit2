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

#include "git2/oid.h"
#include "git2/config.h"

/**
 * Three-way tree differencing
 */

typedef enum {
	TREE_IDX_ANCESTOR = 0,
	TREE_IDX_OURS = 1,
	TREE_IDX_THEIRS = 2
} merge_tree_index_t;

/* Tracks D/F conflicts */
struct merge_index_df_data {
	git_merge_index *merge_index;
	
	const char *df_path;
	const char *prev_path;
	git_merge_index_conflict *prev_conflict;
};

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
	git_merge_index_conflict *delta_tree;
	git_pool *pool = &merge_index->pool;
	
	if ((delta_tree = git_pool_malloc(pool, sizeof(git_merge_index_conflict))) == NULL)
		return NULL;

	if (index_entry_dup(&delta_tree->ancestor_entry, pool, entries[TREE_IDX_ANCESTOR]) < 0 ||
		index_entry_dup(&delta_tree->our_entry, pool, entries[TREE_IDX_OURS]) < 0 ||
		index_entry_dup(&delta_tree->their_entry, pool, entries[TREE_IDX_THEIRS]) < 0)
		return NULL;

	delta_tree->our_status = merge_index_conflict_entry_status(
		entries[TREE_IDX_ANCESTOR], entries[TREE_IDX_OURS]);
	delta_tree->their_status = merge_index_conflict_entry_status(
		entries[TREE_IDX_ANCESTOR], entries[TREE_IDX_THEIRS]);

	return delta_tree;
}

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

static int merge_index_find_renames(
	git_merge_index *merge_index,
	const git_merge_tree_opts *opts)
{
	struct merge_index_similarity *similarity_ours, *similarity_theirs;
	int error = 0;

	assert(merge_index && opts);

	if (!opts || (opts->flags & GIT_MERGE_TREE_FIND_RENAMES) == 0)
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
	
	assert(merge_index && ancestor_tree && our_tree && their_tree);

	if ((error = git_iterator_for_tree(&iterators[TREE_IDX_ANCESTOR], (git_tree *)ancestor_tree)) < 0 ||
		(error = git_iterator_for_tree(&iterators[TREE_IDX_OURS], (git_tree *)our_tree)) < 0 ||
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

int git_diff_trees(
	git_merge_index *merge_index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *opts)
{
	int error = 0;
	
	assert(merge_index && ancestor_tree && our_tree && their_tree && opts);
	
	if ((error = diff_trees(merge_index, ancestor_tree, our_tree, their_tree)) >= 0)
		error = merge_index_find_renames(merge_index, opts);

	return error;
}

void git_merge_index_free(git_merge_index *merge_index)
{
	if (!merge_index)
		return;
	
	git_vector_free(&merge_index->conflicts);
	git_pool_clear(&merge_index->pool);
	git__free(merge_index);
}
