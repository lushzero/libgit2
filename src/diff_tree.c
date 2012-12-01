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
 * n-way tree differencing
 */

static int index_entry_cmp(git_index_entry *a, git_index_entry *b)
{
	int diff;
	
	assert (a && b);
	
	if ((diff = a->mode - b->mode) == 0)
		diff = git_oid_cmp(&a->oid, &b->oid);
	
	return diff;
}

int git_diff_tree_many(
	git_repository *repo,
	git_tree **trees,
	size_t trees_length,
	uint32_t flags,
	git_diff_tree_many_cb callback,
	void *payload)
{
	git_iterator **iterators;
	git_index_entry **items = NULL, *best_next_item, **next_items;
	git_vector_cmp entry_compare = git_index_entry__cmp;
	int next_item_modified;
	size_t i;
	int error = 0;
	
	assert(repo && trees && callback);
	
	iterators = git__calloc(trees_length, sizeof(git_iterator *));
	GITERR_CHECK_ALLOC(iterators);
	
	items = git__calloc(trees_length, sizeof(git_index_entry *));
	GITERR_CHECK_ALLOC(items);
	
	next_items = git__calloc(trees_length, sizeof(git_index_entry *));
	GITERR_CHECK_ALLOC(next_items);
	
	for (i = 0; i < trees_length; i++) {
		if ((error = git_iterator_for_tree(&iterators[i], repo, trees[i])) < 0)
			return -1;
	}
	
	/* Set up the iterators */
	for (i = 0; i < trees_length; i++) {
		if ((error = git_iterator_current(iterators[i],
			(const git_index_entry **)&items[i])) < 0)
			goto done;
	}
	
	while (true) {
		memset(next_items, 0x0, sizeof(git_index_entry *) * trees_length);
		best_next_item = NULL;
		next_item_modified = 0;
		
		/* Find the next path(s) to consume from each iterator */
		for (i = 0; i < trees_length; i++) {
			if (items[i] == NULL) {
				next_item_modified = 1;
				continue;
			}
			
			if (best_next_item == NULL) {
				best_next_item = items[i];
				next_items[i] = items[i];
			} else {
				int diff = entry_compare(items[i], best_next_item);
				
				if (diff < 0) {
					/*
					 * Found an item that sorts before our current item, make
					 * our current item this one.
					 */
					memset(next_items, 0x0,
						sizeof(git_index_entry *) * trees_length);
					next_item_modified = 1;
					best_next_item = items[i];
					next_items[i] = items[i];
				} else if (diff > 0) {
					/* No entry for the current item, this is modified */
					next_item_modified = 1;
				} else if (diff == 0) {
					next_items[i] = items[i];
					
					if (!next_item_modified && !(flags & GIT_DIFF_TREE_RETURN_UNMODIFIED))
						next_item_modified = index_entry_cmp(best_next_item, items[i]);
				}
			}
		}
		
		if (best_next_item == NULL)
			break;
		
		if (next_item_modified || (flags & GIT_DIFF_TREE_RETURN_UNMODIFIED)) {
			if (callback((const git_index_entry **)next_items, payload)) {
				error = GIT_EUSER;
				goto done;
			}
		}
		
		/* Advance each iterator that participated */
		for (i = 0; i < trees_length; i++) {
			if (next_items[i] != NULL &&
				(error = git_iterator_advance(iterators[i],
				(const git_index_entry **)&items[i])) < 0)
				goto done;
		}
	}
	
done:
	for (i = 0; i < trees_length; i++)
		git_iterator_free(iterators[i]);
	
	git__free(iterators);
	git__free(items);
	git__free(next_items);
	
	return error;
}

/**
 * Three-way tree differencing
 */

typedef enum {
	INDEX_ANCESTOR = 0,
	INDEX_OURS = 1,
	INDEX_THEIRS = 2
} threeway_index;

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

static git_diff_tree_delta *diff_tree__delta_from_entries(
	git_diff_tree_list *diff_tree,
	const git_index_entry **entries)
{
	git_diff_tree_delta *delta_tree;
	git_diff_tree_entry *tree_entries[3];
	size_t i;
	
	if ((delta_tree = git_pool_malloc(&diff_tree->pool, sizeof(git_diff_tree_delta))) == NULL)
		return NULL;
	
	tree_entries[INDEX_ANCESTOR] = &delta_tree->ancestor;
	tree_entries[INDEX_OURS] = &delta_tree->ours;
	tree_entries[INDEX_THEIRS] = &delta_tree->theirs;
	
	for (i = 0; i < 3; i++) {
		if (entries[i] == NULL)
			continue;
		
		if ((tree_entries[i]->file.path = git_pool_strdup(&diff_tree->pool, entries[i]->path)) == NULL)
			return NULL;
		
		git_oid_cpy(&tree_entries[i]->file.oid, &entries[i]->oid);
		tree_entries[i]->file.size = entries[i]->file_size;
		tree_entries[i]->file.mode = entries[i]->mode;
		tree_entries[i]->file.flags |= GIT_DIFF_FILE_VALID_OID;
	}
	
	for (i = 1; i < 3; i++) {
		if (entries[INDEX_ANCESTOR] == NULL && entries[i] == NULL)
			continue;
		else if (entries[INDEX_ANCESTOR] == NULL && entries[i] != NULL)
			tree_entries[i]->status = GIT_DELTA_ADDED;
		else if (entries[INDEX_ANCESTOR] != NULL && entries[i] == NULL)
			tree_entries[i]->status = GIT_DELTA_DELETED;
		else if (S_ISDIR(entries[i]->mode) ^ S_ISDIR(entries[i]->mode) ||
			S_ISLNK(entries[i]->mode) ^ S_ISLNK(entries[i]->mode))
			tree_entries[i]->status = GIT_DELTA_TYPECHANGE;
		else if (git_oid_cmp(&entries[INDEX_ANCESTOR]->oid, &entries[i]->oid) ||
				 entries[INDEX_ANCESTOR]->mode != entries[i]->mode)
			tree_entries[i]->status = GIT_DELTA_MODIFIED;
	}
	
	return delta_tree;
}

static int diff_tree__create_delta(const git_index_entry **tree_items, void *payload)
{
	git_diff_tree_list *diff_tree = payload;
	git_diff_tree_delta *delta;
	
	assert(tree_items && diff_tree);
	
	if ((delta = diff_tree__delta_from_entries(diff_tree, tree_items)) == NULL ||
		git_vector_insert(&diff_tree->deltas, delta) < 0)
		return -1;
	
	return 0;
}

int git_diff_tree(git_diff_tree_list **out,
	git_repository *repo,
	git_tree *ancestor_tree,
	git_tree *our_tree,
	git_tree *their_tree,
	uint32_t flags)
{
	git_diff_tree_list *diff_tree;
	git_tree *trees[3];
	int error = 0;
	
	assert(out && repo && ancestor_tree && our_tree && their_tree);
	
	*out = NULL;
	
	diff_tree = diff_tree__list_alloc(repo);
	GITERR_CHECK_ALLOC(diff_tree);
	
	trees[INDEX_ANCESTOR] = ancestor_tree;
	trees[INDEX_OURS] = our_tree;
	trees[INDEX_THEIRS] = their_tree;
	
	if ((error = git_diff_tree_many(repo, trees, 3, flags, diff_tree__create_delta, diff_tree)) < 0) {
		git_diff_tree_list_free(diff_tree);
		return error;
	}
	
	*out = diff_tree;
	return 0;
}

int git_diff_tree_foreach(
	git_diff_tree_list *diff_tree,
	git_diff_tree_cb callback,
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
