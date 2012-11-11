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

static git_diff_tree_list *diff_tree_list_alloc(git_repository *repo)
{
    git_diff_tree_list *diff_tree = git__calloc(1, sizeof(git_diff_tree_list));
    
    if (diff_tree == NULL)
        return NULL;
    
    GIT_REFCOUNT_INC(diff_tree);
    diff_tree->repo = repo;
    
    if (git_vector_init(&diff_tree->deltas, 0, git_diff_delta__cmp) < 0 ||
        git_pool_init(&diff_tree->pool, 1, 0) < 0)
        return NULL;
    
    return diff_tree;
}

static git_diff_tree_delta *diff_tree_delta__from_entries(
	git_diff_tree_list *diff_tree,
	git_index_entry **entries,
	size_t entries_length)
{
	git_diff_tree_delta *delta_tree;
	size_t i;

	if ((delta_tree = git__calloc(1, sizeof(git_diff_tree_delta))) == NULL ||
		(delta_tree->files = git__calloc(entries_length, sizeof(git_diff_file))) == NULL)
        return NULL;

	for (i = 0; i < entries_length; i++) {
		if (entries[i] == NULL) {
			memset(&delta_tree->files[i], 0x0, sizeof(git_diff_file));
			continue;
		}

		if ((delta_tree->files[i].path = git_pool_strdup(&diff_tree->pool, entries[i]->path)) == NULL)
			return NULL;

		git_oid_cpy(&delta_tree->files[i].oid, &entries[i]->oid);
		delta_tree->files[i].size = entries[i]->file_size;
		delta_tree->files[i].mode = entries[i]->mode;
		delta_tree->files[i].flags |= GIT_DIFF_FILE_VALID_OID;
	}

    return delta_tree;
}

static int index_entry_cmp(git_index_entry *a, git_index_entry *b)
{
	int diff;

	assert (a && b);

	/*
	 * TODO: if this is constrained to git_index_entries from
	 * git_tree_iterators then we needn't even test all of these
	 * since many will be unset.
	 */
	if ((diff = a->ctime.seconds - b->ctime.seconds) == 0 &&
		(diff = a->ctime.nanoseconds - b->ctime.nanoseconds) == 0 &&
		(diff = a->mtime.seconds - b->mtime.seconds) == 0 &&
		(diff = a->mtime.nanoseconds - b->mtime.nanoseconds) == 0 &&
		(diff = a->dev - b->dev) == 0 &&
		(diff = a->ino - b->ino) == 0 &&
		(diff = a->mode - b->mode) == 0 &&
		(diff = a->uid - b->uid) == 0 &&
		(diff = a->gid - b->gid) == 0 &&
		(diff = a->file_size - b->file_size) == 0 &&
		(diff = a->flags - b->flags) == 0 &&
		(diff = a->flags_extended - b->flags_extended) == 0)
		diff = git_oid_cmp(&a->oid, &b->oid);

	return diff;
}

int git_diff_trees(
    git_diff_tree_list **out,
    git_repository *repo,
    git_tree **trees,
    size_t trees_length,
    const git_diff_tree_options *opts)
{
    git_iterator **iterators;
	git_index_entry **items = NULL, *best_next_item, **next_items;
	git_vector_cmp entry_compare = git_index_entry_cmp_case;
	git_diff_tree_list *diff_tree = diff_tree_list_alloc(repo);
	int next_item_modified;
    bool return_unmodified;
	size_t i;
	int error = 0;

	assert(out && repo && trees);

	*out = NULL;
    
    iterators = git__calloc(trees_length, sizeof(git_iterator *));
    GITERR_CHECK_ALLOC(iterators);

    items = git__calloc(trees_length, sizeof(git_index_entry *));
    GITERR_CHECK_ALLOC(items);

    next_items = git__calloc(trees_length, sizeof(git_index_entry *));
    GITERR_CHECK_ALLOC(next_items);
    
    return_unmodified = opts != NULL &&
        (opts->flags & GIT_DIFF_TREE_RETURN_UNMODIFIED) == GIT_DIFF_TREE_RETURN_UNMODIFIED;
    
	for (i = 0; i < trees_length; i++) {
        if ((error = git_iterator_for_tree(&iterators[i], repo, trees[i])) < 0)
            goto done;
    }

	/* Set up the iterators */
	for (i = 0; i < trees_length; i++) {
		if ((error = git_iterator_current(iterators[i], (const git_index_entry **)&items[i])) < 0)
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
					memset(next_items, 0x0, sizeof(git_index_entry *) * trees_length);
					next_item_modified = 1;
					best_next_item = items[i];
					next_items[i] = items[i];
                } else if (diff > 0) {
                    /* No entry for the current item, this is modified */
                    next_item_modified = 1;
                } else if (diff == 0) {
					next_items[i] = items[i];

					if (!next_item_modified && !return_unmodified)
						next_item_modified = index_entry_cmp(best_next_item, items[i]);
				}
			}
		}

		if (best_next_item == NULL)
			break;

		if (next_item_modified || return_unmodified) {
			git_diff_tree_delta *delta;

			if ((delta = diff_tree_delta__from_entries(diff_tree, next_items, trees_length)) == NULL ||
				(error = git_vector_insert(&diff_tree->deltas, delta)) < 0)
                goto done;
		}

		/* Advance each iterator that participated */
		for (i = 0; i < trees_length; i++) {
			if (next_items[i] != NULL &&
				(error = git_iterator_advance(iterators[i], (const git_index_entry **)&items[i])) < 0)
				goto done;
		}
	}

done:
    git__free(iterators);
	git__free(items);
	git__free(next_items);

	if (error >= 0)
		*out = diff_tree;

	return error;
}

int git_diff_trees_threeway(
    git_diff_tree_list **out,
    git_repository *repo,
    git_tree *ancestor_tree,
    git_tree *tree1,
    git_tree *tree2,
    const git_diff_tree_options *opts)
{
    git_tree *trees[3];
    git_diff_tree_list *diff_tree;
    int error;
    
    assert(out && repo && ancestor_tree && tree1 && tree2);

    trees[0] = ancestor_tree;
    trees[1] = tree1;
    trees[2] = tree2;

    if ((error = git_diff_trees(&diff_tree, repo, trees, 3, opts)) >= 0)
        *out = diff_tree;

    return error;
}

