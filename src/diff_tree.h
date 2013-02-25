/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_tree_h__
#define INCLUDE_diff_tree_h__

#include "repository.h"
#include "pool.h"
#include "vector.h"

#include "git2/diff.h"
#include "git2/merge.h"

#define GIT_MERGE_INDEX_ENTRY_EXISTS(X)	((X).mode != 0)

struct git_merge_index {
	git_repository *repo;
	git_pool pool;

	/* Vector of git_index_entry */
	git_vector staged;

	/* Vector of git_merge_index_conflict */
	git_vector conflicts;

	/* Vector of git_merge_index_conflict */
	git_vector resolved;
};

/**
 * Description of changes to one file across three trees.
 */
typedef struct {
	git_merge_conflict_type_t type;

	git_index_entry ancestor_entry;
	
	git_index_entry our_entry;
	git_delta_t our_status;
	
	git_index_entry their_entry;
	git_delta_t their_status;
} git_merge_index_conflict;

/** @name Three-way Tree Diff Functions
 *
 * Functions that operate on three trees, a common ancestor, and two
 * child trees ("ours" and "theirs").
 *
 * @param out Pointer to a git_diff_tree_list that will be allocated.
 * @param repo The repository containing the trees.
 * @param ancestor_tree The git_tree object representing the common ancestor.
 * @param our_tree The git_tree object representing the "ours" side.
 * @param their_tree The git_tree object representing the "theirs" side.
 * @param flags A combination of git_diff_tree_option_t values above (default 0)
 * @return 0 on success, or error code
 */
/**@{*/

int git_diff_trees(
	git_merge_index *merge_index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *opts);

/**
 * Deallocate a diff_tree list.
 */
void git_merge_index_free(git_merge_index *diff_tree);

#endif
