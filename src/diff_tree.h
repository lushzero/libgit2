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

#define GIT_DIFF_TREE_FILE_EXISTS(X)	((X).mode != 0)

struct git_diff_tree_list {
	git_repository *repo;
	git_pool pool;

	git_vector deltas;    /* vector of git_diff_tree_delta */
};

/**
 * The git_diff_tree_list list object that contains all individual
 * object deltas.
 */
typedef struct git_diff_tree_list git_diff_tree_list;

/**
 * Description of changes to one file across three trees.
 */
typedef struct {
	git_diff_file ancestor_file;
	
	git_diff_file our_file;
	git_delta_t our_status;
	
	git_diff_file their_file;
	git_delta_t their_status;
	
	git_merge_conflict_t conflict;
} git_diff_tree_delta;

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
	git_diff_tree_list **out,
	git_repository *repo,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *opts);

/**
 * Deallocate a diff_tree list.
 */
void git_diff_tree_list_free(git_diff_tree_list *diff_tree);

#endif
