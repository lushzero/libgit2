/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_diff_tree_h__
#define INCLUDE_git_diff_tree_h__

/**
 * @file git2/diff_tree.h
 * @brief Git tree differencing routines.
 *
 * Tree-way (ancestor/ours/theirs) tree differencing and arbitrary n-way
 * tree differencing.  When you are done with a tree diff list object,
 * it must be freed.
 *
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/**
 * Flags for diff options.  A combination of these flags can be passed
 * in via the `flags` value in the `git_diff_tree_options`.
 */
typedef enum {
	/** Normal diff, the default */
	GIT_DIFF_TREE_NORMAL = 0,
	/** Return unmodified entries */
	GIT_DIFF_TREE_RETURN_UNMODIFIED = 1,
} git_diff_tree_option_t;

/**
 * Structure describing options about how the diff should be executed.
 *
 * Setting all values of the structure to zero will yield the default
 * values.  Similarly, passing NULL for the options structure will
 * give the defaults.  The default values are marked below.
 *
 * - flags: a combination of the git_diff_tree_option_t values above
 */
typedef struct {
	uint32_t flags;				/**< defaults to GIT_DIFF_NORMAL */
} git_diff_tree_options;

/**
 * The diff_tree list object that contains all individual object deltas.
 */
typedef struct git_diff_tree_list git_diff_tree_list;

/**
 * Description of changes to one file across many trees.
 */
typedef struct {
	git_diff_file *files;
} git_diff_tree_delta;

/** @name Diff Tree List Generator Functions
 *
 * These are the functions you would use to create (or destroy) a
 * git_diff_tree_list from various objects in a repository.
 */
/**@{*/

/**
 * Compute a difference between many tree objects.
 *
 */

GIT_EXTERN(int) git_diff_trees(
    git_diff_tree_list **out,
    git_repository *repo,
    git_tree **trees,
    size_t trees_length,
    const git_diff_tree_options *opts);

/**
 * Compute a three-way difference between two trees and their common
 * ancestor.
 *
 */

GIT_EXTERN(int) git_diff_trees_threeway(
    git_diff_tree_list **out,
    git_repository *repo,
    git_tree *ancestor_tree,
    git_tree *tree1,
    git_tree *tree2,
    const git_diff_tree_options *opts);

/**@}*/

/**
 * Deallocate a diff_tree list.
 */
GIT_EXTERN(void) git_diff_tree_list_free(git_diff_tree_list *diff);

GIT_END_DECL

/** @} */

#endif
