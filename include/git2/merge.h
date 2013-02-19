/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_merge_h__
#define INCLUDE_git_merge_h__

#include "git2/common.h"
#include "git2/types.h"
#include "git2/oid.h"
#include "git2/diff_tree.h"
#include "git2/checkout.h"

/**
 * @file git2/merge.h
 * @brief Git merge routines
 * @defgroup git_merge Git merge routines
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/**
 * Automerge options for `git_merge_trees_opts`.
 */ 
typedef enum {
	GIT_MERGE_AUTOMERGE_NORMAL = 0,
	GIT_MERGE_AUTOMERGE_NONE = (1 << 1),
	GIT_MERGE_AUTOMERGE_FAVOR_OURS = (1 << 2),
	GIT_MERGE_AUTOMERGE_FAVOR_THEIRS = (1 << 3),
} git_merge_automerge_flags;

typedef struct {
	git_diff_tree_options diff_opts;
	unsigned int resolve_flags;
} git_merge_trees_opts;

#define GIT_MERGE_TREES_OPTS_INIT {GIT_DIFF_TREE_OPTIONS_INIT, 0}


/**
 * Find a merge base between two commits
 *
 * @param out the OID of a merge base between 'one' and 'two'
 * @param repo the repository where the commits exist
 * @param one one of the commits
 * @param two the other commit
 * @return Zero on success; GIT_ENOTFOUND or -1 on failure.
 */
GIT_EXTERN(int) git_merge_base(
	git_oid *out,
	git_repository *repo,
	const git_oid *one,
	const git_oid *two);

/**
 * Find a merge base given a list of commits
 *
 * @param out the OID of a merge base considering all the commits
 * @param repo the repository where the commits exist
 * @param input_array oids of the commits
 * @param length The number of commits in the provided `input_array`
 * @return Zero on success; GIT_ENOTFOUND or -1 on failure.
 */
GIT_EXTERN(int) git_merge_base_many(
	git_oid *out,
	git_repository *repo,
	const git_oid input_array[],
	size_t length);

GIT_EXTERN(int) git_merge_trees(
	git_merge_result **out,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_trees_opts *opts);

/**
 * Free a merge result.
 *
 * @param merge_result the merge result to free
 */
GIT_EXTERN(void) git_merge_result_free(git_merge_result *merge_result);

/** @} */
GIT_END_DECL
#endif
