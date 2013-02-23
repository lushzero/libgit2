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
 * Flags for tree_many diff options.  A combination of these flags can be
 * passed in via the `flags` value in the `git_diff_tree_many_options`.
 */
typedef enum {
	/** Return unmodified entries */
	GIT_MERGE_TREE_RETURN_UNMODIFIED = (1 << 0),
	
	/** Detect renames */
	GIT_MERGE_TREE_FIND_RENAMES = (1 << 1),
} git_merge_tree_flags;

/**
 * Automerge options for `git_merge_trees_opts`.
 */ 
typedef enum {
	GIT_MERGE_AUTOMERGE_NORMAL = 0,
	GIT_MERGE_AUTOMERGE_NONE = 1,
	GIT_MERGE_AUTOMERGE_FAVOR_OURS = 2,
	GIT_MERGE_AUTOMERGE_FAVOR_THEIRS = 3,
} git_merge_automerge_flags;


typedef struct {
	unsigned int version;
	git_merge_tree_flags flags;
	
	/** Similarity to consider a file renamed (default 50) */
	unsigned int rename_threshold;
	
	/** Maximum similarity sources to examine (overrides the
	 * `merge.renameLimit` config) (default 200)
	 */
	unsigned int target_limit;
	
	/** Flags for automerging content. */
	git_merge_automerge_flags automerge_flags;
} git_merge_tree_opts;

#define GIT_MERGE_TREE_OPTS_VERSION 1
#define GIT_MERGE_TREE_OPTS_INIT {GIT_MERGE_TREE_OPTS_VERSION}

/** Types of conflicts when files are merged from branch to branch. */
typedef enum {
	/* No conflict - a change only occurs in one branch. */
	GIT_MERGE_CONFLICT_NONE = 0,
	
	/* Occurs when a file is modified in both branches. */
	GIT_MERGE_CONFLICT_BOTH_MODIFIED = (1 << 0),
	
	/* Occurs when a file is added in both branches. */
	GIT_MERGE_CONFLICT_BOTH_ADDED = (1 << 1),
	
	/* Occurs when a file is deleted in both branches. */
	GIT_MERGE_CONFLICT_BOTH_DELETED = (1 << 2),
	
	/* Occurs when a file is modified in one branch and deleted in the other. */
	GIT_MERGE_CONFLICT_MODIFIED_DELETED = (1 << 3),
	
	/* Occurs when a file is renamed in one branch and modified in the other. */
	GIT_MERGE_CONFLICT_RENAMED_MODIFIED = (1 << 4),
	
	/* Occurs when a file is renamed in one branch and deleted in the other. */
	GIT_MERGE_CONFLICT_RENAMED_DELETED = (1 << 5),
	
	/* Occurs when a file is renamed in one branch and a file with the same
	 * name is added in the other.  Eg, A->B and new file B.  Core git calls
	 * this a "rename/delete". */
	GIT_MERGE_CONFLICT_RENAMED_ADDED = (1 << 6),
	
	/* Occurs when both a file is renamed to the same name in the ours and
	 * theirs branches.  Eg, A->B and A->B in both.  Automergeable. */
	GIT_MERGE_CONFLICT_BOTH_RENAMED = (1 << 7),
	
	/* Occurs when a file is renamed to different names in the ours and theirs
	 * branches.  Eg, A->B and A->C. */
	GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2 = (1 << 8),
	
	/* Occurs when two files are renamed to the same name in the ours and
	 * theirs branches.  Eg, A->C and B->C. */
	GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1 = (1 << 9),
	
	/* Occurs when an item at a path in one branch is a directory, and an
	 * item at the same path in a different branch is a file. */
	GIT_MERGE_CONFLICT_DIRECTORY_FILE = (1 << 10),

	/* The child of a folder that is in a directory/file conflict. */
	GIT_MERGE_CONFLICT_DF_CHILD = (1 << 11),
} git_merge_conflict_t;


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

typedef struct git_merge_tree_result git_merge_tree_result;

/* TODO: doc! */
/* Note the part about how the index is only added to. */
GIT_EXTERN(int) git_merge_trees(
	git_merge_tree_result **out,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_tree_opts *opts);

/**
 * Free a merge index.
 *
 * @param merge_index the merge index to free
 */
void git_merge_index_free(git_merge_index *diff_tree);

/** @} */
GIT_END_DECL
#endif
