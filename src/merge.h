/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_merge_h__
#define INCLUDE_merge_h__

#include "vector.h"
#include "commit_list.h"
#include "diff_tree.h"

#include "git2/types.h"

#define GIT_MERGE_MSG_FILE		"MERGE_MSG"
#define GIT_MERGE_MODE_FILE		"MERGE_MODE"

#define GIT_MERGE_TREE_RENAME_THRESHOLD	50
#define GIT_MERGE_TREE_TARGET_LIMIT		1000

/** Internal structure for merge tree results */
struct git_merge_tree_result {
	bool is_uptodate;
	
	bool is_fastforward;
	git_oid fastforward_oid;
	
	git_merge_index *diff_tree;
	git_vector conflicts;
};

int git_merge__bases_many(
	git_commit_list **out,
	git_revwalk *walk,
	git_commit_list_node *one,
	git_vector *twos);

#endif
