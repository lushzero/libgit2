/*
 * Copyright (C) 2009-2012 the libgit2 contributors
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
#include "git2/diff_tree.h"

#define GIT_MERGE_MSG_FILE		"MERGE_MSG"
#define GIT_MERGE_MODE_FILE		"MERGE_MODE"

#define MERGE_CONFIG_FILE_MODE	0666

/** Internal structure for merge inputs */
struct git_merge_head {
	char *branch_name;
	git_oid oid;

	git_commit *commit;
};

/** Internal structure for merge results */
struct git_merge_result {
	bool is_uptodate;

	bool is_fastforward;
	git_oid fastforward_oid;
	
	git_diff_tree_list *diff_tree;
	git_vector conflicts;
};

int git_merge__setup(
	git_repository *repo,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	unsigned int flags);
int git_merge__bases_many(git_commit_list **out, git_revwalk *walk, git_commit_list_node *one, git_vector *twos);
int git_merge__cleanup(git_repository *repo);

#endif
