/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_checkout_h__
#define INCLUDE_checkout_h__

#include "git2/repository.h"
#include "git2/oid.h"
#include "git2/checkout.h"
#include "iterator.h"
#include "vector.h"
#include "buffer.h"

#define GIT_CHECKOUT__NOTIFY_CONFLICT_TREE (1u << 12)

typedef struct {
	git_repository *repo;
	git_diff_list *diff;
	git_checkout_opts opts;
	bool opts_free_baseline;
	char *pfx;
	git_index *index;
	git_pool pool;
	git_vector removes;
	git_buf path;
	size_t workdir_len;
	unsigned int strategy;
	int can_symlink;
	bool reload_submodules;
	size_t total_steps;
	size_t completed_steps;
} git_checkout_data;

int git_checkout_data_init(
	git_checkout_data *data,
	git_repository *repo,
	git_index *index,
	git_checkout_opts *proposed);

void git_checkout_data_clear(git_checkout_data *data);

/**
 * Update the working directory to match the target iterator.  The
 * expected baseline value can be passed in via the checkout options
 * or else will default to the HEAD commit.
 */
extern int git_checkout_iterator(
	git_iterator *target,
	git_checkout_opts *opts);

int git_checkout_blob(
	struct stat *st,
	git_checkout_data *data,
	const git_oid *oid,
	const char *path,
	mode_t mode);

#endif
