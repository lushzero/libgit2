/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_checkout_h__
#define INCLUDE_checkout_h__

#include "git2/checkout.h"

int git_checkout_blob(
	git_repository *repo,
	const git_oid *oid,
	const char *path,
	int mode,
	git_checkout_opts *opts);

#endif
