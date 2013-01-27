/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_refdb_h__
#define INCLUDE_refdb_h__

#include "git2/refdb.h"

struct git_refdb {
	git_repository *repo;
	git_refcount rc;
	git_refdb_backend *backend;
};

#endif
