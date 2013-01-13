/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_refdb_backend_h__
#define INCLUDE_git_refdb_backend_h__

#include "common.h"
#include "types.h"
#include "oid.h"

/**
 * @file git2/refdb_backend.h
 * @brief Git custom refs backend functions
 * @defgroup git_refdb_backend Git custom refs backend API
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/** An instance for a custom backend */
struct git_refdb_backend {
	/* implementers must provide these */
	int (*exists)(int *exists, struct git_refdb_backend *backend, const char *ref_name);
	int (*lookup)(struct git_refdb_backend *backend, git_reference *);
	int (*foreach)(struct git_refdb_backend *backend, unsigned int list_flags, git_reference_foreach_cb callback, void *payload);
	int (*foreach_glob)(struct git_refdb_backend *backend, const char *glob, unsigned int list_flags, git_reference_foreach_cb callback, void *payload);
	int (*write)(struct git_refdb_backend *backend, git_reference *);
	int (*delete)(struct git_refdb_backend *backend, git_reference *);
	int (*packall)(struct git_refdb_backend *backend);
	void (*free)(struct git_refdb_backend *backend);
};

GIT_EXTERN(int) git_refdb_backend_fs(struct git_refdb_backend **backend_out, git_repository *repo);

GIT_END_DECL

#endif
