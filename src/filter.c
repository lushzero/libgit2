/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "fileops.h"
#include "hash.h"
#include "filter.h"
#include "repository.h"
#include "git2/config.h"
#include "blob.h"

int git_filters_load(git_vector *filters, git_repository *repo, const char *path, int mode)
{
	int error;

	if (mode == GIT_FILTER_TO_ODB) {
		/* Load the CRLF cleanup filter when writing to the ODB */
		error = git_filter_add__crlf_to_odb(filters, repo, path);
		if (error < 0)
			return error;
	} else {
		error = git_filter_add__crlf_to_workdir(filters, repo, path);
		if (error < 0)
			return error;
	}

	return (int)filters->length;
}

void git_filters_free(git_vector *filters)
{
	size_t i;
	git_filter *filter;

	git_vector_foreach(filters, i, filter) {
		if (filter->do_free != NULL)
			filter->do_free(filter);
		else
			git__free(filter);
	}

	git_vector_free(filters);
}

int git_filters_apply(void **dst, size_t *dst_len, git_vector *filters, const char *path, const void *src, size_t src_len)
{
	git_filter *filter;
	const char *in;
	char *out = NULL;
	size_t in_len, out_len;
	size_t i;
	int error = 0;
	int filtered = 0;

	*dst = NULL;
	*dst_len = 0;

	if (src_len == 0)
		return 0;

	in = src;
	in_len = src_len;

	git_vector_foreach(filters, i, filter) {
		if ((error = filter->apply(&out, &out_len, filter, path, in, in_len)) < 0)
			goto on_error;

		/* Filter cancelled application; do nothing. */
		if (error == 0)
			continue;

		if (filtered)
			git__free(out);

		in = out;
		in_len = out_len;

		filtered++;
	}

	if (filtered > 0) {
		*dst = out;
		*dst_len = out_len;
	}

	return filtered;

on_error:
	if (filtered)
		git__free(out);

	return error;
}
