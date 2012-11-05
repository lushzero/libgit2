/*
 * Copyright (C) 2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "diff.h"
#include "fileops.h"
#include "config.h"
#include "attr_file.h"
#include "filter.h"

#include "git2/oid.h"

static char *diff_prefix_from_pathspec(const git_strarray *pathspec)
{
	git_buf prefix = GIT_BUF_INIT;
	const char *scan;

	if (git_buf_common_prefix(&prefix, pathspec) < 0)
		return NULL;

	/* diff prefix will only be leading non-wildcards */
	for (scan = prefix.ptr; *scan; ++scan) {
		if (git__iswildcard(*scan) &&
			(scan == prefix.ptr || (*(scan - 1) != '\\')))
			break;
	}
	git_buf_truncate(&prefix, scan - prefix.ptr);

	if (prefix.size <= 0) {
		git_buf_free(&prefix);
		return NULL;
	}

	git_buf_unescape(&prefix);

	return git_buf_detach(&prefix);
}

static bool diff_pathspec_is_interesting(const git_strarray *pathspec)
{
	const char *str;

	if (pathspec == NULL || pathspec->count == 0)
		return false;
	if (pathspec->count > 1)
		return true;

	str = pathspec->strings[0];
	if (!str || !str[0] || (!str[1] && (str[0] == '*' || str[0] == '.')))
		return false;
	return true;
}

static bool diff_path_matches_pathspec(git_diff_list *diff, const char *path)
{
	unsigned int i;
	git_attr_fnmatch *match;

	if (!diff->pathspec.length)
		return true;

	git_vector_foreach(&diff->pathspec, i, match) {
		int result = strcmp(match->pattern, path) ? FNM_NOMATCH : 0;

		if (((diff->opts.flags & GIT_DIFF_DISABLE_PATHSPEC_MATCH) == 0) &&
			result == FNM_NOMATCH)
			result = p_fnmatch(match->pattern, path, 0);

		/* if we didn't match, look for exact dirname prefix match */
		if (result == FNM_NOMATCH &&
			(match->flags & GIT_ATTR_FNMATCH_HASWILD) == 0 &&
			strncmp(path, match->pattern, match->length) == 0 &&
			path[match->length] == '/')
			result = 0;

		if (result == 0)
			return (match->flags & GIT_ATTR_FNMATCH_NEGATIVE) ? false : true;
	}

	return false;
}

static git_diff_delta *diff_delta__alloc(
	git_diff_list *diff,
	git_delta_t status,
	const char *path)
{
	git_diff_delta *delta = git__calloc(1, sizeof(git_diff_delta));
	if (!delta)
		return NULL;

	delta->old_file.path = git_pool_strdup(&diff->pool, path);
	if (delta->old_file.path == NULL) {
		git__free(delta);
		return NULL;
	}

	delta->new_file.path = delta->old_file.path;

	if (diff->opts.flags & GIT_DIFF_REVERSE) {
		switch (status) {
		case GIT_DELTA_ADDED:   status = GIT_DELTA_DELETED; break;
		case GIT_DELTA_DELETED: status = GIT_DELTA_ADDED; break;
		default: break; /* leave other status values alone */
		}
	}
	delta->status = status;

	return delta;
}

static git_diff_delta *diff_delta__dup(
	const git_diff_delta *d, git_pool *pool)
{
	git_diff_delta *delta = git__malloc(sizeof(git_diff_delta));
	if (!delta)
		return NULL;

	memcpy(delta, d, sizeof(git_diff_delta));

	delta->old_file.path = git_pool_strdup(pool, d->old_file.path);
	if (delta->old_file.path == NULL)
		goto fail;

	if (d->new_file.path != d->old_file.path) {
		delta->new_file.path = git_pool_strdup(pool, d->new_file.path);
		if (delta->new_file.path == NULL)
			goto fail;
	} else {
		delta->new_file.path = delta->old_file.path;
	}

	return delta;

fail:
	git__free(delta);
	return NULL;
}

static git_diff_delta *diff_delta__merge_like_cgit(
	const git_diff_delta *a, const git_diff_delta *b, git_pool *pool)
{
	git_diff_delta *dup;

	/* Emulate C git for merging two diffs (a la 'git diff <sha>').
	 *
	 * When C git does a diff between the work dir and a tree, it actually
	 * diffs with the index but uses the workdir contents.  This emulates
	 * those choices so we can emulate the type of diff.
	 *
	 * We have three file descriptions here, let's call them:
	 *  f1 = a->old_file
	 *  f2 = a->new_file AND b->old_file
	 *  f3 = b->new_file
	 */

	/* if f2 == f3 or f2 is deleted, then just dup the 'a' diff */
	if (b->status == GIT_DELTA_UNMODIFIED || a->status == GIT_DELTA_DELETED)
		return diff_delta__dup(a, pool);

	/* otherwise, base this diff on the 'b' diff */
	if ((dup = diff_delta__dup(b, pool)) == NULL)
		return NULL;

	/* If 'a' status is uninteresting, then we're done */
	if (a->status == GIT_DELTA_UNMODIFIED)
		return dup;

	assert(a->status != GIT_DELTA_UNMODIFIED);
	assert(b->status != GIT_DELTA_UNMODIFIED);

	/* A cgit exception is that the diff of a file that is only in the
	 * index (i.e. not in HEAD nor workdir) is given as empty.
	 */
	if (dup->status == GIT_DELTA_DELETED) {
		if (a->status == GIT_DELTA_ADDED)
			dup->status = GIT_DELTA_UNMODIFIED;
		/* else don't overwrite DELETE status */
	} else {
		dup->status = a->status;
	}

	git_oid_cpy(&dup->old_file.oid, &a->old_file.oid);
	dup->old_file.mode  = a->old_file.mode;
	dup->old_file.size  = a->old_file.size;
	dup->old_file.flags = a->old_file.flags;

	return dup;
}

static int diff_delta__from_one(
	git_diff_list *diff,
	git_delta_t   status,
	const git_index_entry *entry)
{
	git_diff_delta *delta;

	if (status == GIT_DELTA_IGNORED &&
		(diff->opts.flags & GIT_DIFF_INCLUDE_IGNORED) == 0)
		return 0;

	if (status == GIT_DELTA_UNTRACKED &&
		(diff->opts.flags & GIT_DIFF_INCLUDE_UNTRACKED) == 0)
		return 0;

	if (!diff_path_matches_pathspec(diff, entry->path))
		return 0;

	delta = diff_delta__alloc(diff, status, entry->path);
	GITERR_CHECK_ALLOC(delta);

	/* This fn is just for single-sided diffs */
	assert(status != GIT_DELTA_MODIFIED);

	if (delta->status == GIT_DELTA_DELETED) {
		delta->old_file.mode = entry->mode;
		delta->old_file.size = entry->file_size;
		git_oid_cpy(&delta->old_file.oid, &entry->oid);
	} else /* ADDED, IGNORED, UNTRACKED */ {
		delta->new_file.mode = entry->mode;
		delta->new_file.size = entry->file_size;
		git_oid_cpy(&delta->new_file.oid, &entry->oid);
	}

	delta->old_file.flags |= GIT_DIFF_FILE_VALID_OID;

	if (delta->status == GIT_DELTA_DELETED ||
		!git_oid_iszero(&delta->new_file.oid))
		delta->new_file.flags |= GIT_DIFF_FILE_VALID_OID;

	if (git_vector_insert(&diff->deltas, delta) < 0) {
		git__free(delta);
		return -1;
	}

	return 0;
}

static int diff_delta__from_two(
	git_diff_list *diff,
	git_delta_t   status,
	const git_index_entry *old_entry,
	uint32_t old_mode,
	const git_index_entry *new_entry,
	uint32_t new_mode,
	git_oid *new_oid)
{
	git_diff_delta *delta;

	if (status == GIT_DELTA_UNMODIFIED &&
		(diff->opts.flags & GIT_DIFF_INCLUDE_UNMODIFIED) == 0)
		return 0;

	if ((diff->opts.flags & GIT_DIFF_REVERSE) != 0) {
		uint32_t temp_mode = old_mode;
		const git_index_entry *temp_entry = old_entry;
		old_entry = new_entry;
		new_entry = temp_entry;
		old_mode = new_mode;
		new_mode = temp_mode;
	}

	delta = diff_delta__alloc(diff, status, old_entry->path);
	GITERR_CHECK_ALLOC(delta);

	git_oid_cpy(&delta->old_file.oid, &old_entry->oid);
	delta->old_file.size = old_entry->file_size;
	delta->old_file.mode = old_mode;
	delta->old_file.flags |= GIT_DIFF_FILE_VALID_OID;

	git_oid_cpy(&delta->new_file.oid, &new_entry->oid);
	delta->new_file.size = new_entry->file_size;
	delta->new_file.mode = new_mode;

	if (new_oid) {
		if ((diff->opts.flags & GIT_DIFF_REVERSE) != 0)
			git_oid_cpy(&delta->old_file.oid, new_oid);
		else
			git_oid_cpy(&delta->new_file.oid, new_oid);
	}

	if (new_oid || !git_oid_iszero(&new_entry->oid))
		delta->new_file.flags |= GIT_DIFF_FILE_VALID_OID;

	if (git_vector_insert(&diff->deltas, delta) < 0) {
		git__free(delta);
		return -1;
	}

	return 0;
}

static git_diff_delta *diff_delta__last_for_item(
	git_diff_list *diff,
	const git_index_entry *item)
{
	git_diff_delta *delta = git_vector_last(&diff->deltas);
	if (!delta)
		return NULL;

	switch (delta->status) {
	case GIT_DELTA_UNMODIFIED:
	case GIT_DELTA_DELETED:
		if (git_oid_cmp(&delta->old_file.oid, &item->oid) == 0)
			return delta;
		break;
	case GIT_DELTA_ADDED:
		if (git_oid_cmp(&delta->new_file.oid, &item->oid) == 0)
			return delta;
		break;
	case GIT_DELTA_MODIFIED:
		if (git_oid_cmp(&delta->old_file.oid, &item->oid) == 0 ||
			git_oid_cmp(&delta->new_file.oid, &item->oid) == 0)
			return delta;
		break;
	default:
		break;
	}

	return NULL;
}

static char *diff_strdup_prefix(git_pool *pool, const char *prefix)
{
	size_t len = strlen(prefix);

	/* append '/' at end if needed */
	if (len > 0 && prefix[len - 1] != '/')
		return git_pool_strcat(pool, prefix, "/");
	else
		return git_pool_strndup(pool, prefix, len + 1);
}

static int diff_delta__cmp(const void *a, const void *b)
{
	const git_diff_delta *da = a, *db = b;
	int val = strcmp(da->old_file.path, db->old_file.path);
	return val ? val : ((int)da->status - (int)db->status);
}

static int config_bool(git_config *cfg, const char *name, int defvalue)
{
	int val = defvalue;

	if (git_config_get_bool(&val, cfg, name) < 0)
		giterr_clear();

	return val;
}

static git_diff_list *git_diff_list_alloc(
	git_repository *repo, const git_diff_options *opts)
{
	git_config *cfg;
	size_t i;
	git_diff_list *diff = git__calloc(1, sizeof(git_diff_list));
	if (diff == NULL)
		return NULL;

	GIT_REFCOUNT_INC(diff);
	diff->repo = repo;

	if (git_vector_init(&diff->deltas, 0, diff_delta__cmp) < 0 ||
		git_pool_init(&diff->pool, 1, 0) < 0)
		goto fail;

	/* load config values that affect diff behavior */
	if (git_repository_config__weakptr(&cfg, repo) < 0)
		goto fail;
	if (config_bool(cfg, "core.symlinks", 1))
		diff->diffcaps = diff->diffcaps | GIT_DIFFCAPS_HAS_SYMLINKS;
	if (config_bool(cfg, "core.ignorestat", 0))
		diff->diffcaps = diff->diffcaps | GIT_DIFFCAPS_ASSUME_UNCHANGED;
	if (config_bool(cfg, "core.filemode", 1))
		diff->diffcaps = diff->diffcaps | GIT_DIFFCAPS_TRUST_MODE_BITS;
	if (config_bool(cfg, "core.trustctime", 1))
		diff->diffcaps = diff->diffcaps | GIT_DIFFCAPS_TRUST_CTIME;
	/* Don't set GIT_DIFFCAPS_USE_DEV - compile time option in core git */

	if (opts == NULL)
		return diff;

	memcpy(&diff->opts, opts, sizeof(git_diff_options));
	memset(&diff->opts.pathspec, 0, sizeof(diff->opts.pathspec));

	diff->opts.old_prefix = diff_strdup_prefix(&diff->pool,
		opts->old_prefix ? opts->old_prefix : DIFF_OLD_PREFIX_DEFAULT);
	diff->opts.new_prefix = diff_strdup_prefix(&diff->pool,
		opts->new_prefix ? opts->new_prefix : DIFF_NEW_PREFIX_DEFAULT);

	if (!diff->opts.old_prefix || !diff->opts.new_prefix)
		goto fail;

	if (diff->opts.flags & GIT_DIFF_REVERSE) {
		char *swap = diff->opts.old_prefix;
		diff->opts.old_prefix = diff->opts.new_prefix;
		diff->opts.new_prefix = swap;
	}

	/* INCLUDE_TYPECHANGE_TREES implies INCLUDE_TYPECHANGE */
	if (diff->opts.flags & GIT_DIFF_INCLUDE_TYPECHANGE_TREES)
		diff->opts.flags |= GIT_DIFF_INCLUDE_TYPECHANGE;

	/* only copy pathspec if it is "interesting" so we can test
	 * diff->pathspec.length > 0 to know if it is worth calling
	 * fnmatch as we iterate.
	 */
	if (!diff_pathspec_is_interesting(&opts->pathspec))
		return diff;

	if (git_vector_init(
		&diff->pathspec, (unsigned int)opts->pathspec.count, NULL) < 0)
		goto fail;

	for (i = 0; i < opts->pathspec.count; ++i) {
		int ret;
		const char *pattern = opts->pathspec.strings[i];
		git_attr_fnmatch *match = git__calloc(1, sizeof(git_attr_fnmatch));
		if (!match)
			goto fail;
		match->flags = GIT_ATTR_FNMATCH_ALLOWSPACE;
		ret = git_attr_fnmatch__parse(match, &diff->pool, NULL, &pattern);
		if (ret == GIT_ENOTFOUND) {
			git__free(match);
			continue;
		} else if (ret < 0)
			goto fail;

		if (git_vector_insert(&diff->pathspec, match) < 0)
			goto fail;
	}

	return diff;

fail:
	git_diff_list_free(diff);
	return NULL;
}

static void diff_list_free(git_diff_list *diff)
{
	git_diff_delta *delta;
	git_attr_fnmatch *match;
	unsigned int i;

	git_vector_foreach(&diff->deltas, i, delta) {
		git__free(delta);
		diff->deltas.contents[i] = NULL;
	}
	git_vector_free(&diff->deltas);

	git_vector_foreach(&diff->pathspec, i, match) {
		git__free(match);
		diff->pathspec.contents[i] = NULL;
	}
	git_vector_free(&diff->pathspec);

	git_pool_clear(&diff->pool);
	git__free(diff);
}

void git_diff_list_free(git_diff_list *diff)
{
	if (!diff)
		return;

	GIT_REFCOUNT_DEC(diff, diff_list_free);
}

void git_diff_list_addref(git_diff_list *diff)
{
	GIT_REFCOUNT_INC(diff);
}

static git_diff_tree_list *diff_tree_list_alloc(git_repository *repo)
{
	git_diff_tree_list *diff_tree = git__calloc(1, sizeof(git_diff_tree_list));

	if (diff_tree == NULL)
		return NULL;

	GIT_REFCOUNT_INC(diff_tree);
	diff_tree->repo = repo;

	if (git_vector_init(&diff_tree->deltas, 0, diff_delta__cmp) < 0 ||
		git_pool_init(&diff_tree->pool, 1, 0) < 0)
        return NULL;
    
    return diff_tree;
}

static void diff_tree_list_free(git_diff_tree_list *diff_tree)
{
	git_diff_delta *delta;
	unsigned int i;

	git_vector_foreach(&diff_tree->deltas, i, delta) {
		git__free(delta);
		diff_tree->deltas.contents[i] = NULL;
	}
	git_vector_free(&diff_tree->deltas);

	git_pool_clear(&diff_tree->pool);
	git__free(diff_tree);
}

void git_diff_tree_list_free(git_diff_tree_list *diff_tree)
{
	if (!diff_tree)
		return;

	GIT_REFCOUNT_DEC(diff_tree, diff_tree_list_free);
}

static int oid_for_workdir_item(
	git_repository *repo,
	const git_index_entry *item,
	git_oid *oid)
{
	int result = 0;
	git_buf full_path = GIT_BUF_INIT;

	if (git_buf_joinpath(
		&full_path, git_repository_workdir(repo), item->path) < 0)
		return -1;

	/* calculate OID for file if possible */
	if (S_ISGITLINK(item->mode)) {
		git_submodule *sm;
		const git_oid *sm_oid;

		if (!git_submodule_lookup(&sm, repo, item->path) &&
			(sm_oid = git_submodule_wd_oid(sm)) != NULL)
			git_oid_cpy(oid, sm_oid);
		else {
			/* if submodule lookup failed probably just in an intermediate
			 * state where some init hasn't happened, so ignore the error
			 */
			giterr_clear();
			memset(oid, 0, sizeof(*oid));
		}
	} else if (S_ISLNK(item->mode))
		result = git_odb__hashlink(oid, full_path.ptr);
	else if (!git__is_sizet(item->file_size)) {
		giterr_set(GITERR_OS, "File size overflow for 32-bit systems");
		result = -1;
	} else {
		git_vector filters = GIT_VECTOR_INIT;

		result = git_filters_load(
			&filters, repo, item->path, GIT_FILTER_TO_ODB);
		if (result >= 0) {
			int fd = git_futils_open_ro(full_path.ptr);
			if (fd < 0)
				result = fd;
			else {
				result = git_odb__hashfd_filtered(
					oid, fd, (size_t)item->file_size, GIT_OBJ_BLOB, &filters);
				p_close(fd);
			}
		}

		git_filters_free(&filters);
	}

	git_buf_free(&full_path);

	return result;
}

#define MODE_BITS_MASK 0000777

static int maybe_modified(
	git_iterator *old_iter,
	const git_index_entry *oitem,
	git_iterator *new_iter,
	const git_index_entry *nitem,
	git_diff_list *diff)
{
	git_oid noid, *use_noid = NULL;
	git_delta_t status = GIT_DELTA_MODIFIED;
	unsigned int omode = oitem->mode;
	unsigned int nmode = nitem->mode;
	bool new_is_workdir = (new_iter->type == GIT_ITERATOR_WORKDIR);

	GIT_UNUSED(old_iter);

	if (!diff_path_matches_pathspec(diff, oitem->path))
		return 0;

	/* on platforms with no symlinks, preserve mode of existing symlinks */
	if (S_ISLNK(omode) && S_ISREG(nmode) && new_is_workdir &&
		!(diff->diffcaps & GIT_DIFFCAPS_HAS_SYMLINKS))
		nmode = omode;

	/* on platforms with no execmode, just preserve old mode */
	if (!(diff->diffcaps & GIT_DIFFCAPS_TRUST_MODE_BITS) &&
		(nmode & MODE_BITS_MASK) != (omode & MODE_BITS_MASK) &&
		new_is_workdir)
		nmode = (nmode & ~MODE_BITS_MASK) | (omode & MODE_BITS_MASK);

	/* support "assume unchanged" (poorly, b/c we still stat everything) */
	if ((diff->diffcaps & GIT_DIFFCAPS_ASSUME_UNCHANGED) != 0)
		status = (oitem->flags_extended & GIT_IDXENTRY_INTENT_TO_ADD) ?
			GIT_DELTA_MODIFIED : GIT_DELTA_UNMODIFIED;

	/* support "skip worktree" index bit */
	else if ((oitem->flags_extended & GIT_IDXENTRY_SKIP_WORKTREE) != 0)
		status = GIT_DELTA_UNMODIFIED;

	/* if basic type of file changed, then split into delete and add */
	else if (GIT_MODE_TYPE(omode) != GIT_MODE_TYPE(nmode)) {
		if ((diff->opts.flags & GIT_DIFF_INCLUDE_TYPECHANGE) != 0)
			status = GIT_DELTA_TYPECHANGE;
		else {
			if (diff_delta__from_one(diff, GIT_DELTA_DELETED, oitem) < 0 ||
				diff_delta__from_one(diff, GIT_DELTA_ADDED, nitem) < 0)
				return -1;
			return 0;
		}
	}

	/* if oids and modes match, then file is unmodified */
	else if (git_oid_cmp(&oitem->oid, &nitem->oid) == 0 &&
			 omode == nmode)
		status = GIT_DELTA_UNMODIFIED;

	/* if we have an unknown OID and a workdir iterator, then check some
	 * circumstances that can accelerate things or need special handling
	 */
	else if (git_oid_iszero(&nitem->oid) && new_is_workdir) {
		/* TODO: add check against index file st_mtime to avoid racy-git */

		/* if the stat data looks exactly alike, then assume the same */
		if (omode == nmode &&
			oitem->file_size == nitem->file_size &&
			(!(diff->diffcaps & GIT_DIFFCAPS_TRUST_CTIME) ||
			 (oitem->ctime.seconds == nitem->ctime.seconds)) &&
			oitem->mtime.seconds == nitem->mtime.seconds &&
			(!(diff->diffcaps & GIT_DIFFCAPS_USE_DEV) ||
			 (oitem->dev == nitem->dev)) &&
			oitem->ino == nitem->ino &&
			oitem->uid == nitem->uid &&
			oitem->gid == nitem->gid)
			status = GIT_DELTA_UNMODIFIED;

		else if (S_ISGITLINK(nmode)) {
			git_submodule *sub;

			if ((diff->opts.flags & GIT_DIFF_IGNORE_SUBMODULES) != 0)
				status = GIT_DELTA_UNMODIFIED;
			else if (git_submodule_lookup(&sub, diff->repo, nitem->path) < 0)
				return -1;
			else if (git_submodule_ignore(sub) == GIT_SUBMODULE_IGNORE_ALL)
				status = GIT_DELTA_UNMODIFIED;
			else {
				unsigned int sm_status = 0;
				if (git_submodule_status(&sm_status, sub) < 0)
					return -1;
				status = GIT_SUBMODULE_STATUS_IS_UNMODIFIED(sm_status)
						 ? GIT_DELTA_UNMODIFIED : GIT_DELTA_MODIFIED;

				/* grab OID while we are here */
				if (git_oid_iszero(&nitem->oid)) {
					const git_oid *sm_oid = git_submodule_wd_oid(sub);
					if (sm_oid != NULL) {
						git_oid_cpy(&noid, sm_oid);
						use_noid = &noid;
					}
				}
			}
		}
	}

	/* if we got here and decided that the files are modified, but we
	 * haven't calculated the OID of the new item, then calculate it now
	 */
	if (status != GIT_DELTA_UNMODIFIED && git_oid_iszero(&nitem->oid)) {
		if (oid_for_workdir_item(diff->repo, nitem, &noid) < 0)
			return -1;
		else if (omode == nmode && git_oid_equal(&oitem->oid, &noid))
			status = GIT_DELTA_UNMODIFIED;

		/* store calculated oid so we don't have to recalc later */
		use_noid = &noid;
	}

	return diff_delta__from_two(
		diff, status, oitem, omode, nitem, nmode, use_noid);
}

static int git_index_entry_cmp_case(const void *a, const void *b)
{
	const git_index_entry *entry_a = a;
	const git_index_entry *entry_b = b;

	return strcmp(entry_a->path, entry_b->path);
}

static int git_index_entry_cmp_icase(const void *a, const void *b)
{
	const git_index_entry *entry_a = a;
	const git_index_entry *entry_b = b;

	return strcasecmp(entry_a->path, entry_b->path);
}

static int index_entry_cmp(git_index_entry *a, git_index_entry *b)
{
	int diff;

	assert (a && b);

	/*
	 * TODO: if this is constrained to git_index_entries from
	 * git_tree_iterators then we needn't even test all of these
	 * since many will be unset.
	 */
	if ((diff = a->ctime.seconds - b->ctime.seconds) == 0 &&
		(diff = a->ctime.nanoseconds - b->ctime.nanoseconds) == 0 &&
		(diff = a->mtime.seconds - b->mtime.seconds) == 0 &&
		(diff = a->mtime.nanoseconds - b->mtime.nanoseconds) == 0 &&
		(diff = a->dev - b->dev) == 0 &&
		(diff = a->ino - b->ino) == 0 &&
		(diff = a->mode - b->mode) == 0 &&
		(diff = a->uid - b->uid) == 0 &&
		(diff = a->gid - b->gid) == 0 &&
		(diff = a->file_size - b->file_size) == 0 &&
		(diff = a->flags - b->flags) == 0 &&
		(diff = a->flags_extended - b->flags_extended) == 0) {
		diff = git_oid_cmp(&a->oid, &b->oid);
	}

	return diff;
}

static git_diff_tree_delta *diff_tree_delta__from_entries(
	git_diff_tree_list *diff_tree,
	git_index_entry **entries,
	size_t entries_length)
{
	git_diff_tree_delta *delta_tree;
	size_t i;

	if ((delta_tree = git__calloc(1, sizeof(git_diff_tree_delta))) == NULL ||
		(delta_tree->files = git__calloc(entries_length, sizeof(git_diff_file))) == NULL)
        return NULL;

	for (i = 0; i < entries_length; i++) {
		if (entries[i] == NULL) {
			memset(&delta_tree->files[i], 0x0, sizeof(git_diff_file));
			continue;
		}

		if ((delta_tree->files[i].path = git_pool_strdup(&diff_tree->pool, entries[i]->path)) == NULL)
			return NULL;

		git_oid_cpy(&delta_tree->files[i].oid, &entries[i]->oid);
		delta_tree->files[i].size = entries[i]->file_size;
		delta_tree->files[i].mode = entries[i]->mode;
		delta_tree->files[i].flags |= GIT_DIFF_FILE_VALID_OID;
	}

    return delta_tree;
}

int git_diff_trees(
    git_diff_tree_list **out,
    git_repository *repo,
    git_tree **trees,
    size_t trees_length,
    unsigned int flags)
{
    git_iterator **iterators;
	git_index_entry **items = NULL, *best_next_item, **next_items;
	git_vector_cmp entry_compare = git_index_entry_cmp_case;
	git_diff_tree_list *diff_tree = diff_tree_list_alloc(repo);
	int next_item_modified;
    bool return_unmodified;
	size_t i;
	int error = 0;

	assert(out && repo && trees);

	*out = NULL;
    
    iterators = git__calloc(trees_length, sizeof(git_iterator *));
    GITERR_CHECK_ALLOC(iterators);

    items = git__calloc(trees_length, sizeof(git_index_entry *));
    GITERR_CHECK_ALLOC(items);

    next_items = git__calloc(trees_length, sizeof(git_index_entry *));
    GITERR_CHECK_ALLOC(next_items);
    
    return_unmodified = (flags & GIT_DIFF_TREES_RETURN_UNMODIFIED) == GIT_DIFF_TREES_RETURN_UNMODIFIED;
    
	for (i = 0; i < trees_length; i++) {
        if ((error = git_iterator_for_tree(&iterators[i], repo, trees[i])) < 0)
            goto done;
    }

	/* Set up the iterators */
	for (i = 0; i < trees_length; i++) {
		if ((error = git_iterator_current(iterators[i], (const git_index_entry **)&items[i])) < 0)
			goto done;
	}

	while (true) {
		memset(next_items, 0x0, sizeof(git_index_entry *) * trees_length);
		best_next_item = NULL;
		next_item_modified = 0;

		/* Find the next path(s) to consume from each iterator */
		for (i = 0; i < trees_length; i++) {
			if (items[i] == NULL) {
				next_item_modified = 1;
				continue;
			}

			if (best_next_item == NULL) {
				best_next_item = items[i];
				next_items[i] = items[i];
			} else {
				int diff = entry_compare(items[i], best_next_item);

				if (diff < 0) {
                    /*
                     * Found an item that sorts before our current item, make
                     * our current item this one.
                     */
					memset(next_items, 0x0, sizeof(git_index_entry *) * trees_length);
					next_item_modified = 1;
					best_next_item = items[i];
					next_items[i] = items[i];
                } else if (diff > 0) {
                    /* No entry for the current item, this is modified */
                    next_item_modified = 1;
                } else if (diff == 0) {
					next_items[i] = items[i];

					if (!next_item_modified && !return_unmodified)
						next_item_modified = index_entry_cmp(best_next_item, items[i]);
				}
			}
		}

		if (best_next_item == NULL)
			break;

		if (next_item_modified || return_unmodified) {
			git_diff_tree_delta *delta;

			if ((delta = diff_tree_delta__from_entries(diff_tree, next_items, trees_length)) == NULL ||
				(error = git_vector_insert(&diff_tree->deltas, delta)) < 0)
				goto done;
		}

		/* Advance each iterator that participated */
		for (i = 0; i < trees_length; i++) {
			if (next_items[i] != NULL && (error = git_iterator_advance(iterators[i], (const git_index_entry **)&items[i])) < 0)
				goto done;
		}
	}

	/* TODO: renames */

done:
    git__free(iterators);
	git__free(items);
	git__free(next_items);

	if (error >= 0)
		*out = diff_tree;

	return error;
}

static bool entry_is_prefixed(
	const git_index_entry *item,
	git_iterator *prefix_iterator,
	const git_index_entry *prefix_item)
{
	size_t pathlen;

	if (!prefix_item ||
		ITERATOR_PREFIXCMP(*prefix_iterator, prefix_item->path, item->path))
		return false;

	pathlen = strlen(item->path);

	return (item->path[pathlen - 1] == '/' ||
			prefix_item->path[pathlen] == '\0' ||
			prefix_item->path[pathlen] == '/');
}

static int diff_from_iterators(
	git_repository *repo,
	const git_diff_options *opts, /**< can be NULL for defaults */
	git_iterator *old_iter,
	git_iterator *new_iter,
	git_diff_list **diff_ptr)
{
	const git_index_entry *oitem, *nitem;
	git_buf ignore_prefix = GIT_BUF_INIT;
	git_diff_list *diff = git_diff_list_alloc(repo, opts);
	git_vector_cmp entry_compare;

	if (!diff)
		goto fail;

	diff->old_src = old_iter->type;
	diff->new_src = new_iter->type;

	/* Use case-insensitive compare if either iterator has
	 * the ignore_case bit set */
	if (!old_iter->ignore_case && !new_iter->ignore_case) {
		entry_compare = git_index_entry_cmp_case;
		diff->opts.flags &= ~GIT_DIFF_DELTAS_ARE_ICASE;
	} else {
		entry_compare = git_index_entry_cmp_icase;
		diff->opts.flags |= GIT_DIFF_DELTAS_ARE_ICASE;

		/* If one of the iterators doesn't have ignore_case set,
		 * then that's unfortunate because we'll have to spool
		 * its data, sort it icase, and then use that for our
		 * merge join to the other iterator that is icase sorted */
		if (!old_iter->ignore_case) {
			if (git_iterator_spoolandsort(&old_iter, old_iter, git_index_entry_cmp_icase, true) < 0)
				goto fail;
		} else if (!new_iter->ignore_case) {
			if (git_iterator_spoolandsort(&new_iter, new_iter, git_index_entry_cmp_icase, true) < 0)
				goto fail;
		}
	}

	if (git_iterator_current(old_iter, &oitem) < 0 ||
		git_iterator_current(new_iter, &nitem) < 0)
		goto fail;

	/* run iterators building diffs */
	while (oitem || nitem) {

		/* create DELETED records for old items not matched in new */
		if (oitem && (!nitem || entry_compare(oitem, nitem) < 0)) {
			if (diff_delta__from_one(diff, GIT_DELTA_DELETED, oitem) < 0)
				goto fail;

			/* if we are generating TYPECHANGE records then check for that
			 * instead of just generating a DELETE record
			 */
			if ((diff->opts.flags & GIT_DIFF_INCLUDE_TYPECHANGE_TREES) != 0 &&
				entry_is_prefixed(oitem, new_iter, nitem))
			{
				/* this entry has become a tree! convert to TYPECHANGE */
				git_diff_delta *last = diff_delta__last_for_item(diff, oitem);
				if (last) {
					last->status = GIT_DELTA_TYPECHANGE;
					last->new_file.mode = GIT_FILEMODE_TREE;
				}
			}

			if (git_iterator_advance(old_iter, &oitem) < 0)
				goto fail;
		}

		/* create ADDED, TRACKED, or IGNORED records for new items not
		 * matched in old (and/or descend into directories as needed)
		 */
		else if (nitem && (!oitem || entry_compare(oitem, nitem) > 0)) {
			git_delta_t delta_type = GIT_DELTA_UNTRACKED;

			/* check if contained in ignored parent directory */
			if (git_buf_len(&ignore_prefix) &&
				ITERATOR_PREFIXCMP(*old_iter, nitem->path,
					git_buf_cstr(&ignore_prefix)) == 0)
				delta_type = GIT_DELTA_IGNORED;

			if (S_ISDIR(nitem->mode)) {
				/* recurse into directory only if there are tracked items in
				 * it or if the user requested the contents of untracked
				 * directories and it is not under an ignored directory.
				 */
				bool contains_tracked =
					entry_is_prefixed(nitem, old_iter, oitem);
				bool recurse_untracked =
					(delta_type == GIT_DELTA_UNTRACKED &&
					 (diff->opts.flags & GIT_DIFF_RECURSE_UNTRACKED_DIRS) != 0);

				/* do not advance into directories that contain a .git file */
				if (!contains_tracked && recurse_untracked) {
					git_buf *full = NULL;
					if (git_iterator_current_workdir_path(new_iter, &full) < 0)
						goto fail;
					if (git_path_contains_dir(full, DOT_GIT))
						recurse_untracked = false;
				}

				if (contains_tracked || recurse_untracked) {
					/* if this directory is ignored, remember it as the
					 * "ignore_prefix" for processing contained items
					 */
					if (delta_type == GIT_DELTA_UNTRACKED &&
						git_iterator_current_is_ignored(new_iter))
						git_buf_sets(&ignore_prefix, nitem->path);

					if (git_iterator_advance_into_directory(new_iter, &nitem) < 0)
						goto fail;

					continue;
				}
			}

			/* In core git, the next two "else if" clauses are effectively
			 * reversed -- i.e. when an untracked file contained in an
			 * ignored directory is individually ignored, it shows up as an
			 * ignored file in the diff list, even though other untracked
			 * files in the same directory are skipped completely.
			 *
			 * To me, this is odd.  If the directory is ignored and the file
			 * is untracked, we should skip it consistently, regardless of
			 * whether it happens to match a pattern in the ignore file.
			 *
			 * To match the core git behavior, just reverse the following
			 * two "else if" cases so that individual file ignores are
			 * checked before container directory exclusions are used to
			 * skip the file.
			 */
			else if (delta_type == GIT_DELTA_IGNORED) {
				if (git_iterator_advance(new_iter, &nitem) < 0)
					goto fail;
				continue; /* ignored parent directory, so skip completely */
			}

			else if (git_iterator_current_is_ignored(new_iter))
				delta_type = GIT_DELTA_IGNORED;

			else if (new_iter->type != GIT_ITERATOR_WORKDIR)
				delta_type = GIT_DELTA_ADDED;

			if (diff_delta__from_one(diff, delta_type, nitem) < 0)
				goto fail;

			/* if we are generating TYPECHANGE records then check for that
			 * instead of just generating an ADD/UNTRACKED record
			 */
			if (delta_type != GIT_DELTA_IGNORED &&
				(diff->opts.flags & GIT_DIFF_INCLUDE_TYPECHANGE_TREES) != 0 &&
				entry_is_prefixed(nitem, old_iter, oitem))
			{
				/* this entry was a tree! convert to TYPECHANGE */
				git_diff_delta *last = diff_delta__last_for_item(diff, oitem);
				if (last) {
					last->status = GIT_DELTA_TYPECHANGE;
					last->old_file.mode = GIT_FILEMODE_TREE;
				}
			}

			if (git_iterator_advance(new_iter, &nitem) < 0)
				goto fail;
		}

		/* otherwise item paths match, so create MODIFIED record
		 * (or ADDED and DELETED pair if type changed)
		 */
		else {
			assert(oitem && nitem && entry_compare(oitem, nitem) == 0);

			if (maybe_modified(old_iter, oitem, new_iter, nitem, diff) < 0 ||
				git_iterator_advance(old_iter, &oitem) < 0 ||
				git_iterator_advance(new_iter, &nitem) < 0)
				goto fail;
		}
	}

	git_iterator_free(old_iter);
	git_iterator_free(new_iter);
	git_buf_free(&ignore_prefix);

	*diff_ptr = diff;
	return 0;

fail:
	git_iterator_free(old_iter);
	git_iterator_free(new_iter);
	git_buf_free(&ignore_prefix);

	git_diff_list_free(diff);
	*diff_ptr = NULL;
	return -1;
}


int git_diff_tree_to_tree(
	git_repository *repo,
	const git_diff_options *opts, /**< can be NULL for defaults */
	git_tree *old_tree,
	git_tree *new_tree,
	git_diff_list **diff)
{
	git_iterator *a = NULL, *b = NULL;
	char *prefix = opts ? diff_prefix_from_pathspec(&opts->pathspec) : NULL;

	assert(repo && old_tree && new_tree && diff);

	if (git_iterator_for_tree_range(&a, repo, old_tree, prefix, prefix) < 0 ||
		git_iterator_for_tree_range(&b, repo, new_tree, prefix, prefix) < 0)
		return -1;

	git__free(prefix);

	return diff_from_iterators(repo, opts, a, b, diff);
}

int git_diff_index_to_tree(
	git_repository *repo,
	const git_diff_options *opts,
	git_tree *old_tree,
	git_diff_list **diff)
{
	git_iterator *a = NULL, *b = NULL;
	char *prefix = opts ? diff_prefix_from_pathspec(&opts->pathspec) : NULL;

	assert(repo && diff);

	if (git_iterator_for_tree_range(&a, repo, old_tree, prefix, prefix) < 0 ||
	    git_iterator_for_index_range(&b, repo, prefix, prefix) < 0)
		goto on_error;

	git__free(prefix);

	return diff_from_iterators(repo, opts, a, b, diff);

on_error:
	git__free(prefix);
	git_iterator_free(a);
	return -1;
}

int git_diff_workdir_to_index(
	git_repository *repo,
	const git_diff_options *opts,
	git_diff_list **diff)
{
	git_iterator *a = NULL, *b = NULL;
	int error;

	char *prefix = opts ? diff_prefix_from_pathspec(&opts->pathspec) : NULL;

	assert(repo && diff);

	if ((error = git_iterator_for_index_range(&a, repo, prefix, prefix)) < 0 ||
	    (error = git_iterator_for_workdir_range(&b, repo, prefix, prefix)) < 0)
		goto on_error;

	git__free(prefix);

	return diff_from_iterators(repo, opts, a, b, diff);

on_error:
	git__free(prefix);
	git_iterator_free(a);
	return error;
}


int git_diff_workdir_to_tree(
	git_repository *repo,
	const git_diff_options *opts,
	git_tree *old_tree,
	git_diff_list **diff)
{
	git_iterator *a = NULL, *b = NULL;
	int error;

	char *prefix = opts ? diff_prefix_from_pathspec(&opts->pathspec) : NULL;

	assert(repo && old_tree && diff);

	if ((error = git_iterator_for_tree_range(&a, repo, old_tree, prefix, prefix)) < 0 ||
	    (error = git_iterator_for_workdir_range(&b, repo, prefix, prefix)) < 0)
		goto on_error;

	git__free(prefix);

	return diff_from_iterators(repo, opts, a, b, diff);

on_error:
	git__free(prefix);
	git_iterator_free(a);
	return error;
}


bool git_diff_delta__should_skip(
	const git_diff_options *opts, const git_diff_delta *delta)
{
	uint32_t flags = opts ? opts->flags : 0;

	if (delta->status == GIT_DELTA_UNMODIFIED &&
		(flags & GIT_DIFF_INCLUDE_UNMODIFIED) == 0)
		return true;

	if (delta->status == GIT_DELTA_IGNORED &&
		(flags & GIT_DIFF_INCLUDE_IGNORED) == 0)
		return true;

	if (delta->status == GIT_DELTA_UNTRACKED &&
		(flags & GIT_DIFF_INCLUDE_UNTRACKED) == 0)
		return true;

	return false;
}


int git_diff_merge(
	git_diff_list *onto,
	const git_diff_list *from)
{
	int error = 0;
	git_pool onto_pool;
	git_vector onto_new;
	git_diff_delta *delta;
	bool ignore_case = false;
	unsigned int i, j;

	assert(onto && from);

	if (!from->deltas.length)
		return 0;

	if (git_vector_init(&onto_new, onto->deltas.length, diff_delta__cmp) < 0 ||
		git_pool_init(&onto_pool, 1, 0) < 0)
		return -1;

	if ((onto->opts.flags & GIT_DIFF_DELTAS_ARE_ICASE) != 0 ||
		(from->opts.flags & GIT_DIFF_DELTAS_ARE_ICASE) != 0)
	{
		ignore_case = true;

		/* This function currently only supports merging diff lists that
		 * are sorted identically. */
		assert((onto->opts.flags & GIT_DIFF_DELTAS_ARE_ICASE) != 0 &&
				(from->opts.flags & GIT_DIFF_DELTAS_ARE_ICASE) != 0);
	}

	for (i = 0, j = 0; i < onto->deltas.length || j < from->deltas.length; ) {
		git_diff_delta *o = GIT_VECTOR_GET(&onto->deltas, i);
		const git_diff_delta *f = GIT_VECTOR_GET(&from->deltas, j);
		int cmp = !f ? -1 : !o ? 1 : STRCMP_CASESELECT(ignore_case, o->old_file.path, f->old_file.path);

		if (cmp < 0) {
			delta = diff_delta__dup(o, &onto_pool);
			i++;
		} else if (cmp > 0) {
			delta = diff_delta__dup(f, &onto_pool);
			j++;
		} else {
			delta = diff_delta__merge_like_cgit(o, f, &onto_pool);
			i++;
			j++;
		}

		/* the ignore rules for the target may not match the source
		 * or the result of a merged delta could be skippable...
		 */
		if (git_diff_delta__should_skip(&onto->opts, delta)) {
			git__free(delta);
			continue;
		}

		if ((error = !delta ? -1 : git_vector_insert(&onto_new, delta)) < 0)
			break;
	}

	if (!error) {
		git_vector_swap(&onto->deltas, &onto_new);
		git_pool_swap(&onto->pool, &onto_pool);
		onto->new_src = from->new_src;

		/* prefix strings also come from old pool, so recreate those.*/
		onto->opts.old_prefix =
			git_pool_strdup_safe(&onto->pool, onto->opts.old_prefix);
		onto->opts.new_prefix =
			git_pool_strdup_safe(&onto->pool, onto->opts.new_prefix);
	}

	git_vector_foreach(&onto_new, i, delta)
		git__free(delta);
	git_vector_free(&onto_new);
	git_pool_clear(&onto_pool);

	return error;
}
