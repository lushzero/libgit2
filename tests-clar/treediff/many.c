#include "clar_libgit2.h"
#include "git2/diff_tree.h"
#include "git2/tree.h"
#include "diff_tree.h"

static git_repository *repo;

#define TEST_REPO_PATH "merge-resolve"

#define TREE_OID_ANCESTOR	"0d52e3a556e189ba0948ae56780918011c1b167d"
#define TREE_OID_ONE		"1f81433e3161efbf250576c58fede7f6b836f3d3"
#define TREE_OID_TWO		"eea9286df54245fea72c5b557291470eb825f38f"

#define TREE_OID_OCTO1      "62269111c3b02a9355badcb9da8678b1bf41787b"
#define TREE_OID_OCTO2      "d2f8637f2eab2507a1e13cbc9df4729ec386627e"
#define TREE_OID_OCTO3      "c5bbe550b9f09444bdddd3ecf3d97c0b42aa786c"
#define TREE_OID_OCTO4      "3bbf0bf59b20df5d5fc58b9fc1dc07be637c301f"
#define TREE_OID_OCTO5      "5eb7bb6a146eb3c7fd3990b240a2308eceb1cf8d"
#define TREE_OID_OCTO6      "2490b9f1a079420870027deefb49f51d6656cf74"

void test_treediff_many__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
}

void test_treediff_many__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

struct treediff_file_data {
    uint16_t mode;
    char path[128];
    char oid_str[41];
};

struct treediff_data {
    size_t trees_len;
    struct treediff_file_data *file_data;
    size_t file_data_len;
    
    size_t seen;
};

static int treediff_cb(const git_index_entry **tree_items, void *payload)
{
    struct treediff_data *treediff_data = payload;
    git_oid oid;
    size_t idx, i;
    
    idx = treediff_data->seen * treediff_data->trees_len;
    
    for (i = 0; i < treediff_data->trees_len; i++) {
        if (treediff_data->file_data[idx+i].mode == 0) {
            if (tree_items[i] != NULL)
                return -1;
        } else {
            cl_git_pass(git_oid_fromstr(&oid, treediff_data->file_data[idx+i].oid_str));

            if (strcmp(treediff_data->file_data[idx+i].path, tree_items[i]->path) != 0 ||
                git_oid_cmp(&oid, &tree_items[i]->oid) != 0)
                return -1;
        }
    }
    
    ++treediff_data->seen;
    
    return 0;
}

static int treediff(
    const char **tree_oid_strs,
    struct treediff_data *treediff_data,
	uint32_t flags)
{
    git_oid *oids;
    git_tree **trees;
    size_t i;
    
    cl_assert(oids = git__calloc(treediff_data->trees_len, sizeof(git_oid)));
    cl_assert(trees = git__calloc(treediff_data->trees_len, sizeof(git_tree *)));
    
    for (i = 0; i < treediff_data->trees_len; i++) {
        cl_git_pass(git_oid_fromstr(&oids[i], tree_oid_strs[i]));
        cl_git_pass(git_tree_lookup(&trees[i], repo, &oids[i]));
    }
    
    cl_git_pass(git_diff_tree_many(repo, (const git_tree **)trees, treediff_data->trees_len, flags, treediff_cb, treediff_data));
    
    cl_assert(treediff_data->seen == treediff_data->file_data_len);

    for (i = 0; i < treediff_data->trees_len; i++)
        git_object_free((git_object *)trees[i]);
    
    git__free(trees);
    git__free(oids);
    
    return 0;
}

void test_treediff_many__two_trees(void)
{
    const char *tree_oid_strs[] = { TREE_OID_ONE, TREE_OID_TWO };
	uint32_t flags = 0;
    struct treediff_data treediff_data;

    struct treediff_file_data treediff_file_data[] = {
        { 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487" },
        { 0, "", "" },
        
        { 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf" },
        { 0100644, "automergeable.txt", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe" },
        
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-branch.txt", "4eb04c9e79e88f6640d01ff5b25ca2a60764f216" },
        
        { 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2" },
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        
        { 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10" },
        { 0100644, "conflicting.txt", "2bd0a343aeef7a2cf0d158478966a6e587ff3863" },
        
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd" },
        { 0, "", "" },
        
        { 0, "", "" },
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
    };

    memset(&treediff_data, 0x0, sizeof(treediff_data));
    treediff_data.trees_len = 2;
    treediff_data.file_data = treediff_file_data;
    treediff_data.file_data_len = 7;

    cl_git_pass(treediff(tree_oid_strs, &treediff_data, flags));
}

void test_treediff_many__two_trees_unmodified(void)
{
    const char *tree_oid_strs[] = { TREE_OID_ONE, TREE_OID_TWO };
    uint32_t flags = GIT_DIFF_TREE_RETURN_UNMODIFIED;
    struct treediff_data treediff_data;

    struct treediff_file_data treediff_file_data[] = {
        { 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487" },
        { 0, "", "" },
        
        { 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf" },
        { 0100644, "automergeable.txt", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe" },
        
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-branch.txt", "4eb04c9e79e88f6640d01ff5b25ca2a60764f216" },
        
        { 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2" },
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        
        { 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10" },
        { 0100644, "conflicting.txt", "2bd0a343aeef7a2cf0d158478966a6e587ff3863" },
        
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd" },
        { 0, "", "" },
        
        { 0, "", "" },
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
        
        { 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d" },
        { 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d" },
    };
    
    memset(&treediff_data, 0x0, sizeof(treediff_data));
    treediff_data.trees_len = 2;
    treediff_data.file_data = treediff_file_data;
    treediff_data.file_data_len = 8;
    
    cl_git_pass(treediff(tree_oid_strs, &treediff_data, flags));
}

void test_treediff_many__three_trees(void)
{
    const char *tree_oid_strs[] = { TREE_OID_ANCESTOR, TREE_OID_ONE, TREE_OID_TWO };
	uint32_t flags = 0;
    struct treediff_data treediff_data;

    struct treediff_file_data treediff_file_data[] = {
        { 0, "", "" },
        { 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487" },
        { 0, "", "" },
        
        { 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b" },
        { 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf" },
        { 0100644, "automergeable.txt", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe" },
        
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-branch.txt", "4eb04c9e79e88f6640d01ff5b25ca2a60764f216" },
        
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2" },
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        
        { 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46" },
        { 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10" },
        { 0100644, "conflicting.txt", "2bd0a343aeef7a2cf0d158478966a6e587ff3863" },
        
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd" },
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd" },
        { 0, "", "" },
        
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
        { 0, "", "" },
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
    };
    
    memset(&treediff_data, 0x0, sizeof(treediff_data));
    treediff_data.trees_len = 3;
    treediff_data.file_data = treediff_file_data;
    treediff_data.file_data_len = 7;
    
    cl_git_pass(treediff(tree_oid_strs, &treediff_data, flags));
}

void test_treediff_many__three_trees_unmodified(void)
{
    const char *tree_oid_strs[] = { TREE_OID_ANCESTOR, TREE_OID_ONE, TREE_OID_TWO };
	uint32_t flags = GIT_DIFF_TREE_RETURN_UNMODIFIED;
    struct treediff_data treediff_data;
    
    struct treediff_file_data treediff_file_data[] = {
        { 0, "", "" },
        { 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487" },
        { 0, "", "" },
        
        { 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b" },
        { 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf" },
        { 0100644, "automergeable.txt", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe" },
        
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-branch.txt", "4eb04c9e79e88f6640d01ff5b25ca2a60764f216" },
        
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        { 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2" },
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b" },
        
        { 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46" },
        { 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10" },
        { 0100644, "conflicting.txt", "2bd0a343aeef7a2cf0d158478966a6e587ff3863" },
        
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd" },
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd" },
        { 0, "", "" },
        
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
        { 0, "", "" },
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5" },
        
        { 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d" },
        { 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d" },
        { 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d" },
    };
    
    memset(&treediff_data, 0x0, sizeof(treediff_data));
    treediff_data.trees_len = 3;
    treediff_data.file_data = treediff_file_data;
    treediff_data.file_data_len = 8;
    
    cl_git_pass(treediff(tree_oid_strs, &treediff_data, flags));
}

void test_treediff_many__six_trees(void)
{
    const char *tree_oid_strs[] = {
        TREE_OID_OCTO1, TREE_OID_OCTO2, TREE_OID_OCTO3,
        TREE_OID_OCTO4, TREE_OID_OCTO5, TREE_OID_OCTO6 };
	uint32_t flags = 0;
    struct treediff_data treediff_data;
    
    struct treediff_file_data treediff_file_data[] = {
        { 0100644, "new-in-octo1.txt", "84de84f8f3a6d63e636ee9ad81f4b80512fa9bbe" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },

        { 0, "", "" },
        { 0100644, "new-in-octo2.txt", "09055301463b7f2f8ee5d368f8ed5c0a40ad8515" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },

        { 0, "", "" },
        { 0, "", "" },
        { 0100644, "new-in-octo3.txt", "31d5472536041a83d986829240bbbdc897c6f8a6" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },

        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0100644, "new-in-octo4.txt", "f29e7fb590551095230c6149cbe72f2e9104a796" },
        { 0, "", "" },
        { 0, "", "" },

        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0100644, "new-in-octo5.txt", "3748859b001c6e627e712a07951aee40afd19b41" },
        { 0, "", "" },

        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0, "", "" },
        { 0100644, "new-in-octo6.txt", "da178208145ef585a1bd5ca5f4c9785d738df2cf" },
    };
    
    memset(&treediff_data, 0x0, sizeof(treediff_data));
    treediff_data.trees_len = 6;
    treediff_data.file_data = treediff_file_data;
    treediff_data.file_data_len = 6;
    
    cl_git_pass(treediff(tree_oid_strs, &treediff_data, flags));
}
