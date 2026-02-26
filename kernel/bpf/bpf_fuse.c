// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Google LLC
//
// Improved BPF verifier hooks for FUSE -- safer bounds checking and clearer logic.

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/fuse.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/ptrace.h>
#include <linux/compiler.h>

/* Forward declarations of helper prototypes (provided by BPF core) */
extern const struct bpf_func_proto *bpf_get_trace_printk_proto(void);
extern const struct bpf_func_proto bpf_get_current_uid_gid_proto;
extern const struct bpf_func_proto bpf_get_current_pid_tgid_proto;
extern const struct bpf_func_proto bpf_map_lookup_elem_proto;
extern const struct bpf_func_proto bpf_map_update_elem_proto;

/* Return function prototypes allowed for FUSE BPF programs */
static const struct bpf_func_proto *
fuse_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
    switch (func_id) {
    case BPF_FUNC_trace_printk:
        return bpf_get_trace_printk_proto();

    case BPF_FUNC_get_current_uid_gid:
        return &bpf_get_current_uid_gid_proto;

    case BPF_FUNC_get_current_pid_tgid:
        return &bpf_get_current_pid_tgid_proto;

    case BPF_FUNC_map_lookup_elem:
        return &bpf_map_lookup_elem_proto;

    case BPF_FUNC_map_update_elem:
        return &bpf_map_update_elem_proto;

    default:
        pr_debug("fuse: invalid bpf func %d\n", func_id);
        return NULL;
    }
}

/*
 * Validate access to fields inside struct fuse_bpf_args.
 *
 * - `off` is byte offset from start of struct fuse_bpf_args
 * - `size` is requested access size (bytes)
 * - `type` is BPF_READ or BPF_WRITE
 *
 * We allow:
 * - read-only access to the in_args[i].value buffers
 * - read/write (rw) access to out_args[i].value buffers
 *
 * This implementation computes offsets/element sizes dynamically
 * (so it survives small layout changes) and performs strict bounds checks.
 */
static bool fuse_prog_is_valid_access(int off, int size,
                                      enum bpf_access_type type,
                                      const struct bpf_prog *prog,
                                      struct bpf_insn_access_aux *info)
{
    size_t struct_size = sizeof(struct fuse_bpf_args);

    /* Basic bounds check: requested range must be inside the struct */
    if (off < 0 || size <= 0)
        return false;
    if ((size_t)off + (size_t)size > struct_size)
        return false;

    /* compute in_args and out_args metadata using typeof() to be robust */
    size_t in_base = offsetof(struct fuse_bpf_args, in_args);
    size_t out_base = offsetof(struct fuse_bpf_args, out_args);

    size_t in_elem_size = sizeof(((struct fuse_bpf_args *)0)->in_args[0]);
    size_t out_elem_size = sizeof(((struct fuse_bpf_args *)0)->out_args[0]);

    size_t in_count = 0, out_count = 0;

    /* Safely compute element counts (avoid division by zero) */
    if (in_elem_size)
        in_count = sizeof(((struct fuse_bpf_args *)0)->in_args) / in_elem_size;
    if (out_elem_size)
        out_count = sizeof(((struct fuse_bpf_args *)0)->out_args) / out_elem_size;

    /* compute offset of the 'value' member inside an in_args/out_args element */
    /* This uses typeof(...) which is common in kernel code */
    size_t in_value_off_in_elem = offsetof(typeof(((struct fuse_bpf_args *)0)->in_args[0]), value);
    size_t out_value_off_in_elem = offsetof(typeof(((struct fuse_bpf_args *)0)->out_args[0]), value);

    size_t i;
    /* Check each in_args[i].value region: allow READ only */
    for (i = 0; i < in_count; i++) {
        size_t elem_value_off = in_base + i * in_elem_size + in_value_off_in_elem;
        size_t elem_value_end = elem_value_off + /* assume buffer size fits in element */ in_elem_size - in_value_off_in_elem;

        if ((size_t)off >= elem_value_off && (size_t)off + (size_t)size <= elem_value_end) {
            /* Access targets in_args[i].value */
            if (type != BPF_READ)
                return false; /* writes to input buffers are not allowed */
            info->reg_type = PTR_TO_RDONLY_BUF;
            /* ctx_field_size tells verifier how big the readable region is */
            info->ctx_field_size = (u32)(elem_value_end - elem_value_off);
            return true;
        }
    }

    /* Check each out_args[i].value region: allow READ and WRITE */
    for (i = 0; i < out_count; i++) {
        size_t elem_value_off = out_base + i * out_elem_size + out_value_off_in_elem;
        size_t elem_value_end = elem_value_off + out_elem_size - out_value_off_in_elem;

        if ((size_t)off >= elem_value_off && (size_t)off + (size_t)size <= elem_value_end) {
            /* Access targets out_args[i].value */
            info->reg_type = PTR_TO_RDWR_BUF;
            info->ctx_field_size = (u32)(elem_value_end - elem_value_off);
            return true;
        }
    }

    /* For any other field inside the struct: allow read-only accesses only */
    if (type != BPF_READ)
        return false;

    /* generic read: allow but no pointer semantics */
    return true;
}

const struct bpf_verifier_ops fuse_verifier_ops = {
    .get_func_proto  = fuse_prog_func_proto,
    .is_valid_access = fuse_prog_is_valid_access,
};

/* empty prog ops (kept for completeness / future extension) */
const struct bpf_prog_ops fuse_prog_ops = {
};