// SPDX-License-Identifier: GPL-2.0
/*
 * Android 15 / 6.6: game affinity policy.
 * - New threads in the target UID get a one-time default mask from fork hook.
 * - sched_setaffinity requests for the target UID are short-circuited by the
 *   Android vendor hook; a work item applies our selected mask outside hook
 *   context.
 * - task_rename tracepoint handles thread names assigned after clone.
 *
 * Tracepoints are resolved at runtime via for_each_kernel_tracepoint() to
 * avoid referencing non-exported __tracepoint_* symbols on GKI kernels.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/cpumask.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/tracepoint.h>
#include <linux/ftrace.h>
#include <trace/hooks/sched.h>

#define GAME_PKG "com.tencent.ig"

static uid_t g_game_uid = (uid_t)-1;
static unsigned long (*set_cpus_allowed_ptr_sym)(struct task_struct *,
                                                const struct cpumask *);
static struct workqueue_struct *affinity_wq;

static bool fork_trace_registered;
static bool affinity_hook_registered;
static bool rename_trace_registered;

static struct tracepoint *tp_fork;
static struct tracepoint *tp_rename;

/* Older Android kernels do not export kallsyms_lookup_name to modules. */
static unsigned long (*kallsyms_lookup_name_sym)(const char *name);
static int dummy_pre(struct kprobe *p, struct pt_regs *regs) { return 0; }
static unsigned long get_kallsyms_addr(void)
{
    struct kprobe probe = { .pre_handler = dummy_pre,
                            .symbol_name = "kallsyms_lookup_name" };
    unsigned long addr;
    if (register_kprobe(&probe))
        return 0;
    addr = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}
static unsigned long my_kallsyms_lookup(const char *name)
{
    if (!kallsyms_lookup_name_sym)
        kallsyms_lookup_name_sym = (void *)get_kallsyms_addr();
    if (!kallsyms_lookup_name_sym)
        return 0;
    return kallsyms_lookup_name_sym(name);
}

struct thread_rule { const char *name; cpumask_t mask; };
static struct thread_rule rules[] = {
    { "UEGameThread",    { .bits = { 0xF0 } } },
    { "RHIThread",       { .bits = { 0xF0 } } },
    { "RenderThread",    { .bits = { 0xF0 } } },
    { "TaskGraphNP",     { .bits = { 0xF0 } } },
    { "mali-event-hand", { .bits = { 0xF0 } } },
    { "mali-cpu-comman", { .bits = { 0xF0 } } },
    { "NativeThread",    { .bits = { 0xF0 } } },
};
static const cpumask_t default_mask = { .bits = { 0x7F } };

static struct thread_rule *pick_rule(const char *comm)
{
    struct thread_rule *best = NULL;
    size_t best_len = 0;
    int i;

    for (i = 0; i < ARRAY_SIZE(rules); i++) {
        size_t len = strlen(rules[i].name);
        if (strncmp(comm, rules[i].name, len) == 0 && len > best_len) {
            best = &rules[i];
            best_len = len;
        }
    }
    return best;
}

static const struct cpumask *mask_for_task(struct task_struct *p)
{
    struct thread_rule *r = pick_rule(p->comm);
    return r ? &r->mask : &default_mask;
}

static uid_t resolve_pkg_uid(const char *pkg)
{
    char path[256];
    struct path p;
    uid_t uid = (uid_t)-1;

    snprintf(path, sizeof(path), "/data/data/%s", pkg);
    if (kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
        uid = __kuid_val(d_inode(p.dentry)->i_uid);
        path_put(&p);
    }
    return uid;
}

static int call_set_affinity(struct task_struct *p, const struct cpumask *mask) __nocfi
{
    return set_cpus_allowed_ptr_sym(p, mask);
}

struct affinity_work {
    struct work_struct work;
    struct task_struct *task;
    cpumask_t mask;
};

static void affinity_work_fn(struct work_struct *work)
{
    struct affinity_work *aw = container_of(work, struct affinity_work, work);
    int ret;

    ret = call_set_affinity(aw->task, &aw->mask);
    if (ret)
        pr_warn("cpuset_hook_v3: set affinity pid=%d comm=%s ret=%d\n",
                aw->task->pid, aw->task->comm, ret);
    put_task_struct(aw->task);
    kfree(aw);
}

/*
 * 不去重、不限流：每次调用都 queue 一个 work。
 * 实际 set_cpus_allowed_ptr 内部会判断掩码是否变化，没变快速返回。
 * 掩码先和 cpu_online_mask 取交集，避免 CPU 下线时 0x7F 被裁成 0x70
 * 后反复 queue。
 */
static void queue_affinity(struct task_struct *p, const struct cpumask *mask,
                           gfp_t gfp)
{
    struct affinity_work *aw;
    cpumask_t effective;

    cpumask_and(&effective, mask, cpu_online_mask);

    aw = kmalloc(sizeof(*aw), gfp);
    if (!aw)
        return;
    INIT_WORK(&aw->work, affinity_work_fn);
    get_task_struct(p);
    aw->task = p;
    cpumask_copy(&aw->mask, &effective);
    if (!queue_work(affinity_wq, &aw->work)) {
        put_task_struct(p);
        kfree(aw);
    }
}

/* Runs for each cloned task. At this point comm can still be inherited. */
static void on_sched_process_fork(void *ignore, struct task_struct *parent,
                                  struct task_struct *child)
{
    const struct cred *cred;
    uid_t uid;

    rcu_read_lock();
    cred = __task_cred(child);
    uid = __kuid_val(cred->uid);
    rcu_read_unlock();
    if (uid != g_game_uid)
        return;

    queue_affinity(child, mask_for_task(child), GFP_ATOMIC);
}

/* Thread names are commonly assigned after clone; apply the named rule then. */
static void on_task_rename(void *ignore, struct task_struct *p,
                           const char *newcomm)
{
    const struct cred *cred;
    uid_t uid;
    struct thread_rule *r;

    rcu_read_lock();
    cred = __task_cred(p);
    uid = __kuid_val(cred->uid);
    rcu_read_unlock();
    if (uid != g_game_uid)
        return;

    r = pick_rule(newcomm);
    queue_affinity(p, r ? &r->mask : &default_mask, GFP_ATOMIC);
}

/* Android 15-6.6 hook: bool *skip; true returns success without changing mask. */
static void on_sched_setaffinity_early(void *ignore, struct task_struct *p,
                                       const struct cpumask *new_mask,
                                       bool *skip)
{
    const struct cred *cred;
    uid_t uid;
    const struct cpumask *wanted;

    rcu_read_lock();
    cred = __task_cred(p);
    uid = __kuid_val(cred->uid);
    rcu_read_unlock();
    if (uid != g_game_uid)
        return;

    wanted = mask_for_task(p);
    /* Never let the game's requested mask replace the enforced policy. */
    *skip = true;
    queue_affinity(p, wanted, GFP_ATOMIC);
}

struct tp_find_ctx {
    const char *name;
    struct tracepoint **out;
};

static void tp_find_cb(struct tracepoint *tp, void *priv)
{
    struct tp_find_ctx *ctx = priv;

    if (ctx->out && !*ctx->out && tp->name &&
        !strcmp(tp->name, ctx->name))
        *ctx->out = tp;
}

static struct tracepoint *find_tracepoint(const char *name)
{
    struct tracepoint *tp = NULL;
    struct tp_find_ctx ctx = { .name = name, .out = &tp };

    for_each_kernel_tracepoint(tp_find_cb, &ctx);
    return tp;
}

static int __init cpuset_hook_init(void)
{
    unsigned long addr;
    int ret;

    addr = my_kallsyms_lookup("set_cpus_allowed_ptr");
    if (!addr) {
        pr_err("cpuset_hook_v3: set_cpus_allowed_ptr not found\n");
        return -ENXIO;
    }
    set_cpus_allowed_ptr_sym = (void *)addr;

    g_game_uid = resolve_pkg_uid(GAME_PKG);
    if (g_game_uid == (uid_t)-1) {
        pr_err("cpuset_hook_v3: cannot resolve UID for %s\n", GAME_PKG);
        return -ENOENT;
    }

    affinity_wq = alloc_workqueue("cpuset_hook_wq", 0, 0);
    if (!affinity_wq) {
        pr_err("cpuset_hook_v3: alloc_workqueue failed\n");
        return -ENOMEM;
    }

    /* Resolve and register sched_process_fork tracepoint at runtime. */
    tp_fork = find_tracepoint("sched_process_fork");
    if (!tp_fork) {
        pr_err("cpuset_hook_v3: sched_process_fork tracepoint not found\n");
        ret = -ENOENT;
        goto err_destroy_wq;
    }
    ret = tracepoint_probe_register(tp_fork, on_sched_process_fork, NULL);
    if (ret) {
        pr_err("cpuset_hook_v3: register sched_process_fork failed: %d\n", ret);
        goto err_destroy_wq;
    }
    fork_trace_registered = true;

    /* Android vendor hook for sched_setaffinity_early. */
    ret = register_trace_android_vh_sched_setaffinity_early(
              on_sched_setaffinity_early, NULL);
    if (ret) {
        pr_err("cpuset_hook_v3: register affinity hook failed: %d\n", ret);
        goto err_unreg_fork;
    }
    affinity_hook_registered = true;

    /* Resolve and register task_rename tracepoint at runtime. */
    tp_rename = find_tracepoint("task_rename");
    if (!tp_rename) {
        pr_err("cpuset_hook_v3: task_rename tracepoint not found\n");
        ret = -ENOENT;
        goto err_unreg_affinity;
    }
    ret = tracepoint_probe_register(tp_rename, on_task_rename, NULL);
    if (ret) {
        pr_err("cpuset_hook_v3: register task_rename failed: %d\n", ret);
        goto err_unreg_affinity;
    }
    rename_trace_registered = true;

    pr_info("cpuset_hook_v3: loaded package=%s uid=%u default=0x7f special=0xf0\n",
            GAME_PKG, g_game_uid);
    return 0;

err_unreg_affinity:
    unregister_trace_android_vh_sched_setaffinity_early(
        on_sched_setaffinity_early, NULL);
    affinity_hook_registered = false;
err_unreg_fork:
    tracepoint_probe_unregister(tp_fork, on_sched_process_fork, NULL);
    fork_trace_registered = false;
err_destroy_wq:
    destroy_workqueue(affinity_wq);
    affinity_wq = NULL;
    return ret;
}

static void __exit cpuset_hook_exit(void)
{
    if (rename_trace_registered && tp_rename)
        tracepoint_probe_unregister(tp_rename, on_task_rename, NULL);
    rename_trace_registered = false;

    if (affinity_hook_registered)
        unregister_trace_android_vh_sched_setaffinity_early(
            on_sched_setaffinity_early, NULL);
    affinity_hook_registered = false;

    if (fork_trace_registered && tp_fork)
        tracepoint_probe_unregister(tp_fork, on_sched_process_fork, NULL);
    fork_trace_registered = false;

    if (affinity_wq) {
        destroy_workqueue(affinity_wq);
        affinity_wq = NULL;
    }
    pr_info("cpuset_hook_v3: unloaded\n");
}

module_init(cpuset_hook_init);
module_exit(cpuset_hook_exit);
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_DESCRIPTION("Android game CPU affinity policy via vendor hook");
