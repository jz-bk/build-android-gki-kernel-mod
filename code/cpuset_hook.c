// SPDX-License-Identifier: GPL-2.0
/*
 * Android 15 / 6.6: game affinity policy.
 * - New threads in the target UID get a one-time default mask from fork hook.
 * - sched_setaffinity requests for the target UID are short-circuited by the
 *   Android vendor hook; a work item applies our selected mask outside hook
 *   context. No kprobe register patching and no recurring polling.
 *
 * The task_rename tracepoint handles thread names assigned after clone.
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
#include <trace/hooks/sched.h>
#include <trace/events/sched.h>
#include <trace/events/task.h>

#define GAME_PKG "com.tencent.ig"

static uid_t g_game_uid = (uid_t)-1;
static unsigned long (*set_cpus_allowed_ptr_sym)(struct task_struct *,
                                                const struct cpumask *);
static bool fork_trace_registered;
static bool affinity_hook_registered;
static bool rename_trace_registered;

static struct workqueue_struct *affinity_wq;

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
        pr_warn("cpuset_hook_v2: set affinity pid=%d comm=%s ret=%d\n",
                aw->task->pid, aw->task->comm, ret);
    put_task_struct(aw->task);
    kfree(aw);
}

static void queue_affinity(struct task_struct *p, const struct cpumask *mask,
                           gfp_t gfp)
{
    struct affinity_work *aw;

    if (cpumask_equal(&p->cpus_mask, mask))
        return;
    aw = kmalloc(sizeof(*aw), gfp);
    if (!aw)
        return;
    INIT_WORK(&aw->work, affinity_work_fn);
    get_task_struct(p);
    aw->task = p;
    cpumask_copy(&aw->mask, mask);
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

    /* Initial per-thread binding. task_rename corrects named rules later. */
    queue_affinity(child, &default_mask, GFP_ATOMIC);
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

static int __init cpuset_hook_init(void)
{
    unsigned long addr;
    int ret;

    /* Resolve the internal scheduler helper through kallsyms lookup exposed
     * by this build's existing DDK environment. */
    addr = my_kallsyms_lookup("set_cpus_allowed_ptr");
    if (!addr) {
        pr_err("cpuset_hook_v2: set_cpus_allowed_ptr not found\n");
        return -ENXIO;
    }
    set_cpus_allowed_ptr_sym = (void *)addr;

    g_game_uid = resolve_pkg_uid(GAME_PKG);
    if (g_game_uid == (uid_t)-1) {
        pr_err("cpuset_hook_v2: cannot resolve UID for %s\n", GAME_PKG);
        return -ENOENT;
    }

    /* 创建私有工作队列，放在注册 trace 之前 */
    affinity_wq = alloc_workqueue("cpuset_hook_wq", 0, 0);
    if (!affinity_wq) {
        pr_err("cpuset_hook_v2: alloc_workqueue failed\n");
        return -ENOMEM;
    }
  
    ret = register_trace_sched_process_fork(on_sched_process_fork, NULL);
    if (ret) {
        pr_err("cpuset_hook_v2: register sched_process_fork failed: %d\n", ret);
        return ret;
    }
    fork_trace_registered = true;

    ret = register_trace_android_vh_sched_setaffinity_early(
              on_sched_setaffinity_early, NULL);
    if (ret) {
        pr_err("cpuset_hook_v2: register affinity hook failed: %d\n", ret);
        unregister_trace_sched_process_fork(on_sched_process_fork, NULL);
        fork_trace_registered = false;
        return ret;
    }
    affinity_hook_registered = true;

    ret = register_trace_task_rename(on_task_rename, NULL);
    if (ret) {
        pr_err("cpuset_hook_v2: register task_rename failed: %d\n", ret);
        unregister_trace_android_vh_sched_setaffinity_early(
            on_sched_setaffinity_early, NULL);
        affinity_hook_registered = false;
        unregister_trace_sched_process_fork(on_sched_process_fork, NULL);
        fork_trace_registered = false;
        return ret;
    }
    rename_trace_registered = true;

    pr_info("cpuset_hook_v2: loaded package=%s uid=%u default=0x7f special=0xf0\n",
            GAME_PKG, g_game_uid);
    return 0;
}

static void __exit cpuset_hook_exit(void)
{
    if (rename_trace_registered)
        unregister_trace_task_rename(on_task_rename, NULL);
    if (affinity_hook_registered)
        unregister_trace_android_vh_sched_setaffinity_early(
            on_sched_setaffinity_early, NULL);
    if (fork_trace_registered)
        unregister_trace_sched_process_fork(on_sched_process_fork, NULL);

    if (affinity_wq) {
        destroy_workqueue(affinity_wq);   /* 内部会 flush 并等待所有已排队工作完成 */
        affinity_wq = NULL;
    }
    pr_info("cpuset_hook_v2: unloaded\n");
}

module_init(cpuset_hook_init);
module_exit(cpuset_hook_exit);
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_DESCRIPTION("Android game CPU affinity policy via vendor hook");
