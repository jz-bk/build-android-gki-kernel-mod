#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/cpumask.h>
#include <linux/sched/task.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

#define GAME_PKG    "com.tencent.ig"

/* ---------------- kallsyms 查找 ---------------- */
static unsigned long (*kallsyms_lookup_name_sym)(const char *name);

static int dummy_pre(struct kprobe *p, struct pt_regs *regs) { return 0; }

static unsigned long get_kallsyms_addr(void)
{
    struct kprobe probe = {
        .pre_handler = dummy_pre,
        .symbol_name = "kallsyms_lookup_name",
    };
    unsigned long addr;

    if (register_kprobe(&probe))
        return 0;
    addr = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}

static unsigned long my_kallsyms_lookup(const char *name)
{
    if (!kallsyms_lookup_name_sym) {
        kallsyms_lookup_name_sym = (void *)get_kallsyms_addr();
        if (!kallsyms_lookup_name_sym)
            return 0;
    }
    return kallsyms_lookup_name_sym(name);
}

/* ---------------- 全局变量 ---------------- */
static unsigned long (*set_cpus_allowed_ptr_sym)(struct task_struct *,
                                                 const struct cpumask *);
static uid_t g_game_uid = (uid_t)-1;

static struct kprobe kp_setaffinity;

/* ---------------- 规则表 ---------------- */
struct thread_rule {
    const char *name;
    cpumask_t mask;
};

/* 4-7 -> 0xF0，0-6 -> 0x7F */
static struct thread_rule rules[] = {
    { "UEGameThread",    { .bits = { 0xF0 } } },
    { "RHIThread",       { .bits = { 0xF0 } } },
    { "RenderThread",    { .bits = { 0xF0 } } },
    { "TaskGraphNP",     { .bits = { 0xF0 } } },
    { "mali-event-hand", { .bits = { 0xF0 } } },
    { "mali-cpu-comman", { .bits = { 0xF0 } } },
    { "NativeThread",    { .bits = { 0xF0 } } },
};

static cpumask_t default_mask = { .bits = { 0x7F } };   /* 0-6 */

/* 最长前缀优先 */
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

/* ---------------- 包名 -> UID（init 阶段，可睡眠） ---------------- */
static uid_t resolve_pkg_uid(const char *pkg)
{
    char path[256];
    struct path p;
    uid_t uid = (uid_t)-1;

    snprintf(path, sizeof(path), "/data/data/%s", pkg);
    if (kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
        uid = __kuid_val(p.dentry->d_inode->i_uid);
        path_put(&p);
    }
    return uid;
}

/* ---------------- CFI 豁免的间接调用 ---------------- */
static int call_set_affinity(struct task_struct *t, const struct cpumask *m)
    __nocfi
{
    return set_cpus_allowed_ptr_sym(t, m);
}

/* ---------------- workqueue 异步绑核 ---------------- */
struct affinity_work {
    struct work_struct work;
    struct task_struct *task;
    cpumask_t mask;
};

static void affinity_work_fn(struct work_struct *work)
{
    struct affinity_work *aw = container_of(work, struct affinity_work, work);
    int ret;

    if (!aw->task)
        goto out;

    ret = call_set_affinity(aw->task, &aw->mask);
    if (ret)
        pr_err("cpuset_hook: work set affinity pid=%d ret=%d\n",
               aw->task->pid, ret);

    put_task_struct(aw->task);

out:
    kfree(aw);
}

/* ---------------- sched_setaffinity 拦截 ---------------- */
static int setaffinity_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct cred *cred;
    uid_t uid;
    struct thread_rule *r;
    const struct cpumask *mask;
    struct affinity_work *aw;
    cpumask_t curr;

    rcu_read_lock();
    cred = (struct cred *)__task_cred(current);
    uid = __kuid_val(cred->uid);
    rcu_read_unlock();

    if (uid != g_game_uid)
        return 0;

    r = pick_rule(current->comm);
    mask = r ? &r->mask : &default_mask;

    /* 已经是目标掩码，直接跳过，不碰调度器 */
    if (cpumask_equal(&current->cpus_mask, mask)) {
        regs->regs[0] = 0;
        return 1;
    }

    /* 异步执行真正的绑核，避免在原子上下文操作 rq->lock */
    aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
    if (!aw) {
        regs->regs[0] = 0;
        return 1;
    }

    INIT_WORK(&aw->work, affinity_work_fn);
    get_task_struct(current);
    aw->task = current;
    aw->mask = *mask;
    schedule_work(&aw->work);

    /* 伪造成功返回，跳过原 sched_setaffinity */
    regs->regs[0] = 0;
    return 1;
}

/* ---------------- 模块入口 ---------------- */
static int __init cpuset_hook_init(void)
{
    unsigned long addr;

    addr = my_kallsyms_lookup("set_cpus_allowed_ptr");
    if (!addr) {
        pr_err("cpuset_hook: set_cpus_allowed_ptr not found\n");
        return -ENXIO;
    }
    set_cpus_allowed_ptr_sym = (void *)addr;
    pr_info("cpuset_hook: set_cpus_allowed_ptr @ %px\n", (void *)addr);

    g_game_uid = resolve_pkg_uid(GAME_PKG);
    if (g_game_uid == (uid_t)-1) {
        pr_err("cpuset_hook: cannot resolve UID for %s\n", GAME_PKG);
        return -ENOENT;
    }
    pr_info("cpuset_hook: %s -> uid=%d\n", GAME_PKG, g_game_uid);

    kp_setaffinity.symbol_name = "sched_setaffinity";
    kp_setaffinity.pre_handler = setaffinity_handler;

    if (register_kprobe(&kp_setaffinity)) {
        pr_err("cpuset_hook: register_kprobe(sched_setaffinity) failed\n");
        return -ENXIO;
    }
    pr_info("cpuset_hook: sched_setaffinity hook registered\n");

    pr_info("cpuset_hook: loaded\n");
    return 0;
}

static void __exit cpuset_hook_exit(void)
{
    unregister_kprobe(&kp_setaffinity);
    flush_scheduled_work();
    pr_info("cpuset_hook: unloaded\n");
}

module_init(cpuset_hook_init);
module_exit(cpuset_hook_exit);

MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_DESCRIPTION("Hook sched_setaffinity to force affinity for game threads");
