#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/debugfs.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include "fsinfo.h"

struct fsinfo_item {
	struct list_head list;
	struct fsinfo_entry entry;
};

struct fsinfo_data {
	bool prot;
	struct dentry *dent;
	struct list_head items;
#ifdef MODULE
	unsigned long **sys_call_table;
	void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt,
				    phys_addr_t size, pgprot_t prot);
	asmlinkage long (*original_statfs)(const struct pt_regs *regs);
#endif
};

static struct fsinfo_data *fsinfo = NULL;

static void masked_copy(void *data, void *from, void *mask, size_t len)
{
	size_t i;
	u8 *xdata = (u8 *)data;
	u8 *xfrom = (u8 *)from;
	u8 *xmask = (u8 *)mask;
	for (i = 0; i < len; i++) {
		if (xmask[i])
			xdata[i] = xfrom[i];
	}
}

static int apply_statfs(struct fsinfo_item *item, struct statfs __user *buf)
{
	struct statfs stat, new_stat;
	if (!fsinfo)
		return 0;
	if (copy_from_user(&stat, buf, sizeof(stat)))
		return -EFAULT;
	memcpy(&new_stat, &stat, sizeof(stat));
	masked_copy(&new_stat, &item->entry.stat, &item->entry.mask,
		    sizeof(stat));
	if (item->entry.auto_bavail) {
		long bavail_diff = stat.f_blocks - stat.f_bavail;
		new_stat.f_bavail = new_stat.f_blocks - bavail_diff;
	}
	if (item->entry.auto_bfree) {
		long bfree_diff = stat.f_blocks - stat.f_bfree;
		new_stat.f_bfree = new_stat.f_blocks - bfree_diff;
	}
	if (copy_to_user(buf, &new_stat, sizeof(new_stat)))
		return -EFAULT;
	return 0;
}

int fsinfo_patch_statfs(const char __user *upath, struct statfs __user *buf)
{
	int ret;
	struct fsinfo_item *item;
	struct path path;
	char cpath[FSINFO_PATH_LEN], *dp;
	unsigned int lfl = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	if ((ret = user_path_at(AT_FDCWD, upath, lfl, &path)))
		return ret;
	memset(cpath, 0, sizeof(cpath));
	dp = d_path(&path, cpath, sizeof(cpath));
	path_put(&path);
	if (IS_ERR(dp))
		return PTR_ERR(dp);
	if (!dp[0])
		return -EINVAL;
	list_for_each_entry(item, &fsinfo->items, list) {
		if (strcmp(item->entry.path, dp) != 0)
			continue;
		return apply_statfs(item, buf);
	}
	return 0;
}
EXPORT_SYMBOL(fsinfo_patch_statfs);

#ifdef MODULE
static asmlinkage long hooked_statfs(const struct pt_regs *regs)
{
	long ret;
	struct statfs __user *buf;
	const char __user *upath;
	if (!fsinfo)
		return -EFAULT;
	ret = fsinfo->original_statfs(regs);
	if (ret == 0) {
		upath = (void *)regs->regs[0];
		buf = (void *)regs->regs[1];
		ret = fsinfo_patch_statfs(upath, buf);
	}
	return ret;
}
#endif

static int fsinfo_show(struct seq_file *m, void *v)
{
	struct fsinfo_item *item;
	if (!fsinfo)
		return -EFAULT;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	list_for_each_entry(item, &fsinfo->items, list) {
		if (seq_write(m, &item->entry, sizeof(struct fsinfo_entry)))
			goto done;
	}
done:
	return 0;
}

static int process_one(struct fsinfo_entry __user *uentry)
{
	int ret;
	bool unset = false;
	struct path path;
	struct fsinfo_entry entry;
	struct fsinfo_item *item, *tmp;
	char *dp;
	unsigned int lfl = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	if (copy_from_user(&entry, uentry, sizeof(entry)))
		return -EFAULT;
	if ((ret = user_path_at(AT_FDCWD, uentry->path, lfl, &path)))
		return ret;
	memset(entry.path, 0, sizeof(entry.path));
	dp = d_path(&path, entry.path, sizeof(entry.path));
	path_put(&path);
	if (IS_ERR(dp))
		return PTR_ERR(dp);
	if (!dp[0])
		return -EINVAL;
	unset = !memchr_inv(&entry.mask, 0, sizeof(entry.mask));
	list_for_each_entry_safe(item, tmp, &fsinfo->items, list) {
		if (strcmp(item->entry.path, dp) != 0)
			continue;
		if (unset) {
			list_del(&item->list);
			kfree(item);
		} else
			goto fill;
		return 0;
	}
	if (!unset) {
		if (!(item = kzalloc(sizeof(*item), GFP_KERNEL)))
			return -ENOMEM;
		list_add_tail(&item->list, &fsinfo->items);
fill:
		memcpy(&item->entry, &entry, sizeof(entry));
		memset(item->entry.path, 0, sizeof(item->entry.path));
		strncpy(item->entry.path, dp, sizeof(item->entry.path) - 1);
	}
	return 0;
}

static ssize_t fsinfo_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int pret;
	size_t cnt, i;
	ssize_t ret = count;
	struct fsinfo_entry __user *uentry;
	if (!fsinfo)
		return -EFAULT;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	cnt = count / sizeof(struct fsinfo_entry);
	if ((count % sizeof(struct fsinfo_entry)) != 0)
		return -EINVAL;
	for (i = 0; i < cnt; i++) {
		uentry = (struct fsinfo_entry __user *)buf;
		buf += sizeof(struct fsinfo_entry);
		pret = process_one(uentry);
		if (pret) {
			if (i > 0)
				ret = i * sizeof(struct fsinfo_entry);
			else
				ret = pret;
			break;
		}
	}
	return ret;
}

static long real_statfs(struct fsinfo_entry __user *e)
{
	int error;
	struct path path;
	struct statfs buf;
	struct kstatfs st;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
retry:
	error = user_path_at(AT_FDCWD, e->path, lookup_flags, &path);
	if (!error) {
		error = vfs_statfs(&path, &st);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	if (!error) {
		if (sizeof(buf) != sizeof(st)) {
			memset(&buf, 0, sizeof(buf));
			if (sizeof(buf.f_blocks) == 4) {
				if ((st.f_blocks | st.f_bfree | st.f_bavail |
				     st.f_bsize | st.f_frsize) &
				    0xffffffff00000000ULL)
					return -EOVERFLOW;
				if (st.f_files != -1 &&
				    (st.f_files & 0xffffffff00000000ULL))
					return -EOVERFLOW;
				if (st.f_ffree != -1 &&
				    (st.f_ffree & 0xffffffff00000000ULL))
					return -EOVERFLOW;
			}
			buf.f_type = st.f_type;
			buf.f_bsize = st.f_bsize;
			buf.f_blocks = st.f_blocks;
			buf.f_bfree = st.f_bfree;
			buf.f_bavail = st.f_bavail;
			buf.f_files = st.f_files;
			buf.f_ffree = st.f_ffree;
			buf.f_fsid = st.f_fsid;
			buf.f_namelen = st.f_namelen;
			buf.f_frsize = st.f_frsize;
			buf.f_flags = st.f_flags;
		} else
			memcpy(&buf, &st, sizeof(st));
		if (copy_to_user(&e->stat, &buf, sizeof(buf)))
			return -EFAULT;
	}
	return error;
}

static long fsinfo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FSINFO_REAL_STATFS:
		return real_statfs((struct fsinfo_entry __user *)arg);
	case FSINFO_UNLOCK_MOD:
		if (fsinfo->prot) {
			fsinfo->prot = false;
			module_put(THIS_MODULE);
		}
		return 0;
	default:
		return -EINVAL;
	}
}

static int fsinfo_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return single_open(file, fsinfo_show, inode->i_private);
}

static const struct file_operations fsinfo_fops = {
	.owner = THIS_MODULE,
	.open = fsinfo_open,
	.read = seq_read,
	.write = fsinfo_write,
	.llseek = seq_lseek,
	.release = single_release,
	.unlocked_ioctl = fsinfo_ioctl,
};

#define SET_SYSCALL_PROT(prot)                                             \
	fsinfo->update_mapping_prot(__pa_symbol(fsinfo->sys_call_table),   \
				    (unsigned long)fsinfo->sys_call_table, \
				    NR_syscalls * sizeof(void *),          \
				    (prot) ? PAGE_KERNEL_RO : PAGE_KERNEL);

static int __init fsinfo_init(void)
{
	int ret = -EFAULT;
	fsinfo = kzalloc(sizeof(struct fsinfo_data), GFP_KERNEL);
	if (!fsinfo)
		return -ENOMEM;
	if (!try_module_get(THIS_MODULE)) {
		pr_err("failed to get self module\n");
		goto err_free;
	}
	fsinfo->prot = true;
	INIT_LIST_HEAD(&fsinfo->items);
#ifdef MODULE
	fsinfo->update_mapping_prot = (void *)kallsyms_lookup_name(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
		"update_mapping_prot"
#else
		"create_mapping_late"
#endif
	);
	if (!fsinfo->update_mapping_prot) {
		pr_err("failed to find update_mapping_prot\n");
		goto err_free;
	}
	fsinfo->sys_call_table =
		(unsigned long **)kallsyms_lookup_name("sys_call_table");
	if (!fsinfo->sys_call_table) {
		pr_err("failed to find sys_call_table\n");
		goto err_free;
	}
#endif
	fsinfo->dent =
		debugfs_create_file("fsinfo", 0600, NULL, NULL, &fsinfo_fops);
	if (!fsinfo->dent) {
		pr_err("fsinfo create failed\n");
		goto err_free;
	}
#ifdef MODULE
	fsinfo->original_statfs = (void *)fsinfo->sys_call_table[__NR_statfs];
	SET_SYSCALL_PROT(false);
	fsinfo->sys_call_table[__NR_statfs] = (unsigned long *)hooked_statfs;
	SET_SYSCALL_PROT(true);
#endif
	return 0;
err_free:
	kfree(fsinfo);
	return ret;
}

static void __exit fsinfo_exit(void)
{
	struct fsinfo_item *item, *tmp;
	if (!fsinfo)
		return;
	list_for_each_entry_safe(item, tmp, &fsinfo->items, list) {
		list_del(&item->list);
		kfree(item);
	}
	if (fsinfo->dent)
		debugfs_remove(fsinfo->dent);
#ifdef MODULE
	SET_SYSCALL_PROT(false);
	fsinfo->sys_call_table[__NR_statfs] =
		(unsigned long *)fsinfo->original_statfs;
	SET_SYSCALL_PROT(true);
#endif
	kfree(fsinfo);
}

module_init(fsinfo_init);
module_exit(fsinfo_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("fsinfo tool");
