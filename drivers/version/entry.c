#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>

#define DEVICE_NAME "fake_uts"
#define FAKE_UTS_MAGIC 0xF1
#define FAKE_UTS_SET_ALL _IOW(FAKE_UTS_MAGIC, 1, struct fake_uts_data)

struct fake_uts_data {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};

static struct new_utsname real_uts; // 保存原始值
static struct new_utsname fake_uts; // 存储伪造的值
static bool is_active = false;      // 标记是否启用伪造

static dev_t dev_num;
static struct cdev cdev;
static struct class *uts_class;

// 保存原始 utsname 结构
static void backup_real_uts(void) {
  memcpy(&real_uts, utsname(), sizeof(real_uts));
}

// 恢复原始值
static void restore_uts(void) {
  memcpy(utsname(), &real_uts, sizeof(real_uts));
}

// 应用伪造值
static void apply_fake_uts(void) {
  memcpy(utsname(), &fake_uts, sizeof(fake_uts));
}

// ioctl 处理
static long fake_uts_ioctl(struct file *file, unsigned int cmd,
                           unsigned long arg) {
  struct fake_uts_data data;

  switch (cmd) {
  case FAKE_UTS_SET_ALL:
    if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
      return -EFAULT;

    strncpy(fake_uts.sysname, data.sysname, sizeof(fake_uts.sysname));
    strncpy(fake_uts.nodename, data.nodename, sizeof(fake_uts.nodename));
    strncpy(fake_uts.release, data.release, sizeof(fake_uts.release));
    strncpy(fake_uts.version, data.version, sizeof(fake_uts.version));
    strncpy(fake_uts.machine, data.machine, sizeof(fake_uts.machine));
    strncpy(fake_uts.domainname, data.domainname, sizeof(fake_uts.domainname));

    if (!is_active) {
      backup_real_uts();
      is_active = true;
    }
    apply_fake_uts();
    return 0;

  default:
    return -ENOTTY;
  }
}

static const struct file_operations fops = {
    .unlocked_ioctl = fake_uts_ioctl,
    .owner = THIS_MODULE,
};

static int __init fake_uts_init(void) {
  int ret;

  ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
  if (ret < 0) {
    pr_err("Failed to allocate device number\n");
    return ret; // 返回实际错误码（如 -ENOMEM）
  }

  cdev_init(&cdev, &fops);
  if (cdev_add(&cdev, dev_num, 1) < 0)
    goto err_cdev;

  uts_class = class_create(THIS_MODULE, DEVICE_NAME);
  device_create(uts_class, NULL, dev_num, NULL, DEVICE_NAME);

  pr_info("Fake UTS module loaded\n");
  return 0;

err_cdev:
  unregister_chrdev_region(dev_num, 1);
  return -1;
}

static void __exit fake_uts_exit(void) {
  if (is_active)
    restore_uts();

  device_destroy(uts_class, dev_num);
  class_destroy(uts_class);
  cdev_del(&cdev);
  unregister_chrdev_region(dev_num, 1);

  pr_info("Fake UTS module unloaded\n");
}

module_init(fake_uts_init);
module_exit(fake_uts_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("SanJiu");