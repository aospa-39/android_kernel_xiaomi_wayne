
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/export.h>
#include <linux/shmem_fs.h>
#include <soc/qcom/socinfo.h>
#include "internal.h"

// 假设的模糊处理函数，这里使用异或操作  
long fuzz_serial(long serial) {  
    // 选择一个固定的异或值，这里简单起见使用固定的数字  
    const long fuzz_value = 0x12345678;  
    return serial ^ fuzz_value;  
}

static ssize_t hook_sanjiu_id(char *buff, size_t size) {  
    long serial;
	long fuzzed_serial;
    char serial_str[50];
    ssize_t ret;
  	//size_t serial_len;

    if (buff == NULL || size == 0) {
        return -1; // 错误处理
    }
  
    serial = socinfo_get_serial_number();
    if (serial < 0) {
        return -1; // 错误处理
    }
  
    // 对序列号进行模糊处理
    fuzzed_serial = fuzz_serial(serial);

    // 将模糊处理后的序列号转换为字符串
    snprintf(serial_str, sizeof(serial_str), "%ld\n", fuzzed_serial);
  
    strncpy(buff, serial_str, size);
    buff[size - 1] = '\0'; // 确保字符串以null字符结尾

    ret = strlen(buff);
    return ret;
}

static struct hook_path{
	const char *path;
	ssize_t (*callback)(char *buff, size_t size);
} hooks[] = {
	{ "/sanjiu_id", hook_sanjiu_id},
	// { "/sys/devices/soc0/serial_number", hook_serial_number},
	{NULL,NULL}
};

static struct hook_path *get_hook(const char *path) {
	int i;
	for (i = 0; hooks[i].callback; i++)
		if (strcmp(path, hooks[i].path) == 0)
			return &hooks[i];
	return NULL;
}

struct file *fs_hook_file(const char *path) {
	int err;
	void *buf = NULL;
	struct file *f = NULL;
	struct hook_path *hook = NULL;
	ssize_t ret = -ENOENT;
	loff_t pos = 0;
	size_t len = PAGE_SIZE;
	if (!path || IS_ERR(path)) return ERR_PTR(-ENODATA);
	if (!(hook = get_hook(path))) return ERR_PTR(-ENODATA);
	if (!(buf = kmalloc(len, GFP_KERNEL))) goto fail;
	memset(buf, 0, len);
	if ((ret = hook->callback(buf, len)) < 0) goto fail;
	f = shmem_file_setup(path, 0, VM_NORESERVE);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		pr_warn_ratelimited("failed to create file: %ld\n", ret);
		goto fail;
	}
	f->f_mode |= FMODE_PREAD | FMODE_PWRITE | FMODE_NOCMTIME | FMODE_LSEEK;
	f->f_flags |= O_RDONLY | O_LARGEFILE | O_NOATIME;
	if ((err = kernel_write(f, buf, ret, &pos)) < 0) {
		ret = err;
		pr_warn_ratelimited("failed to write file: %ld\n", ret);
		goto fail;
	}
	f->f_mode &= ~(FMODE_WRITE | FMODE_PWRITE);
	kfree(buf);
	return f;
fail:
	if (buf) kfree(buf);
	if (f) fput(f);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(fs_hook_file);

struct file *fs_hook_path(struct path *path) {
	char *buff, *p;
	struct file *f = ERR_PTR(-ENODATA);
	size_t len = PAGE_SIZE;
	if (!path || IS_ERR(path)) return f;
	if (!(buff = kmalloc(len, GFP_KERNEL)))
		return ERR_PTR(-ENOMEM);
	if ((p = d_path(path, buff, len)))
		f = fs_hook_file(p);
	kfree(buff);
	return f;
}
EXPORT_SYMBOL(fs_hook_path);
