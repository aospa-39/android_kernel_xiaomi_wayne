#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include "fsinfo.h"

static int find_mnt_by_fstype(const char *fstype, char *buff, size_t sz)
{
	int res = -1;
	memset(buff, 0, sz);
	FILE *file = fopen("/proc/mounts", "r");
	if (!file)
		err(1, "open /proc/mounts failed");
	char src[4096], tgt[4096], type[4096], opt[4096];
	int dump, pass;
	while (true) {
		int ret = fscanf(file, "%255s %255s %255s %255s %d %d", src,
				 tgt, type, opt, &dump, &pass);
		if (ret != 6)
			break;
		if (strcmp(type, fstype) == 0) {
			strncpy(buff, tgt, sz - 1);
			res = 0;
			break;
		}
	}
	fclose(file);
	return res;
}

static void print_statfs(const char *prefix, struct statfs *st)
{
	union {
		fsid_t f;
		unsigned long u;
	} fsid;
	fsid.f = st->f_fsid;
	printf("%sf_type    = 0x%lx\n", prefix, st->f_type);
	printf("%sf_bsize   = %ld\n", prefix, st->f_bsize);
	printf("%sf_blocks  = %lu\n", prefix, st->f_blocks);
	printf("%sf_bfree   = %lu\n", prefix, st->f_bfree);
	printf("%sf_bavail  = %lu\n", prefix, st->f_bavail);
	printf("%sf_files   = %lu\n", prefix, st->f_files);
	printf("%sf_ffree   = %lu\n", prefix, st->f_ffree);
	printf("%sf_fsid    = 0x%lx\n", prefix, fsid.u);
	printf("%sf_namelen = %lu\n", prefix, st->f_namelen);
	printf("%sf_frsize  = %lu\n", prefix, st->f_frsize);
	printf("%sf_flags   = %lu\n", prefix, st->f_flags);
}

int main(int argc, char **argv)
{
	int ret, fd;
	struct fsinfo_entry entry;
	char debugfs[4096], fsinfo[4096];
	if (argc < 1 || argc > 3)
		errx(1, "Usage: fsinfo-tool [FS [SIZE]]");

	/* Prepare debugfs */
	if (find_mnt_by_fstype("debugfs", debugfs, sizeof(debugfs))) {
		strcpy(debugfs, "/sys/kernel/debug");
		ret = mount("debugfs", debugfs, "debugfs", 0, NULL);
		if (ret != 0)
			err(1, "mount debugfs failed");
	}
	snprintf(fsinfo, sizeof(fsinfo), "%s/fsinfo", debugfs);
	if ((fd = open(fsinfo, O_RDWR)) < 0)
		err(1, "open fsinfo %s failed", fsinfo);

	if (argc == 3) {
		char *end;
		unsigned long size;
		struct statfs cur_st;
		struct fsinfo_entry old_entry;

		/* Read args */
		errno = 0;
		size = strtoul(argv[2], &end, 0);
		if (errno != 0 || !end || *end)
			err(1, "invalid size %s", argv[2]);
		memset(&old_entry, 0, sizeof(old_entry));
		if (strlen(argv[1]) >= sizeof(old_entry.path) - 1)
			errx(1, "path too long %s", argv[2]);
		strncpy(old_entry.path, argv[1], sizeof(old_entry.path) - 1);

		/* Get real statfs */
		if ((ret = ioctl(fd, FSINFO_REAL_STATFS, &old_entry)) != 0)
			err(1, "statfs %s failed", argv[1]);
		printf("Original filesystem:\n");
		print_statfs("  ", &old_entry.stat);

		/* Patch statfs */
		if (old_entry.stat.f_bsize == 0)
			errx(1, "bad block size in statfs");
		size /= old_entry.stat.f_bsize;
		memcpy(&entry, &old_entry, sizeof(old_entry));
		entry.stat.f_blocks = size;
		memset(&entry.mask.f_blocks, 0xff, sizeof(entry.mask.f_blocks));
		entry.auto_bavail = true;
		entry.auto_bfree = true;

		/* Apply patch */
		errno = 0;
		ssize_t wr = write(fd, &entry, sizeof(entry));
		if (wr != sizeof(entry))
			err(1, "set fsinfo failed");

		if ((ret = statfs(argv[1], &cur_st)) != 0)
			err(1, "statfs %s failed", argv[1]);
		printf("Hooked filesystem:\n");
		print_statfs("  ", &cur_st);
	} else if (argc == 2) {
		/* Fill path */
		memset(&entry, 0, sizeof(entry));
		if (strlen(argv[1]) >= sizeof(entry.path) - 1)
			errx(1, "path too long %s", argv[2]);
		strncpy(entry.path, argv[1], sizeof(entry.path) - 1);

		printf("Removing patch %s\n", argv[1]);

		/* Remove patch */
		errno = 0;
		ssize_t wr = write(fd, &entry, sizeof(entry));
		if (wr != sizeof(entry))
			err(1, "set fsinfo failed");
	} else {
		/* Print all patches */
		int cnt = 0;
		while (true) {
			memset(&entry, 0, sizeof(entry));
			ssize_t rd = read(fd, &entry, sizeof(entry));
			if (rd != (ssize_t)sizeof(entry))
				break;
			printf("Hooked filesystem %s:\n", entry.path);
			print_statfs("  ", &entry.stat);
			cnt++;
		}
		printf("%d hooked filesystems\n", cnt);
	}
	close(fd);
	return 0;
}
