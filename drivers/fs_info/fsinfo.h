#define FSINFO_PATH_LEN 1024
struct fsinfo_entry {
	char path[FSINFO_PATH_LEN];
	struct statfs stat, mask;
	bool auto_bavail;
	bool auto_bfree;
};
#define FSINFO_REAL_STATFS 0x111101
#define FSINFO_UNLOCK_MOD 0x111102
