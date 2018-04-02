#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/xattr.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>

#include "eaInfo.h"

struct dentry* get_dentry_from_pathname(const char *pathname)
{
	struct path path;
	kern_path(pathname, LOOKUP_FOLLOW, &path);
	return path.dentry;
}

asmlinkage long sys_addEAKey(const char *pathName, char *value)
{
	struct dentry *dentry = get_dentry_from_pathname(pathName);
	printk(KERN_INFO "flock: Attempting to add security.key to %s\n", pathName);
	if (vfs_setxattr(dentry, "security.key", (void *)value, strlen(value), 0) == -1)
		printk(KERN_INFO "flock: Failed to add security.key extended attribute to %s\n", pathName);
	return 0;
}
