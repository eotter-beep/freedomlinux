// SPDX-License-Identifier: GPL-2.0-only
/*
 * USB Guard - simple policy engine that blocks USB devices exposing
 * dangerous functionality until explicitly authorised.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/security.h>
#include <linux/securityfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/usb/ch9.h>
#include <linux/usb/authorization.h>

struct usb_guard_rule {
struct list_head list;
u16 vendor;
u16 product;
};

static LIST_HEAD(usb_guard_rules);
static DEFINE_MUTEX(usb_guard_lock);

static struct notifier_block usb_guard_nb;
static struct dentry *usb_guard_dir;
static struct dentry *usb_guard_policy_file;
static bool usb_guard_registered;

static bool usb_guard_class_is_dangerous(u8 class)
{
	switch (class) {
	case USB_CLASS_PER_INTERFACE:
		/* Consult individual interfaces instead. */
		return false;
	case USB_CLASS_MASS_STORAGE:
	case USB_CLASS_COMM:
	case USB_CLASS_CDC_DATA:
	case USB_CLASS_APP_SPEC:
	case USB_CLASS_VENDOR_SPEC:
		return true;
	default:
		return false;
	}
}

static bool usb_guard_device_whitelisted(struct usb_device *udev)
{
	struct usb_guard_rule *rule;
	u16 vendor = le16_to_cpu(udev->descriptor.idVendor);
	u16 product = le16_to_cpu(udev->descriptor.idProduct);
	bool allowed = false;

	mutex_lock(&usb_guard_lock);
	list_for_each_entry(rule, &usb_guard_rules, list) {
		if (rule->vendor == vendor && rule->product == product) {
			allowed = true;
			break;
		}
	}
	mutex_unlock(&usb_guard_lock);

	return allowed;
}

static bool usb_guard_interfaces_dangerous(struct usb_device *udev)
{
	struct usb_host_config *config = udev->actconfig;
	int i, j;

	if (!config)
		return false;

	for (i = 0; i < config->desc.bNumInterfaces; i++) {
		struct usb_interface_cache *cache = config->intf_cache[i];

		if (!cache)
			continue;

		for (j = 0; j < cache->num_altsetting; j++) {
			struct usb_host_interface *alt = &cache->altsetting[j];

			if (usb_guard_class_is_dangerous(alt->desc.bInterfaceClass))
				return true;
		}
	}

	return false;
}

static bool usb_guard_device_allowed(struct usb_device *udev)
{
	if (!udev->parent)
		return true;

	/* already blocked? */
	if (udev->authorized == 0)
		return true;

	if (usb_guard_device_whitelisted(udev))
		return true;

	if (!usb_guard_class_is_dangerous(udev->descriptor.bDeviceClass) &&
	    !usb_guard_interfaces_dangerous(udev))
		return true;

	return false;
}

static int usb_guard_notifier(struct notifier_block *nb,
			      unsigned long action,
			      void *data)
{
	struct usb_device *udev = data;
	int ret;

	if (action != USB_DEVICE_ADD)
		return NOTIFY_OK;

	if (usb_guard_device_allowed(udev))
		return NOTIFY_OK;

	dev_warn(&udev->dev,
		 "USB Guard denied %04x:%04x (interfaces require authorization)\n",
		 le16_to_cpu(udev->descriptor.idVendor),
		 le16_to_cpu(udev->descriptor.idProduct));

	ret = usb_deauthorize_device(udev);
	if (ret)
		dev_warn(&udev->dev,
			 "Failed to deauthorize device: %d\n",
			 ret);

	return NOTIFY_OK;
}

static ssize_t usb_guard_policy_read(struct file *file,
			      char __user *buf,
			      size_t len, loff_t *ppos)
{
	struct usb_guard_rule *rule;
	char *kbuf;
	size_t pos = 0;
	ssize_t ret;

	kbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	mutex_lock(&usb_guard_lock);
	list_for_each_entry(rule, &usb_guard_rules, list) {
		if (pos >= PAGE_SIZE - 1)
			break;
		pos += scnprintf(kbuf + pos, PAGE_SIZE - pos,
				  "%04x:%04x\n",
				  rule->vendor, rule->product);
	}
	mutex_unlock(&usb_guard_lock);

	ret = simple_read_from_buffer(buf, len, ppos, kbuf, pos);
	kfree(kbuf);

	return ret;
}

static void usb_guard_clear_rules(void)
{
	struct usb_guard_rule *rule, *tmp;

	list_for_each_entry_safe(rule, tmp, &usb_guard_rules, list) {
		list_del(&rule->list);
		kfree(rule);
	}
}

static ssize_t usb_guard_policy_write(struct file *file,
			      const char __user *buf,
			      size_t len, loff_t *ppos)
{
	char kbuf[64];
	u16 vendor, product;
	struct usb_guard_rule *rule;
	int parsed;

	if (len == 0)
		return 0;

	if (len >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;

	kbuf[len] = '\0';
	strim(kbuf);

	if (!strcmp(kbuf, "clear")) {
		mutex_lock(&usb_guard_lock);
		usb_guard_clear_rules();
		mutex_unlock(&usb_guard_lock);
		return len;
	}

	parsed = sscanf(kbuf, "allow %hx %hx", &vendor, &product);
	if (parsed == 2) {
		bool exists = false;

		mutex_lock(&usb_guard_lock);
		list_for_each_entry(rule, &usb_guard_rules, list) {
			if (rule->vendor == vendor && rule->product == product) {
				exists = true;
				break;
			}
		}

		if (!exists) {
			rule = kzalloc(sizeof(*rule), GFP_KERNEL);
			if (!rule) {
				mutex_unlock(&usb_guard_lock);
				return -ENOMEM;
				}
			rule->vendor = vendor;
			rule->product = product;
			list_add_tail(&rule->list, &usb_guard_rules);
		}
		mutex_unlock(&usb_guard_lock);
		return len;
	}

	return -EINVAL;
}

static const struct file_operations usb_guard_policy_fops = {
	.owner = THIS_MODULE,
	.read = usb_guard_policy_read,
	.write = usb_guard_policy_write,
	.llseek = default_llseek,
};

static int __init usb_guard_init(void)
{
	int ret;

	usb_guard_nb.notifier_call = usb_guard_notifier;

	usb_guard_dir = securityfs_create_dir("usb_guard", NULL);
	if (IS_ERR(usb_guard_dir)) {
		pr_warn("usb_guard: failed to create securityfs directory (%ld)\n",
			PTR_ERR(usb_guard_dir));
		usb_guard_dir = NULL;
	}

	if (usb_guard_dir) {
		usb_guard_policy_file = securityfs_create_file("policy", 0600,
				      usb_guard_dir, NULL,
				      &usb_guard_policy_fops);
		if (IS_ERR(usb_guard_policy_file)) {
			pr_warn("usb_guard: failed to create policy file (%ld)\n",
				PTR_ERR(usb_guard_policy_file));
			usb_guard_policy_file = NULL;
		}
	}

	ret = usb_register_notify(&usb_guard_nb);
	if (ret) {
		pr_err("usb_guard: failed to register USB notifier (%d)\n", ret);
		securityfs_remove(usb_guard_policy_file);
		usb_guard_policy_file = NULL;
		securityfs_remove(usb_guard_dir);
		usb_guard_dir = NULL;
		return ret;
	}

	usb_guard_registered = true;
	pr_info("usb_guard: policy engine active\n");

	return 0;
}

static void __exit usb_guard_exit(void)
{
	if (usb_guard_registered)
		usb_unregister_notify(&usb_guard_nb);

	usb_guard_registered = false;

	securityfs_remove(usb_guard_policy_file);
	usb_guard_policy_file = NULL;
	securityfs_remove(usb_guard_dir);
	usb_guard_dir = NULL;

	mutex_lock(&usb_guard_lock);
	usb_guard_clear_rules();
	mutex_unlock(&usb_guard_lock);
}

security_initcall(usb_guard_init);
module_exit(usb_guard_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("USB Guard security policy");
MODULE_AUTHOR("FreedomLinux");
