=====================
USB Guard securityfs
=====================

The ``USB Guard`` policy engine prevents newly attached USB devices from
exposing high-risk functionality until they have been explicitly allowed.
It is implemented in the ``CONFIG_SECURITY_USB_GUARD`` option and depends on
``SECURITY`` and ``USB`` support in the kernel configuration.

Overview
========

When USB Guard is enabled the kernel monitors each hotplugged USB device and
rejects those which expose classes commonly associated with potentially
dangerous behaviour, such as mass storage, communications, CDC data or
vendor-specific interfaces.  Denied devices are immediately marked as
unauthorised using ``usb_deauthorize_device()``, which prevents the kernel from
binding drivers or accessing the device.

Allowing devices
================

Authorised vendor/product pairs are managed through the
``/sys/kernel/security/usb_guard/policy`` securityfs file.  Reading the file
returns the current allow-list as hexadecimal ``VID:PID`` pairs, one per line::

    # cat /sys/kernel/security/usb_guard/policy
    04f2:b221

Write the string ``clear`` to remove all entries::

    # echo clear > /sys/kernel/security/usb_guard/policy

To allow an individual device permanently, write an ``allow`` rule containing
its vendor and product identifiers::

    # echo "allow 04f2 b221" > /sys/kernel/security/usb_guard/policy

Future connections from the permitted device will no longer be blocked by the
policy engine.

Notifications
=============

Whenever USB Guard blocks a device it logs a kernel warning containing the
``VID:PID`` pair of the rejected hardware.  This can be observed via ``dmesg``
or the kernel log.

Interactions
============

* Devices that are already unauthorised (for example through the generic USB
  authorisation framework) are ignored by USB Guard.
* Root hubs and other kernel-internal devices are not subject to the policy.
* The policy engine requires securityfs to be mounted.  When securityfs is not
  available, the kernel will log a warning and USB Guard will operate with an
  empty allow-list.
