/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_USB_AUTHORIZATION_H
#define __LINUX_USB_AUTHORIZATION_H

struct usb_device;

int usb_deauthorize_device(struct usb_device *usb_dev);
int usb_authorize_device(struct usb_device *usb_dev);

#endif /* __LINUX_USB_AUTHORIZATION_H */
