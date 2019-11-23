/*
 * Copyright (C) 2014 Samsung Electronics Co. Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef __LINUX_USB_NOTIFIER_H__
#define __LINUX_USB_NOTIFIER_H__

#if defined(CONFIG_USB_NOTIFY_LAYER)
extern void mt_usb_connect(void);
extern void mt_usb_disconnect(void);
extern void mt_usb_host_connect(int delay);
extern void mt_usb_host_disconnect(int delay);
extern void mt_otg_accessory_power(int is_on);
#else
static inline void mt_usb_connect(void) {}
static inline void mt_usb_disconnect(void) {}
static inline void mt_usb_host_connect(int delay) {}
static inline void mt_usb_host_disconnect(int delay) {}
static inline void mt_otg_accessory_power(int is_on) {}
#endif
#endif

