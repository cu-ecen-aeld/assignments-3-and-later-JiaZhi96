/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd-circular-buffer.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("JiaZhi96");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
	struct aesd_dev *dev; /* device information */
    PDEBUG("open");
	/*  Find the device */
	dev = container_of(inode->i_cdev, struct aesd_dev, cdev);

	/* and use filp->private_data to point to the device data */
	filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;

    struct aesd_dev *dev = filp->private_data;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    size_t entry_offset = 0;
    struct aesd_buffer_entry *entry = 
        aesd_circular_buffer_find_entry_offset_for_fpos(&dev->write_buf, *f_pos, &entry_offset);

    if (!entry) {
        retval = 0;
        goto read_end;
    }

    size_t size_left = entry->size - entry_offset;
    size_t size_to_read = count > size_left ? size_left : count;
    
    if (copy_to_user(buf, &entry->buffptr[entry_offset], size_to_read)) {
        retval = -EFAULT;
        goto read_end;
    }
    
    *f_pos += size_to_read;
    retval = size_to_read;
  read_end:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

	struct aesd_dev *dev = filp->private_data;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    char *last_buf = dev->temp_buf;
    size_t last_size = dev->temp_size;
    size_t new_size = count + last_size;

    char *new_buf = kmalloc(new_size, GFP_KERNEL);
    if (!new_buf) {
        retval = -ENOMEM;
        goto write_end;
    }

    if (last_buf) {
        memcpy(new_buf, last_buf, last_size);
        kfree(last_buf);
        dev->temp_buf = NULL;
        dev->temp_size = 0;
    }

    if (copy_from_user(&new_buf[last_size], buf, count)) {
        kfree(new_buf);
        retval = -EFAULT;
        goto write_end;
    }

    // Only search from new buf as we already searched last_buf
    char *end_char = memchr(&new_buf[last_size], '\n', count);
    if (end_char != NULL) {
        struct aesd_buffer_entry new_entry = {
            .buffptr = new_buf,
            .size = new_size
        };

        const char *overflow_buffer =
            aesd_circular_buffer_add_entry(&dev->write_buf, &new_entry);
        
        if (overflow_buffer) {
            kfree(overflow_buffer);
        }
    } else {
        // Store into temp_buf if no endline character
        dev->temp_buf = new_buf;
        dev->temp_size = new_size;
    }

    retval = count;
  write_end:
    mutex_unlock(&dev->lock);
    return count;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    aesd_circular_buffer_init(&aesd_device.write_buf);
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    struct aesd_buffer_entry *entryptr;
    size_t index;
    AESD_CIRCULAR_BUFFER_FOREACH(entryptr, &aesd_device.write_buf, index) {
        if (entryptr->buffptr) {
            kfree(entryptr->buffptr);
        }
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
