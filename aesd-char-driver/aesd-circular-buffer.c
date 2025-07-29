/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

static uint8_t get_next_offset(uint8_t curr_offs)
{
    if(++curr_offs >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
        curr_offs = 0;
    }

    return curr_offs;
}

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    uint8_t read_offs = buffer->out_offs;
    size_t total_offs = 0;
    struct aesd_buffer_entry *return_entry = NULL;
    
    do {
        struct aesd_buffer_entry *read_entry = &(buffer->entry[read_offs]);
        if((total_offs + read_entry->size - 1) >= char_offset) {
            *entry_offset_byte_rtn = char_offset - total_offs;
            return_entry = read_entry;
            break;
        }
        total_offs += read_entry->size;
        read_offs = get_next_offset(read_offs);
    } while(read_offs != buffer->in_offs);

    return return_entry;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    struct aesd_buffer_entry *in_entry = &(buffer->entry[buffer->in_offs]);
    in_entry->buffptr = add_entry->buffptr;
    in_entry->size = add_entry->size;
    
    // Overwrite oldest value if buffer is full
    if(buffer->out_offs == buffer->in_offs) {
        buffer->out_offs = get_next_offset(buffer->out_offs);
    }

    buffer->in_offs = get_next_offset(buffer->in_offs);

    buffer->full = (buffer->out_offs == buffer->in_offs);
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
