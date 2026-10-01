/*
 RDP event queuing

 Copyright 2013 Thincast Technologies GmbH, Author: Dorian Johnson

 This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 If a copy of the MPL was not distributed with this file, You can obtain one at
 http://mozilla.org/MPL/2.0/.
 */

#include <winpr/assert.h>
#include <freerdp/display.h>
#include <freerdp/gdi/gdi.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "ios_freerdp_events.h"

#pragma mark -
#pragma mark Sending compacted input events (from main thread)

// While this function may be called from any thread that has an autorelease pool allocated, it is
// not threadsafe: caller is responsible for synchronization
BOOL ios_events_send(mfInfo *mfi, NSDictionary *event_description)
{
	NSError *error = nil;
	NSData *encoded_description = [NSKeyedArchiver archivedDataWithRootObject:event_description
	                                                    requiringSecureCoding:YES
	                                                                    error:&error];

	if (!encoded_description)
	{
		NSLog(@"%s: Failed to archive event (type: %@): %@", __func__,
		      [event_description objectForKey:@"type"], error);
		return FALSE;
	}

	WINPR_ASSERT(mfi);

	if ([encoded_description length] > 32000 || (mfi->event_pipe_producer == -1))
		return FALSE;

	uint32_t archived_data_len = (uint32_t)[encoded_description length];

	// NSLog(@"writing %d bytes to input event pipe", archived_data_len);

	if (!mfi->event_mutex_initialized)
		return FALSE;

	pthread_mutex_lock(&mfi->event_mutex);
	if (mfi->event_pipe_producer == -1)
	{
		pthread_mutex_unlock(&mfi->event_mutex);
		return FALSE;
	}

	const uint8_t *payload = (const uint8_t *)[encoded_description bytes];
	uint8_t *length_bytes = (uint8_t *)&archived_data_len;
	ssize_t written = 0;
	while (written < 4)
	{
		ssize_t rc = write(mfi->event_pipe_producer, length_bytes + written, 4 - written);
		if (rc > 0)
			written += rc;
		else if (rc < 0 && errno == EINTR)
			continue;
		else
		{
			NSLog(@"%s: Failed to write length descriptor to pipe.", __func__);
			pthread_mutex_unlock(&mfi->event_mutex);
			return FALSE;
		}
	}

	written = 0;
	while (written < archived_data_len)
	{
		ssize_t rc = write(mfi->event_pipe_producer, payload + written, archived_data_len - written);
		if (rc > 0)
			written += rc;
		else if (rc < 0 && errno == EINTR)
			continue;
		else
		{
			NSLog(@"%s: Failed to write %d bytes into the event queue (event type: %@).", __func__,
			      (int)[encoded_description length], [event_description objectForKey:@"type"]);
			pthread_mutex_unlock(&mfi->event_mutex);
			return FALSE;
		}
	}

	pthread_mutex_unlock(&mfi->event_mutex);
	return TRUE;
}

static BOOL ios_events_read_full(int fd, void *buffer, size_t length)
{
	size_t offset = 0;
	while (offset < length)
	{
		ssize_t rc = read(fd, (uint8_t *)buffer + offset, length - offset);
		if (rc > 0)
			offset += rc;
		else if (rc < 0 && errno == EINTR)
			continue;
		else
			return FALSE;
	}
	return TRUE;
}

#pragma mark -
#pragma mark Processing compacted input events (from connection thread runloop)

static BOOL ios_events_handle_event(mfInfo *mfi, NSDictionary *event_description)
{
	NSString *event_type = [event_description objectForKey:@"type"];
	BOOL should_continue = TRUE;
	rdpInput *input;

	WINPR_ASSERT(mfi);

	freerdp *instance = mfi->instance;
	WINPR_ASSERT(instance);
	WINPR_ASSERT(instance->context);

	input = instance->context->input;
	WINPR_ASSERT(input);

	if ([event_type isEqualToString:@"mouse"])
	{
		if (!input->MouseEvent(input,
		                       [[event_description objectForKey:@"flags"] unsignedShortValue],
		                       [[event_description objectForKey:@"coord_x"] unsignedShortValue],
		                       [[event_description objectForKey:@"coord_y"] unsignedShortValue]))
		{
			// Returning an error here can terminate the connection.
			NSLog(@"%s: MouseEvent failed.", __func__);
		}
	}
	else if ([event_type isEqualToString:@"keyboard"])
	{
		if ([[event_description objectForKey:@"subtype"] isEqualToString:@"scancode"])
			freerdp_input_send_keyboard_event(
			    input, [[event_description objectForKey:@"flags"] unsignedShortValue],
			    [[event_description objectForKey:@"scancode"] unsignedShortValue]);
		else if ([[event_description objectForKey:@"subtype"] isEqualToString:@"unicode"])
			freerdp_input_send_unicode_keyboard_event(
			    input, [[event_description objectForKey:@"flags"] unsignedShortValue],
			    [[event_description objectForKey:@"unicode_char"] unsignedShortValue]);
		else
			NSLog(@"%s: doesn't know how to send keyboard input with subtype %@", __func__,
			      [event_description objectForKey:@"subtype"]);
	}
	else if ([event_type isEqualToString:@"disconnect"])
		should_continue = FALSE;
	else if ([event_type isEqualToString:@"suspend"] ||
	         [event_type isEqualToString:@"resume"])
	{
		BOOL suspended = [event_type isEqualToString:@"suspend"];
		if (instance->context->gdi)
			(void)gdi_send_suppress_output(instance->context->gdi, suspended);
		(void)freerdp_settings_set_bool(instance->context->settings, FreeRDP_SuspendInput,
		                                 suspended);
	}
	else if ([event_type isEqualToString:@"resize"])
	{
		UINT32 width = [[event_description objectForKey:@"width"] unsignedIntValue];
		UINT32 height = [[event_description objectForKey:@"height"] unsignedIntValue];
		width = MIN(MAX(width, 200U), 8192U);
		height = MIN(MAX(height, 200U), 8192U);
		width &= ~1U;
		MONITOR_DEF monitor = { 0, 0, (INT32)width, (INT32)height, MONITOR_PRIMARY };
		if (!freerdp_display_send_monitor_layout(instance->context, 1, &monitor))
			WLog_WARN(TAG, "Display control resize request failed for %ux%u", width, height);
	}
	else
		NSLog(@"%s: unrecognized event type: %@", __func__, event_type);

	return should_continue;
}

BOOL ios_events_check_handle(mfInfo *mfi)
{
	WINPR_ASSERT(mfi);

	if (WaitForSingleObject(mfi->handle, 0) != WAIT_OBJECT_0)
		return TRUE;

	if (mfi->event_pipe_consumer == -1)
		return TRUE;

	uint32_t archived_data_length = 0;

	// First, read the length of the blob
	if (!ios_events_read_full(mfi->event_pipe_consumer, &archived_data_length, 4) ||
	    archived_data_length < 1 || archived_data_length > 32000)
	{
		NSLog(@"%s: invalid length descriptor, archived_data_length=%u", __func__,
		      archived_data_length);
		return FALSE;
	}

	// NSLog(@"reading %d bytes from input event pipe", archived_data_length);

	NSMutableData *archived_object_data =
	    [[NSMutableData alloc] initWithLength:archived_data_length];
	if (!ios_events_read_full(mfi->event_pipe_consumer, [archived_object_data mutableBytes],
	                          archived_data_length))
	{
		NSLog(@"%s: failed to read the complete event payload; wanted %u bytes.", __func__,
		      archived_data_length);
		[archived_object_data release];
		return FALSE;
	}

	NSError *error = nil;
	NSDictionary *unarchived_object_data = [NSKeyedUnarchiver
	    unarchivedObjectOfClasses:[NSSet setWithObjects:[NSDictionary class], [NSString class],
	                                                    [NSNumber class], nil]
	                     fromData:archived_object_data
	                        error:&error];
	[archived_object_data release];

	if (!unarchived_object_data)
	{
		// just return TRUE and ignore data. (if return FALSE, sesison can be terminated)
		NSLog(@"%s: Failed to unarchive input event: %@", __func__, error);
		return TRUE;
	}

	return ios_events_handle_event(mfi, unarchived_object_data);
}

HANDLE ios_events_get_handle(mfInfo *mfi)
{
	WINPR_ASSERT(mfi);
	return mfi->handle;
}

// Sets up the event pipe
BOOL ios_events_create_pipe(mfInfo *mfi)
{
	int pipe_fds[2];

	WINPR_ASSERT(mfi);

	if (pipe(pipe_fds) == -1)
	{
		NSLog(@"%s: pipe failed.", __func__);
		return FALSE;
	}

	mfi->event_pipe_consumer = pipe_fds[0];
	mfi->event_pipe_producer = pipe_fds[1];
	(void)fcntl(mfi->event_pipe_consumer, F_SETFD, FD_CLOEXEC);
	(void)fcntl(mfi->event_pipe_producer, F_SETFD, FD_CLOEXEC);
	mfi->handle = CreateFileDescriptorEvent(nullptr, FALSE, FALSE, mfi->event_pipe_consumer,
	                                        WINPR_FD_READ | WINPR_FD_WRITE);
	if (!mfi->handle)
	{
		close(mfi->event_pipe_consumer);
		close(mfi->event_pipe_producer);
		mfi->event_pipe_consumer = mfi->event_pipe_producer = -1;
		return FALSE;
	}
	return TRUE;
}

void ios_events_free_pipe(mfInfo *mfi)
{
	WINPR_ASSERT(mfi);
	int consumer_fd = mfi->event_pipe_consumer, producer_fd = mfi->event_pipe_producer;

	mfi->event_pipe_consumer = mfi->event_pipe_producer = -1;
	if (producer_fd != -1)
		close(producer_fd);
	if (consumer_fd != -1)
		close(consumer_fd);
	if (mfi->handle)
		(void)CloseHandle(mfi->handle);
	mfi->handle = nullptr;
}
