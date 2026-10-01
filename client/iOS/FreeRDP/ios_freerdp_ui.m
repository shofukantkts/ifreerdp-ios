/*
 RDP ui callbacks

 Copyright 2013 Thincast Technologies GmbH, Authors: Martin Fleisz, Dorian Johnson

 This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 If a copy of the MPL was not distributed with this file, You can obtain one at
 http://mozilla.org/MPL/2.0/.
 */

#import <Foundation/Foundation.h>

#import <freerdp/gdi/gdi.h>
#import "ios_freerdp_ui.h"

#import "RDPSession.h"
#import "CertificateTrustStore.h"

#pragma mark -
#pragma mark Certificate authentication

static void ios_resize_display_buffer(mfInfo *mfi);

static NSString *ios_string_or_empty(const char *value)
{
	if (!value)
		return @"";
	NSString *result = [NSString stringWithUTF8String:value];
	return result ? result : @"";
}

static BOOL ios_wait_for_ui_result(RDPSession *session, NSMutableDictionary *params)
{
	if (!session || !params)
		return NO;

	NSCondition *condition = [session uiRequestCompleted];
	NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:300.0];
	[condition lock];
	while (![params objectForKey:@"result"])
	{
		if (![condition waitUntilDate:deadline])
			break;
	}
	BOOL result = [[params objectForKey:@"result"] boolValue];
	[condition unlock];
	return result;
}

BOOL ios_ui_authenticate_ex(freerdp *instance, char **username, char **password, char **domain,
                            rdp_auth_reason reason)
{
	const char *target = freerdp_settings_get_server_name(instance->context->settings);
	switch (reason)
	{
		case AUTH_RDSTLS:
		case AUTH_NLA:
			break;

		case AUTH_TLS:
		case AUTH_RDP:
		case AUTH_SMARTCARD_PIN: /* in this case password is pin code */
		case AUTH_FIDO_PIN:
			if ((*username) && (*password))
				return TRUE;
			break;
		case GW_AUTH_HTTP:
		case GW_AUTH_RDG:
		case GW_AUTH_RPC:
			target =
			    freerdp_settings_get_string(instance->context->settings, FreeRDP_GatewayHostname);
			break;
		default:
			break;
	}

	mfInfo *mfi = MFI_FROM_INSTANCE(instance);
	NSMutableDictionary *params = [NSMutableDictionary
	    dictionaryWithObjectsAndKeys:ios_string_or_empty(*username), @"username",
	                                 ios_string_or_empty(*password), @"password",
	                                 ios_string_or_empty(*domain), @"domain",
	                                 ios_string_or_empty(target), @"hostname", nil];
	// request auth UI
	[mfi->session performSelectorOnMainThread:@selector(sessionRequestsAuthenticationWithParams:)
	                               withObject:params
	                            waitUntilDone:YES];
	if (!ios_wait_for_ui_result(mfi->session, params))
	{
		mfi->unwanted = YES;
		return FALSE;
	}

	// Free old values
	free(*username);
	free(*password);
	free(*domain);
	// set values back
	*username = _strdup([ios_string_or_empty([[params objectForKey:@"username"] UTF8String]) UTF8String]);
	*password = _strdup([ios_string_or_empty([[params objectForKey:@"password"] UTF8String]) UTF8String]);
	*domain = _strdup([ios_string_or_empty([[params objectForKey:@"domain"] UTF8String]) UTF8String]);

	if (!(*username) || !(*password) || !(*domain))
	{
		free(*username);
		free(*password);
		free(*domain);
		return FALSE;
	}

	return TRUE;
}

static DWORD ios_ui_verify_certificate_internal(
    freerdp *instance, const char *host, UINT16 port, const char *common_name, const char *subject,
    const char *issuer, const char *fingerprint, const char *old_subject, const char *old_issuer,
    const char *old_fingerprint, DWORD flags)
{
	(void)flags;
	NSString *hostString = ios_string_or_empty(host);
	NSString *fingerprintString = ios_string_or_empty(fingerprint);
	if ([CertificateTrustStore isFingerprint:fingerprintString
	                              trustedForHost:hostString
	                                        port:port])
		return 1;

	mfInfo *mfi = MFI_FROM_INSTANCE(instance);
	if (!mfi || !mfi->session)
		return 0;

	NSMutableDictionary *params = [NSMutableDictionary
	    dictionaryWithObjectsAndKeys:hostString, @"hostname",
	                                 [NSNumber numberWithUnsignedShort:port], @"port",
	                                 ios_string_or_empty(common_name), @"common_name",
	                                 ios_string_or_empty(subject), @"subject",
	                                 ios_string_or_empty(issuer), @"issuer",
	                                 fingerprintString, @"fingerprint",
	                                 ios_string_or_empty(old_subject), @"old_subject",
	                                 ios_string_or_empty(old_issuer), @"old_issuer",
	                                 ios_string_or_empty(old_fingerprint), @"old_fingerprint", nil];
	// request certificate verification UI
	[mfi->session performSelectorOnMainThread:@selector(sessionVerifyCertificateWithParams:)
	                               withObject:params
	                            waitUntilDone:YES];

	if (!ios_wait_for_ui_result(mfi->session, params))
	{
		mfi->unwanted = YES;
		return 0;
	}

	if ([fingerprintString length] > 0)
		(void)[CertificateTrustStore trustFingerprint:fingerprintString
	                                           forHost:hostString
                                              port:port];
	return 1;
}

DWORD ios_ui_verify_certificate_ex(freerdp *instance, const char *host, UINT16 port,
                                   const char *common_name, const char *subject, const char *issuer,
                                   const char *fingerprint, DWORD flags)
{
	return ios_ui_verify_certificate_internal(instance, host, port, common_name, subject, issuer,
	                                           fingerprint, nullptr, nullptr, nullptr, flags);
}

DWORD ios_ui_verify_changed_certificate_ex(freerdp *instance, const char *host, UINT16 port,
                                           const char *common_name, const char *subject,
                                           const char *issuer, const char *fingerprint,
                                           const char *old_subject, const char *old_issuer,
                                           const char *old_fingerprint, DWORD flags)
{
	return ios_ui_verify_certificate_internal(instance, host, port, common_name, subject, issuer,
	                                           fingerprint, old_subject, old_issuer, old_fingerprint,
	                                           flags);
}

#pragma mark -
#pragma mark Graphics updates

BOOL ios_ui_begin_paint(rdpContext *context)
{
	WINPR_ASSERT(context);
	mfInfo *mfi = MFI_FROM_INSTANCE(context->instance);
	WINPR_ASSERT(mfi);

	rdpGdi *gdi = context->gdi;
	WINPR_ASSERT(gdi);
	WINPR_ASSERT(gdi->primary);

	HGDI_DC hdc = gdi->primary->hdc;
	WINPR_ASSERT(hdc);
	if (!hdc->hwnd)
		return TRUE;

	HGDI_WND hwnd = hdc->hwnd;
	if (!hwnd->invalid)
		return TRUE;
	if (mfi->bitmap_mutex_initialized)
	{
		pthread_mutex_lock(&mfi->bitmap_mutex);
		mfi->bitmap_lock_held = TRUE;
	}
	hwnd->invalid->null = TRUE;
	return TRUE;
}

BOOL ios_ui_end_paint(rdpContext *context)
{
	WINPR_ASSERT(context);

	mfInfo *mfi = MFI_FROM_INSTANCE(context->instance);
	WINPR_ASSERT(mfi);

	rdpGdi *gdi = context->gdi;
	WINPR_ASSERT(gdi);
	WINPR_ASSERT(gdi->primary);

	HGDI_DC hdc = gdi->primary->hdc;
	WINPR_ASSERT(hdc);
	if (!hdc->hwnd)
		return TRUE;

	HGDI_WND hwnd = hdc->hwnd;
	WINPR_ASSERT(hwnd->invalid || (hwnd->ninvalid == 0));

	if (!hwnd->invalid || hwnd->ninvalid == 0)
	{
		if (mfi->bitmap_lock_held)
		{
			mfi->bitmap_lock_held = FALSE;
			pthread_mutex_unlock(&mfi->bitmap_mutex);
		}
		return TRUE;
	}

	if (hwnd->invalid->null)
	{
		if (mfi->bitmap_lock_held)
		{
			mfi->bitmap_lock_held = FALSE;
			pthread_mutex_unlock(&mfi->bitmap_mutex);
		}
		return TRUE;
	}

	CGRect dirty_rect =
	    CGRectMake(hwnd->invalid->x, hwnd->invalid->y, hwnd->invalid->w, hwnd->invalid->h);

	if (!hwnd->invalid->null)
		[mfi->session performSelectorOnMainThread:@selector(setNeedsDisplayInRectAsValue:)
		                               withObject:[NSValue valueWithCGRect:dirty_rect]
		                            waitUntilDone:NO];
	if (mfi->bitmap_lock_held)
	{
		mfi->bitmap_lock_held = FALSE;
		pthread_mutex_unlock(&mfi->bitmap_mutex);
	}

	return TRUE;
}

BOOL ios_ui_resize_window(rdpContext *context)
{
	rdpSettings *settings;
	rdpGdi *gdi;

	if (!context || !context->settings)
		return FALSE;

	settings = context->settings;
	gdi = context->gdi;

	if (!gdi_resize(gdi, freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth),
	                freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight)))
		return FALSE;

	ios_resize_display_buffer(MFI_FROM_INSTANCE(context->instance));
	return TRUE;
}

#pragma mark -
#pragma mark Exported

static void ios_create_bitmap_context(mfInfo *mfi)
{
	[mfi->session performSelectorOnMainThread:@selector(sessionBitmapContextWillChange)
	                               withObject:nil
	                            waitUntilDone:YES];
	rdpGdi *gdi = mfi->instance->context->gdi;
	CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();

	if (FreeRDPGetBytesPerPixel(gdi->dstFormat) == 2)
		mfi->bitmap_context = CGBitmapContextCreate(
		    gdi->primary_buffer, gdi->width, gdi->height, 5, gdi->stride, colorSpace,
		    kCGBitmapByteOrder16Little | kCGImageAlphaNoneSkipFirst);
	else
		mfi->bitmap_context = CGBitmapContextCreate(
		    gdi->primary_buffer, gdi->width, gdi->height, 8, gdi->stride, colorSpace,
		    kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst);

	CGColorSpaceRelease(colorSpace);
	[mfi->session performSelectorOnMainThread:@selector(sessionBitmapContextDidChange)
	                               withObject:nil
	                            waitUntilDone:YES];
}

void ios_allocate_display_buffer(mfInfo *mfi)
{
	ios_create_bitmap_context(mfi);
}

void ios_resize_display_buffer(mfInfo *mfi)
{
	// Release the old context in a thread-safe manner
	CGContextRef old_context = mfi->bitmap_context;
	mfi->bitmap_context = nullptr;
	if (old_context)
		CGContextRelease(old_context);
	// Create the new context
	ios_create_bitmap_context(mfi);
}
