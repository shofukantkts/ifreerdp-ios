/*
 Certificate trust-on-first-use store for iFreeRDP.

 Copyright 2026 iFreeRDP contributors

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0
 */

#import "CertificateTrustStore.h"
#import <Security/Security.h>

static NSString *const kCertificateTrustService = @"com.ifreerdp.certificate-trust";

@interface CertificateTrustStore (Private)
+ (NSString *)normalizedFingerprint:(NSString *)fingerprint;
+ (NSString *)accountForHost:(NSString *)host port:(NSUInteger)port;
+ (NSMutableDictionary *)queryForHost:(NSString *)host port:(NSUInteger)port;
@end

@implementation CertificateTrustStore

+ (NSString *)normalizedFingerprint:(NSString *)fingerprint
{
	NSMutableString *normalized = [NSMutableString string];
	for (NSUInteger index = 0; index < [fingerprint length]; index++)
	{
		unichar character = [fingerprint characterAtIndex:index];
		if ([[NSCharacterSet alphanumericCharacterSet] characterIsMember:character])
			[normalized appendFormat:@"%C", character];
	}
	return [normalized uppercaseString];
}

+ (NSString *)accountForHost:(NSString *)host port:(NSUInteger)port
{
	NSString *normalizedHost = [[host lowercaseString]
	    stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
	return [NSString stringWithFormat:@"%@:%lu", normalizedHost, (unsigned long)port];
}

+ (NSMutableDictionary *)queryForHost:(NSString *)host port:(NSUInteger)port
{
	return [NSMutableDictionary dictionaryWithObjectsAndKeys:
	    (id)kSecClassGenericPassword, (id)kSecClass,
	    kCertificateTrustService, (id)kSecAttrService,
	    [self accountForHost:host port:port], (id)kSecAttrAccount, nil];
}

+ (BOOL)isFingerprint:(NSString *)fingerprint
             trustedForHost:(NSString *)host
                       port:(NSUInteger)port
{
	fingerprint = [self normalizedFingerprint:fingerprint];
	if ([fingerprint length] == 0 || [host length] == 0)
		return NO;

	NSMutableDictionary *query = [self queryForHost:host port:port];
	[query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
	[query setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];

	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
	if (status != errSecSuccess || result == NULL)
		return NO;

	NSData *storedData = (NSData *)result;
	NSString *storedFingerprint = [[[NSString alloc] initWithData:storedData
	                                                       encoding:NSUTF8StringEncoding]
	    autorelease];
	CFRelease(result);
	return [[self normalizedFingerprint:storedFingerprint] isEqualToString:fingerprint];
}

+ (BOOL)trustFingerprint:(NSString *)fingerprint
                 forHost:(NSString *)host
                    port:(NSUInteger)port
{
	fingerprint = [self normalizedFingerprint:fingerprint];
	if ([fingerprint length] == 0 || [host length] == 0)
		return NO;

	NSData *data = [fingerprint dataUsingEncoding:NSUTF8StringEncoding];
	NSMutableDictionary *query = [self queryForHost:host port:port];
	NSDictionary *attributes = [NSDictionary dictionaryWithObjectsAndKeys:
	    data, (id)kSecValueData,
	    (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, (id)kSecAttrAccessible, nil];

	OSStatus status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)attributes);
	if (status == errSecItemNotFound)
	{
		[query setObject:data forKey:(id)kSecValueData];
		[query setObject:(id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
	              forKey:(id)kSecAttrAccessible];
		status = SecItemAdd((CFDictionaryRef)query, NULL);
	}

	return status == errSecSuccess;
}

+ (BOOL)deleteAllTrustedCertificates
{
	NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
	    (id)kSecClassGenericPassword, (id)kSecClass,
    kCertificateTrustService, (id)kSecAttrService, nil];
	OSStatus status = SecItemDelete((CFDictionaryRef)query);
	return status == errSecSuccess || status == errSecItemNotFound;
}

@end
