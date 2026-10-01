/*
 Password Encryptor

 Copyright 2013 Thincast Technologies GmbH, Author: Dorian Johnson
 Copyright 2026 iFreeRDP contributors

 This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 If a copy of the MPL was not distributed with this file, You can obtain one at
 http://mozilla.org/MPL/2.0/.
 */

#import "Encryptor.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

#define RDP_ENVELOPE_MAGIC "RDP2"
#define RDP_ENVELOPE_MAGIC_LENGTH 4
#define RDP_ENVELOPE_SALT_LENGTH 16
#define RDP_ENVELOPE_IV_LENGTH 16
#define RDP_ENVELOPE_MAC_LENGTH 32
#define RDP_ENVELOPE_DERIVED_KEY_LENGTH 64
#define RDP_ENVELOPE_PBKDF2_ROUNDS 120000

@interface Encryptor (Private)
- (NSData *)randomDataWithLength:(NSUInteger)length;
- (NSData *)randomInitializationVector;
@end

static BOOL deriveEnvelopeKeys(NSString *password, NSData *salt, uint8_t *encryptionKey,
                               uint8_t *macKey)
{
    const char *passwordBytes = [password UTF8String];
    if (!passwordBytes)
        return NO;

    uint8_t derived[RDP_ENVELOPE_DERIVED_KEY_LENGTH] = { 0 };
    int ret = CCKeyDerivationPBKDF(
        kCCPBKDF2, passwordBytes, strlen(passwordBytes), [salt bytes], [salt length],
        kCCPRFHmacAlgSHA256, RDP_ENVELOPE_PBKDF2_ROUNDS, derived, sizeof(derived));
    if (ret != kCCSuccess)
        return NO;

    memcpy(encryptionKey, derived, kCCKeySizeAES256);
    memcpy(macKey, derived + kCCKeySizeAES256, CC_SHA256_DIGEST_LENGTH);
    memset(derived, 0, sizeof(derived));
    return YES;
}

static BOOL constantTimeEqual(const uint8_t *left, const uint8_t *right, size_t length)
{
    uint8_t difference = 0;
    for (size_t index = 0; index < length; index++)
        difference |= left[index] ^ right[index];
    return difference == 0;
}

@implementation Encryptor

@synthesize plaintextPassword = _plaintext_password;

- (id)initWithPassword:(NSString *)plaintext_password
{
    if (plaintext_password == nil)
        return nil;

    if (!(self = [super init]))
        return nil;

    _plaintext_password = [plaintext_password retain];
    const char *plaintext_password_data =
        [plaintext_password length] ? [plaintext_password UTF8String] : " ";
    if (!plaintext_password_data || !strlen(plaintext_password_data))
        [NSException raise:NSInternalInconsistencyException
                    format:@"%s: plaintext password data is zero length!", __func__];

    // Preserve the original derivation for decrypting existing RDP1 records.
    // New records use PBKDF2-SHA256 with a random salt and an authenticated
    // envelope.
    uint8_t *derived_key = calloc(1, TSXEncryptorPBKDF2KeySize);
    if (!derived_key)
    {
        [self release];
        return nil;
    }

    size_t legacyPasswordLength = strlen(plaintext_password_data);
    if (legacyPasswordLength > 0)
        legacyPasswordLength -= 1;
    int ret = CCKeyDerivationPBKDF(
        kCCPBKDF2, plaintext_password_data, legacyPasswordLength,
        (const uint8_t *)TSXEncryptorPBKDF2Salt, TSXEncryptorPBKDF2SaltLen,
        kCCPRFHmacAlgSHA1, TSXEncryptorPBKDF2Rounds, derived_key, TSXEncryptorPBKDF2KeySize);
    if (ret != kCCSuccess)
    {
        free(derived_key);
        [self release];
        return nil;
    }

    _encryption_key = [[NSData alloc] initWithBytesNoCopy:derived_key
                                                   length:TSXEncryptorPBKDF2KeySize
                                             freeWhenDone:YES];
    return self;
}

- (void)dealloc
{
    [_encryption_key release];
    [_plaintext_password release];
    [super dealloc];
}

#pragma mark - Encrypting/decrypting data

- (NSData *)encryptData:(NSData *)plaintext_data
{
    if (![plaintext_data length])
        return nil;

    NSData *salt = [self randomDataWithLength:RDP_ENVELOPE_SALT_LENGTH];
    NSData *iv = [self randomInitializationVector];
    if (!salt || !iv)
        return nil;

    uint8_t encryptionKey[kCCKeySizeAES256] = { 0 };
    uint8_t macKey[CC_SHA256_DIGEST_LENGTH] = { 0 };
    if (!deriveEnvelopeKeys(_plaintext_password, salt, encryptionKey, macKey))
        return nil;

    NSMutableData *ciphertext =
        [NSMutableData dataWithLength:[plaintext_data length] + TSXEncryptorBlockCipherBlockSize];
    size_t ciphertextLength = 0;
    int ret = CCCrypt(kCCEncrypt, TSXEncryptorBlockCipherAlgo, TSXEncryptorBlockCipherOptions,
                      encryptionKey, sizeof(encryptionKey), [iv bytes], [plaintext_data bytes],
                      [plaintext_data length], [ciphertext mutableBytes], [ciphertext length],
                      &ciphertextLength);
    memset(encryptionKey, 0, sizeof(encryptionKey));
    if (ret != kCCSuccess)
    {
        memset(macKey, 0, sizeof(macKey));
        return nil;
    }
    [ciphertext setLength:ciphertextLength];

    NSMutableData *envelope =
        [NSMutableData dataWithCapacity:RDP_ENVELOPE_MAGIC_LENGTH + [salt length] + [iv length] +
                                         [ciphertext length] + RDP_ENVELOPE_MAC_LENGTH];
    [envelope appendBytes:RDP_ENVELOPE_MAGIC length:RDP_ENVELOPE_MAGIC_LENGTH];
    [envelope appendData:salt];
    [envelope appendData:iv];
    [envelope appendData:ciphertext];

    uint8_t mac[RDP_ENVELOPE_MAC_LENGTH] = { 0 };
    CCHmac(kCCHmacAlgSHA256, macKey, sizeof(macKey), [envelope bytes], [envelope length], mac);
    memset(macKey, 0, sizeof(macKey));
    [envelope appendBytes:mac length:sizeof(mac)];
    return envelope;
}

- (NSData *)decryptData:(NSData *)encrypted_data
{
    const NSUInteger legacyHeaderLength = TSXEncryptorBlockCipherBlockSize;
    const NSUInteger envelopeMinimumLength = RDP_ENVELOPE_MAGIC_LENGTH +
                                              RDP_ENVELOPE_SALT_LENGTH +
                                              RDP_ENVELOPE_IV_LENGTH +
                                              RDP_ENVELOPE_MAC_LENGTH +
                                              TSXEncryptorBlockCipherBlockSize;
    const uint8_t *bytes = [encrypted_data bytes];

    if ([encrypted_data length] >= RDP_ENVELOPE_MAGIC_LENGTH && bytes &&
        memcmp(bytes, RDP_ENVELOPE_MAGIC, RDP_ENVELOPE_MAGIC_LENGTH) == 0)
    {
        if ([encrypted_data length] < envelopeMinimumLength)
            return nil;

        const uint8_t *saltBytes = bytes + RDP_ENVELOPE_MAGIC_LENGTH;
        const uint8_t *ivBytes = saltBytes + RDP_ENVELOPE_SALT_LENGTH;
        const NSUInteger cipherOffset =
            RDP_ENVELOPE_MAGIC_LENGTH + RDP_ENVELOPE_SALT_LENGTH + RDP_ENVELOPE_IV_LENGTH;
        const NSUInteger macOffset = [encrypted_data length] - RDP_ENVELOPE_MAC_LENGTH;
        const NSUInteger cipherLength = macOffset - cipherOffset;
        if (cipherLength == 0 || (cipherLength % TSXEncryptorBlockCipherBlockSize) != 0)
            return nil;

        NSData *salt = [NSData dataWithBytes:saltBytes length:RDP_ENVELOPE_SALT_LENGTH];
        uint8_t encryptionKey[kCCKeySizeAES256] = { 0 };
        uint8_t macKey[CC_SHA256_DIGEST_LENGTH] = { 0 };
        if (!deriveEnvelopeKeys(_plaintext_password, salt, encryptionKey, macKey))
            return nil;

        uint8_t expectedMac[RDP_ENVELOPE_MAC_LENGTH] = { 0 };
        CCHmac(kCCHmacAlgSHA256, macKey, sizeof(macKey), bytes, macOffset, expectedMac);
        BOOL valid = constantTimeEqual(expectedMac, bytes + macOffset, sizeof(expectedMac));
        memset(macKey, 0, sizeof(macKey));
        if (!valid)
        {
            memset(encryptionKey, 0, sizeof(encryptionKey));
            return nil;
        }

        NSMutableData *plaintext = [NSMutableData dataWithLength:cipherLength];
        size_t plaintextLength = 0;
        int ret = CCCrypt(kCCDecrypt, TSXEncryptorBlockCipherAlgo,
                          TSXEncryptorBlockCipherOptions, encryptionKey, sizeof(encryptionKey),
                          ivBytes, bytes + cipherOffset, cipherLength, [plaintext mutableBytes],
                          [plaintext length], &plaintextLength);
        memset(encryptionKey, 0, sizeof(encryptionKey));
        if (ret != kCCSuccess)
            return nil;
        [plaintext setLength:plaintextLength];
        return plaintext;
    }

    // Legacy RDP1 format: IV(16) || AES-CBC ciphertext. Keep this path so an
    // upgrade does not destroy existing saved profiles. The next save rewrites
    // the value using the authenticated RDP2 envelope above.
    if (!bytes || [encrypted_data length] <= legacyHeaderLength ||
        (([encrypted_data length] - legacyHeaderLength) % TSXEncryptorBlockCipherBlockSize) != 0)
        return nil;

    NSUInteger cipherLength = [encrypted_data length] - legacyHeaderLength;
    NSMutableData *plaintext = [NSMutableData dataWithLength:cipherLength];
    size_t plaintextLength = 0;
    int ret = CCCrypt(kCCDecrypt, TSXEncryptorBlockCipherAlgo, TSXEncryptorBlockCipherOptions,
                      [_encryption_key bytes], TSXEncryptorBlockCipherKeySize, bytes,
                      bytes + legacyHeaderLength, cipherLength, [plaintext mutableBytes],
                      [plaintext length], &plaintextLength);
    if (ret != kCCSuccess)
        return nil;
    [plaintext setLength:plaintextLength];
    return plaintext;
}

- (NSData *)encryptString:(NSString *)plaintext_string
{
    return [self encryptData:[plaintext_string dataUsingEncoding:NSUTF8StringEncoding]];
}

- (NSString *)decryptString:(NSData *)encrypted_string
{
    NSData *plaintext = [self decryptData:encrypted_string];
    return [[[NSString alloc] initWithData:plaintext encoding:NSUTF8StringEncoding] autorelease];
}

- (NSData *)randomDataWithLength:(NSUInteger)length
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    if (SecRandomCopyBytes(kSecRandomDefault, length, [data mutableBytes]) != errSecSuccess)
        return nil;
    return data;
}

- (NSData *)randomInitializationVector
{
    return [self randomDataWithLength:RDP_ENVELOPE_IV_LENGTH];
}

@end
