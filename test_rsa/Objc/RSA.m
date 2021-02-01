//
//  RSA.m
//  RSA
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//
#import <CommonCrypto/CommonDigest.h>
#import "RSA.h"

#if DEBUG
#define LOGGING_FACILITY(X, Y)    \
NSAssert(X, Y);

#define LOGGING_FACILITY1(X, Y, Z)    \
NSAssert1(X, Y, Z);
#else
#define LOGGING_FACILITY(X, Y)    \
if (!(X)) {            \
NSLog(Y);        \
}

#define LOGGING_FACILITY1(X, Y, Z)    \
if (!(X)) {                \
NSLog(Y, Z);        \
}
#endif

@interface RSA (){
    @private
    NSData * publicTag;
    NSData * privateTag;
    size_t kSecAttrKeySizeInBitsLength;
    CFTypeRef cfType;
}
    @property (strong, nonatomic) NSString * publicIdentifier;
    @property (strong, nonatomic) NSString * privateIdentifier;
    
    @property (nonatomic,readonly) SecKeyRef publicKeyRef;
    @property (nonatomic,readonly) SecKeyRef privateKeyRef;
    
    @property (nonatomic,readonly) NSData   * publicKeyBits;
    @property (nonatomic,readonly) NSData   * privateKeyBits;
    
    @end

@implementation RSA
    
    @synthesize publicKeyRef, privateKeyRef;
    
    
#pragma mark - Instance Variables
    
- (id)init {
    if (self = [super init]) {
        kSecAttrKeySizeInBitsLength = k2048;
        cfType = kSecAttrKeyTypeRSA;
    }
    return self;
}
    
+ (instancetype)sharedInstance{
    static RSA *_rsa = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _rsa = [[self alloc] init];
    });
    return _rsa;
}
    
#pragma mark - Set identifier strings
    
- (void)setIdentifierForPublicKey:(nullable NSString *)pubIdentifier
                       privateKey:(nullable NSString *)privIdentifier {
    
    self.publicIdentifier =
    (pubIdentifier != NULL) ? pubIdentifier : @"com.rsa.pubIdentifier";
    self.privateIdentifier =
    (privIdentifier != NULL) ? privIdentifier : @"com.rsa.privIdentifier";
    
    // Tag data to search for keys.
    publicTag       = [self.publicIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    privateTag      = [self.privateIdentifier dataUsingEncoding:NSUTF8StringEncoding];
}
    
- (void)setRSAKeySize:(RSAKeySize)keySize {
    kSecAttrKeySizeInBitsLength = keySize;
}
    
#pragma mark - PEM helpers
    
- (NSString *)stripPEM:(NSString *)keyString {
    NSError *error = nil;
    NSString *pattern = @"-{5}.*-{5}\n*" ;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:NSRegularExpressionCaseInsensitive error:&error];
    return [regex stringByReplacingMatchesInString:keyString options:0 range:NSMakeRange(0, keyString.length) withTemplate:@""];
}
    
#pragma mark - Java Helpers
    
    // Java helpers to remove and add extra bits needed for java based backends
    // Once it’s base 64 decoded it strips the ASN.1 encoding associated with the OID
    // and sequence encoding that generally prepends the RSA key data. That leaves it
    // with just the large numbers that make up the public key.
    // Read this for a clear understanding of ANS.1, BER AND PCKS encodings
    // https://stackoverflow.com/a/29707204/1460582
    
- (NSString *)getKeyForJavaServer:(NSData*)keyBits {
    
    if (!keyBits || keyBits.length == 0) {
        return nil;
    }
    
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        
    };
    
    // That gives us the "BITSTRING component of a full DER
    // encoded RSA public key - We now need to build the rest
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    
    if  ([keyBits length ] + 1  < 128 )
    bitstringEncLength = 1 ;
    else
    bitstringEncLength = (int)(([keyBits length] + 1 ) / 256 ) + 2;
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [keyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [keyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:keyBits];
    
    // base64 encode encKey and return
    return [encKey base64EncodedStringWithOptions:0];
    
}
    
    size_t encodeLength(unsigned char * buf, size_t length) {
        
        // encode length in ASN.1 DER format
        if (length < 128) {
            buf[0] = length;
            return 1;
        }
        
        size_t i = (length / 256) + 1;
        buf[0] = i + 0x80;
        for (size_t j = 0 ; j < i; ++j) {
            buf[i - j] = length & 0xFF;
            length = length >> 8;
        }
        
        return i + 1;
    }
    
#pragma mark - Restore
    
- (BOOL)restoreIfExists {
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    
    [self getKeyRefFor:publicTag keyRef:&publicKeyRef];
    [self getKeyRefFor:privateTag keyRef:&privateKeyRef];
    
    return (publicKeyRef && privateKeyRef);
}
    
    
    
#pragma mark - Key generators
    
- (void)generateRSAKeyPairIfNeed:(RSACompletionBlock)completion {
    if (self.restoreIfExists) {
        if (completion != nil) {
            completion();
        }
    } else {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self generateKeyPairRSA];
            
            if (completion != nil) {
                dispatch_async(dispatch_get_main_queue(), completion);
            }
        });
    }
}
    
- (void)generateKeyPairRSA {
    OSStatus sanityCheck = noErr;
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    
    // First delete current keys.
    [self deleteAsymmetricKeys];
    
    NSDictionary *privateKeyAttr = @{
                            (id)kSecAttrIsPermanent: @YES,
                            (id)kSecAttrApplicationTag: privateTag
                            };
    
    NSDictionary *publicKeyAttr = @{
                                     (id)kSecAttrIsPermanent: @YES,
                                     (id)kSecAttrApplicationTag: publicTag
                                     };
    
    NSDictionary *keyPairAttr = @{
                                  (id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                  (id)kSecAttrKeySizeInBits: @(kSecAttrKeySizeInBitsLength),
                                  (id)kSecPrivateKeyAttrs: privateKeyAttr,
                                  (id)kSecPublicKeyAttrs: publicKeyAttr
                                  };
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    LOGGING_FACILITY( sanityCheck == noErr && publicKeyRef != NULL && privateKeyRef != NULL, @"Something went wrong with generating the key pair." );
}
    
#pragma mark - Deletion
    
- (void)deleteAsymmetricKeys {
    
    OSStatus sanityCheck = noErr;
    
    
    NSDictionary *queryPublicKey = @{
                            (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: publicTag,
                            (id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                            };
    
    NSDictionary *queryPrivateKey = @{
                                     (id)kSecClass: (id)kSecClassKey,
                                     (id)kSecAttrApplicationTag: privateTag,
                                     (id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                     };
 
    
    // Delete the private key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing private key, OSStatus == %ld.", (long)sanityCheck );
    
    // Delete the public key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPublicKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing public key, OSStatus == %ld.", (long)sanityCheck );
    
    
    if (publicKeyRef) CFRelease(publicKeyRef);
    if (privateKeyRef) CFRelease(privateKeyRef);
    
    publicKeyRef = NULL;
    privateKeyRef = NULL;
}
    
#pragma mark - Read Bits
    
    
- (CFTypeRef)readKey:(NSData *)tag keyType:(CFTypeRef)keyType {
    
    CFTypeRef  _keyBitsReference = NULL;
    NSDictionary *query = @{
                            (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag,
                            (id)kSecAttrKeyType: (__bridge id)keyType,
                            (id)kSecReturnData: @YES,
                            };
    
    // Get the key bits.
    OSStatus sanityCheck = noErr;
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&_keyBitsReference);
    
    if (sanityCheck != noErr) {
        _keyBitsReference = NULL;
    }
    
    return _keyBitsReference;
}
    
- (NSData *)readKeyBits:(NSData *)tag keyType:(CFTypeRef)keyType {
    CFTypeRef keyRef = [self readKey:tag keyType:keyType];
    NSData *passDat = (__bridge_transfer NSData *)keyRef;
    
    return passDat;
    
}
    
- (NSData *)publicKeyBits {
    return [self readKeyBits:publicTag keyType:kSecAttrKeyTypeRSA];
}
    
- (NSData *)privateKeyBits {
    return [self readKeyBits:privateTag keyType:kSecAttrKeyTypeRSA];
}
    
#pragma mark - Get Refs
    
- (void)getKeyRefFor:(NSData *)tag keyRef:(SecKeyRef *)keyRef {
    
    NSDictionary *query = @{
                            (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag,
                            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                            (id)kSecReturnRef: @YES,
                            };
    
    // Get the key.
    OSStatus resultCode = noErr;
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)keyRef);
    
    if(resultCode != noErr)
    {
        *keyRef = NULL;
    }
    
    query = nil;
}
    
    
#pragma mark - Encrypt and Decrypt
    
- (NSString *)rsaEncryptWithData:(NSData*)data {
    
    SecKeyRef key = self.publicKeyRef;
    
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0*0, cipherBufferSize);
    
    NSData *plainTextBytes = data;
    size_t blockSize = cipherBufferSize - 11;
    size_t blockCount = (size_t)ceil([plainTextBytes length] / (double)blockSize);
    NSMutableData *encryptedData = [NSMutableData dataWithCapacity:0];
    
    for (int i=0; i<blockCount; i++) {
        
        int bufferSize = (int)MIN(blockSize,[plainTextBytes length] - i * blockSize);
        NSData *buffer = [plainTextBytes subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        
        OSStatus status = SecKeyEncrypt(key,
                                        kSecPaddingPKCS1,
                                        (const uint8_t *)[buffer bytes],
                                        [buffer length],
                                        cipherBuffer,
                                        &cipherBufferSize);
        
        if (status == noErr){
            NSData *encryptedBytes = [NSData dataWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            [encryptedData appendData:encryptedBytes];
            
        }else{
            
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            return nil;
        }
    }
    if (cipherBuffer) free(cipherBuffer);
    
    return [encryptedData base64EncodedStringWithOptions:0];
}
    
- (NSString *)decrypt:(NSData*)data error:(NSError **)error {
    NSData *wrappedSymmetricKey = data;
    SecKeyRef key = self.privateKeyRef;
    
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    size_t keyBufferSize = [wrappedSymmetricKey length];
    
    NSMutableData *bits = [NSMutableData dataWithLength:keyBufferSize];
    OSStatus sanityCheck = SecKeyDecrypt(key,
                                         kSecPaddingPKCS1,
                                         (const uint8_t *) [wrappedSymmetricKey bytes],
                                         cipherBufferSize,
                                         [bits mutableBytes],
                                         &keyBufferSize);
    
    if (sanityCheck != 0) {
        NSError *sanityError = [NSError errorWithDomain:NSOSStatusErrorDomain code:sanityCheck userInfo:nil];
        NSLog(@"Error: %@", [sanityError description]);
        if (error != NULL) {
            *error = sanityError;
        }
        return nil;
    }
    
    NSAssert(sanityCheck == noErr, @"Error decrypting, OSStatus == %ld.", (long)sanityCheck);
    
    [bits setLength:keyBufferSize];
    
    return [[NSString alloc] initWithData:bits
                                 encoding:NSUTF8StringEncoding];
}
    
    
#pragma mark - Public Key getters
    
- (NSString *)getPublicKeyAsBase64 {
    return [[self publicKeyBits] base64EncodedStringWithOptions:0];
}
    
- (NSString *)getPublicKeyAsBase64ForJavaServer {
    return [self getKeyForJavaServer:[self publicKeyBits]];
}

- (NSString *)getPrivateKeyAsBase64 {
    return [[self privateKeyBits] base64EncodedStringWithOptions:0];
}
    
#pragma mark - Encrypt helpers
    
- (NSString *)encrypt:(NSData *)data{
    return [self rsaEncryptWithData:data];
}
    
#pragma mark - Decrypt helpers
    

#pragma mark - Sign & Verify
    
    
- (NSData *)sign:(NSData *)plainData
    {
        SecKeyRef privateKey = self.privateKeyRef;
        
        if (privateKey == nil) return nil;
        
        size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
        uint8_t* signedHashBytes = malloc(signedHashBytesSize);
        memset(signedHashBytes, 0x0, signedHashBytesSize);
        
        size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
        uint8_t* hashBytes = malloc(hashBytesSize);
        if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
            if (hashBytes)
                free(hashBytes);
            if (signedHashBytes)
                free(signedHashBytes);
                
            return nil;
        }
        
        SecKeyRawSign(privateKey,
                      kSecPaddingPKCS1SHA256,
                      hashBytes,
                      hashBytesSize,
                      signedHashBytes,
                      &signedHashBytesSize);
        
        NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                            length:(NSUInteger)signedHashBytesSize];
        
        if (hashBytes)
        free(hashBytes);
        if (signedHashBytes)
        free(signedHashBytes);
        
        return signedHash;
    }
    
- (BOOL)verify:(NSData *)plainData signature:(NSData *)signature
{
    SecKeyRef publicKey = self.publicKeyRef;
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signature bytes];
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        if (hashBytes)
            free(hashBytes);
        return NO;
    }
    
    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    if (hashBytes)
        free(hashBytes);
    
    return status == errSecSuccess;
}
    
@end
