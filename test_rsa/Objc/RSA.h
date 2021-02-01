//
//  RSA Wrapper
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^RSACompletionBlock)(void);

@interface RSA : NSObject

typedef enum RSAKeySize: NSInteger {
    k512 = 512,
    k768 = 768,
    k1024 = 1024,
    k2048 = 2048,
} RSAKeySize;

/**
 *  Steps to Follow
 *
 *  Step 1: Start a sharedInstance
 *  Step 2: Set the Public and Private Identifiers
 *  Step 3: Generate/Restore public/private keys for device
 *  Step 4: Encrypt/Decrypt using helpers
 *  Step 5: Sign/Verify using helpers
 *
 *  Note: Public, private identifiers can be any string used
 *        to uniquely identify the keys stored in keychain.
 */

+ (instancetype)sharedInstance;

- (void)setIdentifierForPublicKey:(NSString *)pubIdentifier
                       privateKey:(NSString *)privIdentifier;
    
- (void)setRSAKeySize:(RSAKeySize)keySize;

// restore keys
- (BOOL)restoreIfExists;
    
// Generation Methods
- (void)generateRSAKeyPairIfNeed:(RSACompletionBlock)completion;
    
- (void)deleteAsymmetricKeys;

// Encryption Methods
- (NSString *)encrypt:(NSData *)data;

// Decrypt Methods
- (NSString *)decrypt:(NSData*)data error:(NSError **)error;

// Accessors for Public Key
- (NSString *)getPublicKeyAsBase64;

//  Public Key accessors for Java Servers
- (NSString *)getPublicKeyAsBase64ForJavaServer;

//  Private Key accessors
- (NSString *)getPrivateKeyAsBase64;

// Helpers
- (NSString *)stripPEM:(NSString *)keyString;
    
// Sign & Verify methods
    
- (NSData *)sign:(NSData *)plainData;
- (BOOL)verify:(NSData *)plainData signature:(NSData *)signature;

@end
