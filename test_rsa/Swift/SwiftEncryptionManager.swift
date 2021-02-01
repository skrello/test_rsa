//
//  SwiftEncryptionManager.swift
//  test_rsa
//
//  Created by Mike on 29.01.21.
//

protocol EncryptionManagerProtocol {
    var publicKeyForJavaServer: String { get }

    #if !PRODUCTION
    // maybe need for debugger
    var publicKeyFromStore: String? { get }
    var privateKeyFromStore: String? { get }
    #endif
}

final class SwiftEncryptionManager: EncryptionManagerProtocol {
    private let rsaKeySize = 2048
    private let rsa: SwiftRSA

    init(
        rsaPublicKeyIdentifier: String = "com.rsa.KeyPair.PublicKey",
        rsaPrivateKeyIdentifier: String = "com.rsa.KeyPair.PrivateKey"
    ) {
        self.rsa = SwiftRSA(
            publicKeyIdentifier: rsaPublicKeyIdentifier,
            privateKeyIdentifier: rsaPrivateKeyIdentifier,
            size: rsaKeySize
        )
        self.rsa.generateOrRestoreKeys()
    }

    var publicKeyForJavaServer: String {
        rsa.generateOrRestoreKeys()
        return rsa.publicKeyForJavaServer ?? ""
    }

    #if !PRODUCTION
    var publicKeyFromStore: String? {
        rsa.publicKeyAsBase64
    }

    var privateKeyFromStore: String? {
        rsa.privateKeyAsBase64
    }
    #endif
}
