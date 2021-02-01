//
//  ObjEncryptionManager.swift
//  test_rsa
//
//  Created by Mike on 29.01.21.
//

final class ObjEncryptionManager: EncryptionManagerProtocol {
    private let rsaKeySize = 2048
    private let rsa: RSA

    init(
        rsaPublicKeyIdentifier: String = "com.rsa.KeyPair.PublicKey",
        rsaPrivateKeyIdentifier: String = "com.rsa.KeyPair.PrivateKey"
    ) {
        let rsa = RSA.sharedInstance()!
        rsa.setIdentifierForPublicKey(rsaPublicKeyIdentifier,
                                              privateKey: rsaPrivateKeyIdentifier)
        rsa.setRSAKeySize(RSAKeySize(rsaKeySize))
        rsa.generateKeyPairIfNeed({})
        self.rsa = rsa
    }

    var publicKeyForJavaServer: String {
        rsa.getPublicKeyAsBase64ForJavaServer()
    }

    #if !PRODUCTION
    var publicKeyFromStore: String? {
        rsa.getPublicKeyAsBase64()
    }

    var privateKeyFromStore: String? {
        rsa.getPrivateKeyAsBase64()
    }
    #endif
}
