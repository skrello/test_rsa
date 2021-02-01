//
//  RSA.swift
//  test_rsa
//
//  Created by Mike on 29.01.21.
//

import Foundation
import SwiftyRSA

class SwiftRSA {
    private let publicKeyIdentifier: String
    private let privateKeyIdentifier: String
    private let size: Int

    private var publicKeyReference: SecKey?
    private var privateKeyReference: SecKey?

    private var publicKey: PublicKey?
    private var privateKey: PrivateKey?

    private var publicTag: NSData
    private var privateTag: NSData

    var publicKeyForJavaServer: String? {
        getKeyForJavaServer(publicKeyReference)
    }

    var publicKeyAsBase64: String? {
        return keyAsBase64(for: publicKeyReference)
    }

    var privateKeyAsBase64: String? {
        keyAsBase64(for: privateKeyReference)
    }

    init(publicKeyIdentifier: String,
         privateKeyIdentifier: String,
         size: Int) {

        self.publicKeyIdentifier = publicKeyIdentifier
        self.privateKeyIdentifier = privateKeyIdentifier
        self.size = size

        self.publicTag = publicKeyIdentifier.data(using: .utf8)! as NSData
        self.privateTag = privateKeyIdentifier.data(using: .utf8)! as NSData
    }

    public func generateOrRestoreKeys() {
        if !restoreIfExists() {
            generate()
        }
    }

    public func restoreIfExists() -> Bool {
        if restoreKey(for: publicTag, key: &publicKeyReference) &&
            restoreKey(for: privateTag, key: &privateKeyReference) {
            return true
        }

        publicKey = nil
        privateKey = nil
        publicKeyReference = nil
        privateKeyReference = nil

        return false
    }

    private func keyAsBase64(for anyKey: SecKey?) -> String? {
        guard let anyKey = anyKey else { return nil }
        do {
            let key = try PublicKey(reference: anyKey)
            let base64KeyString = try key.base64String()
            return base64KeyString
        } catch {
            do {
                let key = try PrivateKey(reference: anyKey)
                let base64KeyString = try key.base64String()
                return base64KeyString
            } catch {
                return nil
            }
        }
    }

    private func generate() {
        let privateKeyAttr: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: privateTag
        ]
        let publicKeyAttr: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: publicTag
        ]

        let parameters: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: size,
            kSecPrivateKeyAttrs: privateKeyAttr,
            kSecPublicKeyAttrs: publicKeyAttr
        ]

        SecKeyGeneratePair(parameters as CFDictionary, &publicKeyReference, &privateKeyReference)
        if let publicKeyRef = publicKeyReference {
            publicKey = try? PublicKey(reference: publicKeyRef)
        }

        if let privateKeyRef = privateKeyReference {
            privateKey = try? PrivateKey(reference: privateKeyRef)
        }
    }

    private func restoreKey(for tag: NSData, key: inout SecKey?) -> Bool {
        let query: CFDictionary = [kSecClass: kSecClassKey,
                                   kSecAttrApplicationTag: tag,
                                   kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                   kSecReturnRef: true] as CFDictionary

        var keyPtr: AnyObject? = key
        let result = SecItemCopyMatching(query as CFDictionary, &keyPtr)
        if ( result != noErr || keyPtr == nil ) {
            return false
        }
        key = keyPtr as! SecKey// swiftlint:disable:this force_cast
        return true
    }

    private func getKeyForJavaServer(_ secKey: SecKey?) -> String? {
        guard let secKey = secKey else { return nil }
        if let publicKey = try? PublicKey(reference: secKey),
            let publicKeyData = try? publicKey.data() {
            let bitstringSequence = ASN1.wrap(type: 0x03, followingData: publicKeyData)
            let oidData = ASN1.rsaOID()
            let oidSequence = ASN1.wrap(type: 0x30, followingData: oidData)
            let x509Sequence = ASN1.wrap(type: 0x30, followingData: oidSequence + bitstringSequence)
            return x509Sequence.base64EncodedString(options: .endLineWithLineFeed)
        }
        return nil
    }
}

