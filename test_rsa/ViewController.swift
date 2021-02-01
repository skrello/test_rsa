//
//  ViewController.swift
//  test_rsa
//
//  Created by Mike on 29.01.21.
//

import UIKit

class ViewController: UIViewController {
    var objCRSA: EncryptionManagerProtocol!
    var swiftRSA: EncryptionManagerProtocol!

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .purple
        
        objCRSA = ObjEncryptionManager()
        swiftRSA = SwiftEncryptionManager()
        
        ()
    }


}

