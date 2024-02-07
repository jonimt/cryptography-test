
import XCTest
@testable import cryptotest

final class ecdsaTests: XCTestCase {
  
  var ecdsaModule: ECDSAModule!
  
  override func setUpWithError() throws {
    super.setUp()
    ecdsaModule = ECDSAModule()
  }
  
  override func tearDownWithError() throws {
    ecdsaModule = nil
    super.tearDown()
  }
  
  // Test for generateKeyPair with PEM format validation
  func testGenerateKeyPairPEMFormat() throws {
    let expectation = self.expectation(description: "KeyPairGenerationPEMFormat")
    
    ecdsaModule.generateKeyPair({ (result) in
      if let keys = result as? [String: String] {
        guard let privateKey = keys["privateKeyPEM"], let publicKey = keys["publicKeyPEM"] else {
          XCTFail("Keys not found")
          return
        }
        
        // Assert non-empty keys
        XCTAssertFalse(privateKey.isEmpty, "Private Key is empty")
        XCTAssertFalse(publicKey.isEmpty, "Public Key is empty")
        
        // Regular expression to check PEM format
        let pemRegex = "^-----BEGIN [A-Z ]+ KEY-----[\\s\\S]+-----END [A-Z ]+ KEY-----$"
        
        // Assert PEM format for private key
        let privateKeyMatches = privateKey.range(of: pemRegex, options: .regularExpression)
        XCTAssertNotNil(privateKeyMatches, "Private Key is not in valid PEM format")
        
        // Assert PEM format for public key
        let publicKeyMatches = publicKey.range(of: pemRegex, options: .regularExpression)
        XCTAssertNotNil(publicKeyMatches, "Public Key is not in valid PEM format")
      } else {
        XCTFail("Result is not of type [String: String]")
      }
      expectation.fulfill()
    }, rejecter: { (code, message, error) in
      XCTFail("Key generation failed: \(message ?? "")")
    })
    
    waitForExpectations(timeout: 5, handler: nil)
  }
  
  // Test for signJwt: Success Case
  func testSignJwtSuccess() {
    let expectation = self.expectation(description: "JWTSigningSuccess")
    
    let iss = "issuer"
    let sub = "subject"
    let exp = 3600 // Example: 1 hour in seconds
    
    ecdsaModule.generateKeyPair({ (keysResult) in
      guard let keys = keysResult as? [String: String], let privateKeyPEM = keys["privateKeyPEM"] else {
        XCTFail("Failed to generate keys for test")
        return
      }
      
      self.ecdsaModule.signJwt(iss, sub: sub, exp: exp, privateKeyPEM: privateKeyPEM, resolver: { jwt in
        XCTAssertNotNil(jwt, "JWT should be successfully signed and not nil")
        expectation.fulfill()
      }, rejecter: { code, message, error in
        XCTFail("Signing JWT should have succeeded but failed with message: \(message ?? "")")
      })
    }, rejecter: { _, _, _ in XCTFail("Key generation failed") })
    
    waitForExpectations(timeout: 10)
  }
  
  // Test for signJwt: Invalid Private Key
  func testSignJwtWithInvalidPrivateKey() {
    let expectation = self.expectation(description: "JWTSigningWithInvalidPrivateKey")
    
    // invalid key, g taken out from end, valid key is ...Geg
    let privateKeyPEM = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgw3369DHzgkqwtqP9
    clGnWOJbFyCMKaBeOcEy2IdrayyhRANCAAQzRCqu3+LRIrRo0ar9QxeXkkE1snfI
    FJVJChsBUza6lQBGqfGaFa45I2NwZ27AR3MqxI8i7nbTbwE3cacpuGe
    -----END PRIVATE KEY-----
    """
    let iss = "issuer"
    let sub = "subject"
    let exp = 3600 // Example: 1 hour in seconds
    
    ecdsaModule.signJwt(iss, sub: sub, exp: exp, privateKeyPEM: privateKeyPEM, resolver: { _ in
      XCTFail("Signing should have failed due to invalid private key")
    }, rejecter: { code, message, error in
      XCTAssertNotNil(message, "Expected an error message for invalid private key")
      expectation.fulfill()
    })
    
    waitForExpectations(timeout: 5)
  }
  
  // Test for verifyJwt: Success Case
  func testVerifyJwtSuccess() {
    let expectation = self.expectation(description: "JWTVerificationSuccess")
    
    let iss = "issuer"
    let sub = "subject"
    let exp = 3600
    
    ecdsaModule.generateKeyPair({ (keysResult) in
      guard let keys = keysResult as? [String: String],
            let privateKeyPEM = keys["privateKeyPEM"],
            let publicKeyPEM = keys["publicKeyPEM"] else {
        XCTFail("Failed to generate keys for test")
        return
      }
      
      self.ecdsaModule.signJwt(iss, sub: sub, exp: exp, privateKeyPEM: privateKeyPEM, resolver: { jwt in
        guard let jwt = jwt as? String else {
          XCTFail("Failed to sign JWT")
          return
        }
        
        self.ecdsaModule.verifyJwt(jwt, publicKeyPEM: publicKeyPEM, resolver: { isValid in
          XCTAssertTrue(isValid as? Bool ?? false, "JWT should be valid")
          expectation.fulfill()
        }, rejecter: { _, _, _ in
          XCTFail("Verification should have succeeded")
        })
      }, rejecter: { _, _, _ in XCTFail("Signing JWT failed") })
    }, rejecter: { _, _, _ in XCTFail("Key generation failed") })
    
    waitForExpectations(timeout: 10)
  }
  
  // Test for verifyJwt: Invalid JWT Format
  func testVerifyJwtInvalidFormat() {
    let expectation = self.expectation(description: "JWTInvalidFormat")
    
    // valid public key
    let publicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM0Qqrt/i0SK0aNGq/UMXl5JBNbJ3
    yBSVSQobAVM2upUARqnxmhWuOSNjcGduwEdzKsSPIu52028BN3GnKbhnoA==
    -----END PUBLIC KEY-----
    """
    let malformedJwt = "invalid.jwt.format"
    
    ecdsaModule.verifyJwt(malformedJwt, publicKeyPEM: publicKeyPEM, resolver: { _ in
      XCTFail("Verification should have failed due to invalid JWT format")
    }, rejecter: { code, message, error in
      XCTAssertNotNil(message, "Expected an error message for invalid JWT format")
      expectation.fulfill()
    })
    
    waitForExpectations(timeout: 5)
  }
  
  // Test for verifyJwt: Invalid Public Key
  func testVerifyJwtInvalidPublicKey() {
    let expectation = self.expectation(description: "JWTVerificationWithInvalidPublicKey")
    
    // valid jwt
    let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIwMmk3WjAwMDAwVkswTGNRQUwiLCJpc3MiOiJjb25zdW1lciIsImlhdCI6MTcwNzIyNTkwMCwiZXhwIjoxNzM3MjI1OTAwfQ.rUEZIeHrD1sQkRsOaSzXux_C3Cn9qDAul4lzcMFm5m0YJoZF3WcjNgAo5H59J1LkVpze2SDi-HH4a4cjNpnL8g"
    // ivalid key, M taken away from start, should be MFk...
    let invalidPublicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    FkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM0Qqrt/i0SK0aNGq/UMXl5JBNbJ3
    yBSVSQobAVM2upUARqnxmhWuOSNjcGduwEdzKsSPIu52028BN3GnKbhnoA==
    -----END PUBLIC KEY-----
    """
    
    ecdsaModule.verifyJwt(jwt, publicKeyPEM: invalidPublicKeyPEM, resolver: { _ in
      XCTFail("Verification should have failed due to invalid public key")
    }, rejecter: { code, message, error in
      XCTAssertNotNil(message, "Expected an error message for invalid public key")
      expectation.fulfill()
    })
    
    waitForExpectations(timeout: 5)
  }
  
  func testVerifyJwtSignatureFail() {
    let expectation = self.expectation(description: "JWTSignatureVerificationFail")
    
    // Generate keys and sign a JWT, then tamper with the signature
    // For simplicity, let's assume `jwt` is a previously signed JWT with a valid format but now has an invalid signature.
    // valid jwt, invalid ignature, g taken away from the end, should be ...L8g
    let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIwMmk3WjAwMDAwVkswTGNRQUwiLCJpc3MiOiJjb25zdW1lciIsImlhdCI6MTcwNzIyNTkwMCwiZXhwIjoxNzM3MjI1OTAwfQ.rUEZIeHrD1sQkRsOaSzXux_C3Cn9qDAul4lzcMFm5m0YJoZF3WcjNgAo5H59J1LkVpze2SDi-HH4a4cjNpnL8"
    let publicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM0Qqrt/i0SK0aNGq/UMXl5JBNbJ3
    yBSVSQobAVM2upUARqnxmhWuOSNjcGduwEdzKsSPIu52028BN3GnKbhnoA==
    -----END PUBLIC KEY-----
    """
    
    ecdsaModule.verifyJwt(jwt, publicKeyPEM: publicKeyPEM, resolver: { _ in
      XCTFail("Verification should have failed due to invalid signature")
    }, rejecter: { code, message, error in
      XCTAssertNotNil(message, "Expected an error message for signature verification failure")
      expectation.fulfill()
    })
    
    waitForExpectations(timeout: 5)
  }
  
}
