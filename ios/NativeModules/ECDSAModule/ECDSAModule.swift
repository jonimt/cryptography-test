//
//  ECDSAModule.swift
//

import Foundation
import CryptoKit
import Security

@objc(ECDSAModule)
class ECDSAModule: NSObject {
  
  /**
   For iOS, if you override constantsToExport() then you should also implement + requiresMainQueueSetup to let React Native know if your module needs to be initialized on the main thread, before any JavaScript code executes. Otherwise you will see a warning that in the future your module may be initialized on a background thread unless you explicitly opt out with + requiresMainQueueSetup:. If your module does not require access to UIKit, then you should respond to + requiresMainQueueSetup with NO.
   */
  @objc static func requiresMainQueueSetup() -> Bool {
    return false
  }
  
  // Generate an ECDSA key pair using Curve P-256 and return them in PEM format
  @objc(generateKeyPair:rejecter:)
  func generateKeyPair(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      // Generate a new private key using P-256 curve
      let privateKey = P256.KeyAgreement.PrivateKey()
      // Extract the public key from the generated private key
      let publicKey = privateKey.publicKey
      
      // Convert both keys to PEM format
      let privateKeyPEM = privateKey.pemRepresentation
      let publicKeyPEM = publicKey.pemRepresentation
      
      // Resolve the promise with the private and public keys in PEM format
      resolve(["privateKeyPEM": privateKeyPEM, "publicKeyPEM": publicKeyPEM])
    } catch {
      // None of those throw, so this should never happen, but left it as a template, if something changes in future
      reject("KeyGenerationError", "Error during key generation: \(error.localizedDescription)", error as NSError)
    }
  }
  
  // Sign a JWT with a given issuer (iss), subject (sub), expiration (exp) and a private key in PEM format
  @objc(signJwt:sub:exp:privateKeyPEM:resolver:rejecter:)
  func signJwt(_ iss: String, sub: String, exp: Int, privateKeyPEM: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    
    // Attempt to convert the PEM formatted private key back to a CryptoKit private key
    guard let privateKey = try? P256.Signing.PrivateKey(pemRepresentation: privateKeyPEM) else {
      reject("KeyConversionError", "Could not convert PEM to private key", nil)
      return
    }
    
    do {
      // Convert the private key to its raw representation for signing
      let privateKeyData = privateKey.rawRepresentation
      // Create a JWT signed with the private key
      let jwt = try jwtSignedToken(iss: iss, sub: sub, exp: exp, ecSECp256rKeyK: privateKeyData)
      
      // Resolve the promise with the signed JWT
      resolve(jwt)
    } catch {
      reject("JWTSigningError", "Error signing JWT: \(error.localizedDescription)", error as NSError)
    }
  }
  
  // Verify a JWT using the provided public key in PEM format
  // NB! This is not used in the actual app, just for testing and make sure interoperability with iOS and Android
  @objc(verifyJwt:publicKeyPEM:resolver:rejecter:)
  func verifyJwt(_ jwt: String, publicKeyPEM: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    
    // Split the JWT into its three components: Header, Payload, and Signature
    let parts = jwt.components(separatedBy: ".")
    guard parts.count == 3 else {
      reject("JWTError", "Invalid JWT: Must contain 3 parts", nil)
      return
    }
    
    // Extract the components of the JWT
    let header = parts[0]
    let payload = parts[1]
    let signatureBase64URL = parts[2]
    
    // Attempt to convert the PEM formatted public key back to a CryptoKit public key
    guard let publicKey = try? P256.Signing.PublicKey(pemRepresentation: publicKeyPEM) else {
      reject("KeyConversionError", "Could not convert PEM to public key", nil)
      return
    }
    
    // Decode the base64 URL encoded signature
    guard let signatureData = Data(base64URLEncodedString: signatureBase64URL) else {
      reject("SignatureError", "Invalid signature format", nil)
      return
    }
    
    do {
      // Create an ECDSA signature from the raw data
      let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
      // Concatenate the header and payload to verify the signature against
      let signingInput = "\(header).\(payload)"
      
      // Verify the signature using the public key
      let isValid = publicKey.isValidSignature(signature, for: Data(signingInput.utf8))
      
      // Resolve the promise based on the validity of the signature
      if isValid {
        resolve(true)
      } else {
        throw ECDSAModuleError.myModuleError(customMessage: "Error verifying JWT")
      }
    } catch {
      reject("VerificationError", "Failed to verify signature: \(error.localizedDescription)", error as NSError)
    }
  }
  
  // Utility function to generate the JWT header
  func jwtHeader() throws -> String {
    // Define the JWT header structure
    struct Header: Codable {
      var alg: String
      var typ: String
    }
    let header = Header(alg: "ES256", typ: "JWT")
    let encoder = JSONEncoder()
    
    // Encode the header to a base64 URL encoded string
    guard let encodedHeader = try? encoder.encode(header).base64URLEncodedString else {
      throw ECDSAModuleError.myModuleError(customMessage: "Encoding header failed")
    }
    return encodedHeader
  }
  
  // Utility function to generate the JWT payload
  func jwtPayload(iss: String, sub: String, exp: Int) throws -> String {
    // Define the JWT payload structure
    struct Payload: Codable {
      var iss: String
      var sub: String
      var iat: Int
      var exp: Int
    }
    
    // Calculate the issued at and expiration times
    let now = Date()
    let iat = Int(now.timeIntervalSince1970)
    let exp = iat + exp
    let payload = Payload(iss: iss, sub: sub, iat: iat, exp: exp)
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .secondsSince1970
    
    // Encode the payload to a base64 URL encoded string
    guard let encodedPayload = try? encoder.encode(payload).base64URLEncodedString else {
      throw ECDSAModuleError.myModuleError(customMessage: "Encoding payload failed")
    }
    return encodedPayload
  }
  
  // Function to sign a JWT using the provided issuer, subject, exp and private key
  func jwtSignedToken(iss: String, sub: String, exp: Int, ecSECp256rKeyK keyK: Data) throws -> String {
    // Generate the JWT header and payload
    let header = try jwtHeader()
    let payload = try jwtPayload(iss: iss, sub: sub, exp: exp)
    let signingInput = "\(header).\(payload)"
    
    // Attempt to create a private key from the raw key data
    guard let privateKey = try? P256.Signing.PrivateKey(rawRepresentation: keyK) else {
      throw ECDSAModuleError.myModuleError(customMessage: "Failed to create private key from raw representation")
    }
    
    // Sign the JWT and encode the signature
    guard let sig = try? privateKey.signature(for: Data(signingInput.utf8)).rawRepresentation else {
      throw ECDSAModuleError.myModuleError(customMessage: "Failed to generate signature.")
    }
    
    // Return the complete JWT as a string
    return "\(signingInput).\(sig.base64URLEncodedString)"
  }
}

extension String {
  func base64URLSafe() -> String {
    // Replace base64 characters that are not URL safe ('+', '/') with URL-safe equivalents ('-', '_')
    // Remove padding character ('=') as it's not required in a URL context and can be safely omitted
    return self.replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}

extension Data {
  
  // Initialize Data from a base64 URL encoded string
  init?(base64URLEncodedString: String) {
    // Convert the URL-safe characters back to their base64 equivalents
    let unpadded = base64URLEncodedString
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    
    // Calculate how many '=' padding characters need to be appended
    // Base64 strings should have a length that is a multiple of 4
    let padCount: Int
    switch unpadded.count % 4 {
    case 0: padCount = 0 // No padding needed
    case 1: return nil // Invalid base64 string length
    case 2: padCount = 2 // Two '=' padding characters needed
    case 3: padCount = 1 // One '=' padding character needed
    default: fatalError() // This should never happen
    }
    
    // Attempt to initialize a Data object from the corrected base64 string
    self.init(base64Encoded: String(unpadded + String(repeating: "=", count: padCount)))
  }
  
  // Convert Data to a base64 URL encoded string
  var base64URLEncodedString: String {
    // Convert data to base64
    let base64 = self.base64EncodedString()
    
    // Make the base64 string URL-safe and remove any '=' padding
    return String(base64.split(separator: "=").first!)
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
  }
}

// TODO:
enum ECDSAModuleError: Error {
  case myModuleError(customMessage: String)
}

extension ECDSAModuleError: LocalizedError {
  var errorDescription: String? {
    switch self {
    case .myModuleError(let customMessage):
      return customMessage
    }
  }
}
