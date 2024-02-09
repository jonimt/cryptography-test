package com.cryptotest.ECDSAModule

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableNativeMap

class ECDSAModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
    override fun getName() = "ECDSAModule"

    // Generate an ECDSA key pair using Curve P-256 and return them in PEM format
    @ReactMethod
    fun generateKeyPair(promise: Promise) {
        try {
            val (privateKeyPEM, publicKeyPEM) = CryptographyModule.generateKeyPair()
            val result = WritableNativeMap().apply {
                putString("privateKeyPEM", privateKeyPEM)
                putString("publicKeyPEM", publicKeyPEM)
            }
            // Resolve the promise with the generated key pair.
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("KeyGenerationError", "Error during key generation", e)
        }
    }

    // Sign a JWT with a given issuer (iss), subject (sub), expiration (exp) and a private key in PEM format
    @ReactMethod
    fun signJwt(iss: String, sub: String, exp: Int, privateKeyPEM: String, promise: Promise) {
        try {
            val signedJWT = CryptographyModule.signJwt(iss, sub, exp, privateKeyPEM)
            promise.resolve(signedJWT)
        } catch (e: Exception) {
            promise.reject("JWTSigningError", "Error signing JWT", e)
        }
    }

    // Verify a JWT using the provided public key in PEM format
    // NB! This is not used in the actual app, just for testing and make sure interoperability with iOS and Android
    @ReactMethod
    fun verifyJwt(jwtToken: String, publicKeyPEM: String, promise: Promise) {
        try {
            val verificationResult = CryptographyModule.verifyJwt(jwtToken, publicKeyPEM)
            promise.resolve(verificationResult)
        } catch (e: Exception) {
            promise.reject("VerificationError", "Failed to verify signature", e)
        }
    }
}