package com.cryptotest.ECDSAModule

import android.util.Log
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableNativeMap
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date

class ECDSAModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
    override fun getName() = "ECDSAModule"

    // Generate an ECDSA key pair using Curve P-256 and return them in PEM format
    @ReactMethod
    fun generateKeyPair(promise: Promise) {
        try {
            // Initialize a KeyPairGenerator for the Elliptic Curve algorithm.
            val keyGen = KeyPairGenerator.getInstance("EC")
            keyGen.initialize(256) // Use a 256-bit key size.
            val keyPair = keyGen.generateKeyPair() // Generate the key pair.

            // Convert the private and public keys to PEM format.
            val privateKeyPEM = convertToPEM(keyPair.private.encoded, true)
            val publicKeyPEM = convertToPEM(keyPair.public.encoded, false)

            // Prepare the result to be returned to JavaScript as a map.
            val result = WritableNativeMap().apply {
                putString("privateKeyPEM", privateKeyPEM)
                putString("publicKeyPEM", publicKeyPEM)
            }

            // Resolve the promise with the generated key pair.
            promise.resolve(result)
        } catch (e: NoSuchAlgorithmException) {
            promise.reject("KeyGenerationError", "Error during key generation", e)
        }
    }

    // Sign a JWT with a given issuer (iss), subject (sub), expiration (exp) and a private key in PEM format
    @ReactMethod
    fun signJwt(iss: String, sub: String, exp: Int, privateKeyPEM: String, promise: Promise) {
        try {
            // Strip headers/footers and spaces from the private key PEM string.
            val strippedPrivateKey = convertFromPEM(privateKeyPEM, true)

            // Decode the private key and generate a KeySpec.
            val privateKeyEncoded = Base64.getDecoder().decode(strippedPrivateKey)
            val keySpec = PKCS8EncodedKeySpec(privateKeyEncoded)
            val keyFactory = KeyFactory.getInstance("EC")
            val privateKey = keyFactory.generatePrivate(keySpec) as ECPrivateKey

            // Set up the JWT signing configuration with the private key.
            val algorithm = Algorithm.ECDSA256(null, privateKey)
            val nowMillis = System.currentTimeMillis()
            val now = Date(nowMillis)
            val expMillis = (exp.toLong() * 1000)
            val exp = Date(nowMillis + expMillis)

            // Create and sign the JWT with the specified claims.
            val signedJWT = JWT.create()
                    .withIssuer(iss)
                    .withSubject(sub)
                    .withIssuedAt(now)
                    .withExpiresAt(exp)
                    .sign(algorithm)

            // Resolve the promise with the signed JWT.
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
            // Strip headers/footers and spaces from the public key PEM string.
            val strippedPublicKey = convertFromPEM(publicKeyPEM, false)

            // Decode the public key and generate a KeySpec.
            val publicKeyEncoded = Base64.getDecoder().decode(strippedPublicKey)
            val keySpec = X509EncodedKeySpec(publicKeyEncoded)
            val keyFactory = KeyFactory.getInstance("EC")
            val publicKey = keyFactory.generatePublic(keySpec) as ECPublicKey

            // Set up the JWT verification configuration with the public key.
            val algorithm = Algorithm.ECDSA256(publicKey, null)
            val verifier: JWTVerifier = JWT.require(algorithm).build()
            val decodedJWT: DecodedJWT = verifier.verify(jwtToken)

            // Resolve the promise with the verification result (true if successful).
            promise.resolve(decodedJWT != null)
        } catch (e: Exception) {
            promise.reject("VerificationError", "Failed to verify signature", e)
        }
    }

    private fun convertToPEM(key: ByteArray, isPrivateKey: Boolean): String {
        val type = if (isPrivateKey) "PRIVATE" else "PUBLIC"
        val pemHeader = "-----BEGIN $type KEY-----\n"
        val pemFooter = "\n-----END $type KEY-----"

        return pemHeader + Base64.getEncoder().encodeToString(key)
                .chunked(64) // Breaks the string into lines of 64 characters
                .joinToString("\n") + pemFooter
    }

    private fun convertFromPEM(key: String, isPrivateKey: Boolean): String {
        val type = if (isPrivateKey) "PRIVATE" else "PUBLIC"

        return key
                .replace("-----BEGIN $type KEY-----", "")
                .replace("-----END $type KEY-----", "")
                .replace("\\s".toRegex(), "")
    }
}