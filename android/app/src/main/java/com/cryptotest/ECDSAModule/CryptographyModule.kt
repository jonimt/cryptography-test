package com.cryptotest.ECDSAModule

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Date

class CryptographyModule {
    companion object {
        fun generateKeyPair(): Pair<String, String> {
            val keyGen = KeyPairGenerator.getInstance("EC")
            keyGen.initialize(256)
            val keyPair = keyGen.generateKeyPair()

            val privateKeyPEM = convertToPEM(keyPair.private.encoded, true)
            val publicKeyPEM = convertToPEM(keyPair.public.encoded, false)

            return Pair(privateKeyPEM, publicKeyPEM)
        }

        fun signJwt(iss: String, sub: String, exp: Int, privateKeyPEM: String): String {
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
            val expMillis = exp.toLong() * 1000
            val expiration = Date(nowMillis + expMillis)

            return JWT.create()
                    .withIssuer(iss)
                    .withSubject(sub)
                    .withIssuedAt(now)
                    .withExpiresAt(expiration)
                    .sign(algorithm)
        }

        fun verifyJwt(jwtToken: String, publicKeyPEM: String): Boolean {
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
            verifier.verify(jwtToken)

            return true // If verification is successful, an exception is not thrown
        }

        private fun convertToPEM(key: ByteArray, isPrivateKey: Boolean): String {
            val type = if (isPrivateKey) "PRIVATE" else "PUBLIC"
            val pemHeader = "-----BEGIN $type KEY-----\n"
            val pemFooter = "\n-----END $type KEY-----"
            return pemHeader + Base64.getEncoder().encodeToString(key)
                    .chunked(64)
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
}