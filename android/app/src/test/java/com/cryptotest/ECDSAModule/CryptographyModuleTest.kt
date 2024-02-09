package com.cryptotest.ECDSAModule

import org.junit.Assert.*
import org.junit.Test

class CryptographyModuleTest {

    @Test
    fun testGenerateKeyPairPEMFormat() {
        val (privateKeyPEM, publicKeyPEM) = CryptographyModule.generateKeyPair()

        // Basic validation to check if keys are not empty and have proper headers and footers
        assertTrue(privateKeyPEM.startsWith("-----BEGIN PRIVATE KEY-----"))
        assertTrue(privateKeyPEM.endsWith("-----END PRIVATE KEY-----"))
        assertTrue(publicKeyPEM.startsWith("-----BEGIN PUBLIC KEY-----"))
        assertTrue(publicKeyPEM.endsWith("-----END PUBLIC KEY-----"))
    }

    @Test
    fun testSignJwtSuccess() {
        val (privateKeyPEM, _) = CryptographyModule.generateKeyPair()
        val jwt = CryptographyModule.signJwt("issuer", "subject", 3600, privateKeyPEM)

        assertNotNull(jwt)
        //assertTrue(Pattern.matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*$", jwt))
    }

    @Test(expected = Exception::class)
    fun testSignJwtWithInvalidPrivateKey() {
        // invalid key, P taken out from end, valid key is ...SXP
        val invalidPrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguggey2JLFmC0yAi0\n" +
                "iVc3XRJMlebLMR5Scqodiicn5VuhRANCAATIQmpepXH8uO2WY65rjEyanYXJTwtK\n" +
                "tgLdcrDhJFyqOxfwXHTsVgwIB6zL7OmdkixUw2sm4eQVpTCniqMH9SX\n" +
                "-----END PRIVATE KEY-----"
        CryptographyModule.signJwt("issuer", "subject", 3600, invalidPrivateKeyPEM)
    }

    @Test
    fun testVerifyJwtSuccess() {
        val (privateKeyPEM, publicKeyPEM) = CryptographyModule.generateKeyPair()
        val jwt = CryptographyModule.signJwt("issuer", "subject", 3600, privateKeyPEM)
        val result = CryptographyModule.verifyJwt(jwt, publicKeyPEM)

        assertTrue(result)
    }

    @Test(expected = Exception::class)
    fun testVerifyJwtInvalidFormat() {
        val (_, publicKeyPEM) = CryptographyModule.generateKeyPair()
        CryptographyModule.verifyJwt("invalid.jwt.format", publicKeyPEM)
    }

    @Test(expected = Exception::class)
    fun testVerifyJwtInvalidPublicKey() {
        val (privateKeyPEM, _) = CryptographyModule.generateKeyPair()
        val jwt = CryptographyModule.signJwt("issuer", "subject", 3600, privateKeyPEM)
        // invalid key, M taken away from start, should be MFk...
        val invalidPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                "FkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyEJqXqVx/LjtlmOua4xMmp2FyU8L\n" +
                "SrYC3XKw4SRcqjsX8Fx07FYMCAesy+zpnZIsVMNrJuHkFaUwp4qjB/Ulzw==\n" +
                "-----END PUBLIC KEY-----"
        CryptographyModule.verifyJwt(jwt, invalidPublicKeyPEM)
    }

    @Test(expected = Exception::class)
    fun testVerifyJwtSignatureFail() {
        // Generate first key pair for signing
        val (privateKeyPEM1, _) = CryptographyModule.generateKeyPair()
        val jwt = CryptographyModule.signJwt("issuer", "subject", 3600, privateKeyPEM1)

        // Generate second key pair for verification
        val (_, publicKeyPEM2) = CryptographyModule.generateKeyPair()
        CryptographyModule.verifyJwt(jwt, publicKeyPEM2) // This should fail as the public key doesn't match the private key used for signing
    }
}