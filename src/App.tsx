import React from 'react';
import {
  SafeAreaView,
  StyleSheet,
  Text,
  Pressable,
  View,
  Platform,
} from 'react-native';
import ECDSAModule from '../ECDSAModule';

const iosPrivateKPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgw3369DHzgkqwtqP9
clGnWOJbFyCMKaBeOcEy2IdrayyhRANCAAQzRCqu3+LRIrRo0ar9QxeXkkE1snfI
FJVJChsBUza6lQBGqfGaFa45I2NwZ27AR3MqxI8i7nbTbwE3cacpuGeg
-----END PRIVATE KEY-----`;
const iosPublicKPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM0Qqrt/i0SK0aNGq/UMXl5JBNbJ3
yBSVSQobAVM2upUARqnxmhWuOSNjcGduwEdzKsSPIu52028BN3GnKbhnoA==
-----END PUBLIC KEY-----`;
const iosJWT =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIwMmk3WjAwMDAwVkswTGNRQUwiLCJpc3MiOiJjb25zdW1lciIsImlhdCI6MTcwNzIyNTkwMCwiZXhwIjoxNzM3MjI1OTAwfQ.rUEZIeHrD1sQkRsOaSzXux_C3Cn9qDAul4lzcMFm5m0YJoZF3WcjNgAo5H59J1LkVpze2SDi-HH4a4cjNpnL8g';

const androidPrivateKPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHf//Ktp7SUgl7oUY
3qWwBzpw7aSLFE/PONt+pHnikL2hRANCAATAet9x7ppMLDYz2n8KDBewFmmzIMsC
80PNSELe5oWGpNngud7gvFfEY+lG6tgNh0ws5pWyG0tX4dNNIak6XUYN
-----END PRIVATE KEY-----`;
const androidPublicKPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwHrfce6aTCw2M9p/CgwXsBZpsyDL
AvNDzUhC3uaFhqTZ4Lne4LxXxGPpRurYDYdMLOaVshtLV+HTTSGpOl1GDQ==
-----END PUBLIC KEY-----`;
// This jwt is signed with the private key above
// and should be able to be verified with the public key above
const androidJWT =
  'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjb25zdW1lciIsInN1YiI6IjAyaTdaMDAwMDBWSzBMY1FBTCIsImlhdCI6MTcwNzQ3NTY1OSwiZXhwIjoxNzM3NDc1NjU5fQ.O05fuxcf7hBKvlSbeX45pkehFTch8oz7UoVmaU4QhrEPeiDeCGsE5BolupTm_vdqajPJbL0yMfFG92DWdAQpGA';

function App(): React.JSX.Element {
  const [signedJwt, setJwt] = React.useState<string>('');
  const [publicKey, setPublicKey] = React.useState<string>('');
  const [privateKey, setPrivateKey] = React.useState<string>('');

  const generateKeysiOS = async () => {
    const {privateKeyPEM, publicKeyPEM} = await ECDSAModule.generateKeyPair();

    console.log('privateKeyPEM iOS --> \n', privateKeyPEM);
    console.log('publicKeyPEM iOS --> \n', publicKeyPEM);
    setPrivateKey(privateKeyPEM);
    setPublicKey(publicKeyPEM);
  };

  const signJWTiOS = async () => {
    try {
      const jwt = await ECDSAModule.signJwt(
        'consumer',
        '02i7Z00000VK0LcQAL',
        30000000,
        privateKey,
      );

      console.log('generated jwt --> ', jwt);
      setJwt(jwt);
    } catch (error) {
      console.log('error:' + error);
    }
  };

  const verifyJWTiOS = async () => {
    const verify = await ECDSAModule.verifyJwt(signedJwt, publicKey);
    console.log('verified, is proper JWT --> ', verify);
  };

  const signJWTWithHardAndroidKeysWithiOSModule = async () => {
    const jwt = await ECDSAModule.signJwt(
      'consumer',
      '02i7Z00000VK0LcQAL',
      30000000,
      androidPrivateKPem,
    );
    console.log('generated jwt --> ', jwt);
    verifyJWTSignedWithAndroidKeysWithiOSModule(jwt);
  };

  const verifyJWTSignedWithAndroidKeysWithiOSModule = async (jwt: string) => {
    try {
      const verify = await ECDSAModule.verifyJwt(jwt, androidPublicKPem);
      console.log('verified, is proper JWT --> ', verify);
    } catch (error) {
      console.log('error:' + error);
    }
  };

  const verifyAndroidSignedJWTiniOSModule = async () => {
    try {
      const verify = await ECDSAModule.verifyJwt(androidJWT, androidPublicKPem);
      console.log('verified, is proper JWT --> ', verify);
    } catch (error) {
      console.log('error:' + error);
    }
  };

  const generateKeysAndroid = async () => {
    const {privateKeyPEM, publicKeyPEM} = await ECDSAModule.generateKeyPair();

    console.log('privateKeyPEM Android --> \n', privateKeyPEM);
    console.log('publicKeyPEM Android --> \n', publicKeyPEM);
    setPrivateKey(privateKeyPEM);
    setPublicKey(publicKeyPEM);
  };

  const signJWTAndroid = async () => {
    const jwt = await ECDSAModule.signJwt(
      'consumer',
      '02i7Z00000VK0LcQAL',
      30000000,
      privateKey,
    );

    console.log('generated jwt --> ', jwt);
    setJwt(jwt);
  };

  const verifyJWTAndroid = async () => {
    try {
      const verify = await ECDSAModule.verifyJwt(signedJwt, publicKey);
      console.log('verified, is proper JWT --> ', verify);
    } catch (error) {
      console.log('error verified jwt --> ', JSON.stringify(error));
    }
  };

  const signJWTWithHardiOSKeysWithAndroidModule = async () => {
    const jwt = await ECDSAModule.signJwt(
      'consumer',
      '02i7Z00000VK0LcQAL',
      30000000,
      iosPrivateKPem,
    );
    console.log('generated jwt --> ', jwt);
    verifyJWTSignedWithiOSKeysWithAndroidModule(jwt);
  };

  const verifyJWTSignedWithiOSKeysWithAndroidModule = async (jwt: string) => {
    try {
      const verify = await ECDSAModule.verifyJwt(jwt, iosPublicKPem);
      console.log('verified, is proper JWT --> ', verify);
    } catch (error) {
      console.log('error:' + error);
    }
  };

  const verifyiOSSignedJWTinAndroidModule = async () => {
    try {
      const verify = await ECDSAModule.verifyJwt(iosJWT, iosPublicKPem);
      console.log('verified, is proper JWT --> ', verify);
    } catch (error) {
      console.log('error:' + error);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      {Platform.OS === 'ios' ? (
        <View style={styles.box}>
          <Pressable style={styles.button} onPress={generateKeysiOS}>
            <Text>Generate iOS keys</Text>
          </Pressable>
          <Pressable style={styles.button} onPress={signJWTiOS}>
            <Text>Sign jwt with generated iOS keys</Text>
          </Pressable>
          <Pressable style={styles.button} onPress={verifyJWTiOS}>
            <Text>Verify signed jwt with generated iOS keys</Text>
          </Pressable>
          <Pressable
            style={styles.button}
            onPress={signJWTWithHardAndroidKeysWithiOSModule}>
            <Text>Sign jwt with Android keys in iOS and verify</Text>
          </Pressable>
          <Pressable
            style={styles.button}
            onPress={verifyAndroidSignedJWTiniOSModule}>
            <Text>Verify jwt generated in and with Android keys</Text>
          </Pressable>
        </View>
      ) : (
        <View style={styles.box}>
          <Pressable style={styles.button} onPress={generateKeysAndroid}>
            <Text>Generate Android keys</Text>
          </Pressable>
          <Pressable style={styles.button} onPress={signJWTAndroid}>
            <Text>Sign jwt with generated Android keys</Text>
          </Pressable>
          <Pressable style={styles.button} onPress={verifyJWTAndroid}>
            <Text>Verify signed jwt with generated Android keys</Text>
          </Pressable>
          <Pressable
            style={styles.button}
            onPress={signJWTWithHardiOSKeysWithAndroidModule}>
            <Text>Sign jwt with iOS keys in Android and verify</Text>
          </Pressable>
          <Pressable
            style={styles.button}
            onPress={verifyiOSSignedJWTinAndroidModule}>
            <Text>Verify jwt generated in and with iOS keys</Text>
          </Pressable>
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  box: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  button: {
    width: 200,
    height: 50,
    justifyContent: 'center',
    alignItems: 'center',
    borderWidth: 2,
    borderColor: 'black',
    marginVertical: 10,
  },
});

export default App;
