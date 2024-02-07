/**
 * This exposes the native ECDSAModule module as a JS module.
 */
import {NativeModules} from 'react-native';
const {ECDSAModule} = NativeModules;

interface IEDCSAKeys {
  privateKeyPEM: string;
  publicKeyPEM: string;
}

interface IECDSAModule {
  generateKeyPair(): Promise<IEDCSAKeys>;
  signJwt(
    iss: string,
    sub: string,
    exp: number,
    privateKeyPEM: string,
  ): Promise<string>;
  verifyJwt(jwt: string, publicKeyPEM: string): Promise<boolean>;

  // signData(dataToSign: string, privateKeyBase64: string): Promise<string>;
  // verifyJwt(jwt: string, publicKeyBase64: string): Promise<boolean>;
}

export default ECDSAModule as IECDSAModule;
