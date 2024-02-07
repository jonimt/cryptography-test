//
//  ECDSAModuleBridge.m
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(ECDSAModule, NSObject)

RCT_EXTERN_METHOD(generateKeyPair:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signJwt:(NSString *)iss
                  sub:(NSString *)sub
                  exp:(NSInteger *)exp
                  privateKeyPEM:(NSString *)privateKeyPEM
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyJwt:(NSString *)jwtToken
                  publicKeyPEM:(NSString *)publicKeyPEM
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end

