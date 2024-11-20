//
//  Keychain.h
//  Hermes
//
//  Created by Alex Crichton on 11/19/11.
//

#import "Keychain.h"

BOOL KeychainSetItem(NSString* username, NSString* password) {
  NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: @(KEYCHAIN_SERVICE_NAME),
    (__bridge id)kSecAttrAccount: username
  };

  OSStatus result = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);

  if (result == noErr) {
    NSDictionary *attributesToUpdate = @{
      (__bridge id)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding]
    };
    result = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributesToUpdate);
  } else {
    NSDictionary *attributes = @{
      (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrService: @(KEYCHAIN_SERVICE_NAME),
      (__bridge id)kSecAttrAccount: username,
      (__bridge id)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding]
    };
    result = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
  }

  return result == noErr;
}

NSString *KeychainGetPassword(NSString* username) {
  NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: @(KEYCHAIN_SERVICE_NAME),
    (__bridge id)kSecAttrAccount: username,
    (__bridge id)kSecReturnData: @YES
  };

  CFTypeRef passwordDataRef = NULL;
  OSStatus result = SecItemCopyMatching((__bridge CFDictionaryRef)query, &passwordDataRef);

  if (result != noErr) {
    return nil;
  }

  NSData *passwordData = (__bridge_transfer NSData *)passwordDataRef;
  NSString *password = [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];

  return password;
}
