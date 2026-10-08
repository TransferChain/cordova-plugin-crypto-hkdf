import Foundation
import CoreFoundation
import CryptoKit
#if canImport(Cordova)
import Cordova
#endif

@objc(HKDF)
final class HKDF: CDVPlugin {
    @objc(derive:)
    func derive(_ command: CDVInvokedUrlCommand) {
        // GCD work owns its input copies until result delivery. No shared keys or cache.
        commandDelegate.run(inBackground: {
            do {
                guard command.arguments.count == 4,
                      let options = command.arguments[0] as? [String: Any],
                      let value = options["keyLength"] as? NSNumber,
                      CFGetTypeID(value) != CFBooleanGetTypeID(),
                      value.doubleValue.isFinite,
                      value.doubleValue.rounded(.towardZero) == value.doubleValue,
                      value.doubleValue >= 1, value.doubleValue <= 8160,
                      let input = command.arguments[1] as? Data,
                      let suppliedSalt = command.arguments[2] as? Data,
                      let suppliedInfo = command.arguments[3] as? Data,
                      !input.isEmpty, input.count <= 1048576,
                      suppliedSalt.count <= 65536, suppliedInfo.count <= 65536 else {
                    throw Failure.invalid
                }

                // Force owned copies; Data and CryptoKit can retain internal COW copies.
                // resetBytes clears these owned buffers, not every provider allocation.
                var ikm = input.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
                var salt = Data(suppliedSalt)
                var info = Data(suppliedInfo)

                defer {
                    ikm.resetBytes(in: 0..<ikm.count)
                    salt.resetBytes(in: 0..<salt.count)
                    info.resetBytes(in: 0..<info.count)
                }

                let key = CryptoKit.HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm),
                    salt: salt, info: info, outputByteCount: value.intValue)
                var output = key.withUnsafeBytes { Data($0) }

                defer { output.resetBytes(in: 0..<output.count) }

                self.commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK,
                    messageAsArrayBuffer: output), callbackId: command.callbackId)
            } catch {
                self.commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_ERROR,
                    messageAs: ["code": "INVALID_ARGUMENT", "message": "Invalid HKDF byte input or keyLength."]),
                    callbackId: command.callbackId)
            }
        })
    }

    private enum Failure: Error { case invalid }
}
