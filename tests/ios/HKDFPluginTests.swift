import XCTest
import Cordova
import CryptoTestSupport
@testable import NativeCryptoPlugins

// Execute with the existing macOS/Xcode harness; these are public RFC fixtures.
final class HKDFPluginTests: XCTestCase {
    private func derive(_ length: Any, _ ikm: Data, _ salt: Data, _ info: Data) throws -> CDVPluginResult {
        let plugin = HKDF()
        let delegate = CryptoTestDelegate()
        let done = expectation(description: "HKDF callback")
        done.assertForOverFulfill = true
        var result: CDVPluginResult?
        delegate.onResult = { value in result = value; done.fulfill() }
        plugin.commandDelegate = delegate
        plugin.derive(CDVInvokedUrlCommand(arguments: [["keyLength": length], ikm, salt, info],
            callbackId: "hkdf-test", className: "HKDF", methodName: "derive"))
        wait(for: [done], timeout: 5)
        return try XCTUnwrap(result)
    }

    private func bytes(_ result: CDVPluginResult) throws -> Data {
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_OK.rawValue))
        let message = try XCTUnwrap(result.message as? [String: Any])
        let encoded = try XCTUnwrap(message["data"] as? String)
        return try XCTUnwrap(Data(base64Encoded: encoded))
    }

    func testRFC5869AndEmptySaltInfo() throws {
        let ikm = Data(repeating: 11, count: 22)
        let salt = Data((0...12).map { UInt8($0) })
        let info = Data((240...249).map { UInt8($0) })
        let first = try bytes(derive(42, ikm, salt, info))
        XCTAssertEqual(first.map { String(format: "%02x", $0) }.joined(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        let empty = try bytes(derive(42, ikm, Data(), Data()))
        XCTAssertEqual(empty.map { String(format: "%02x", $0) }.joined(),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        XCTAssertEqual(ikm, Data(repeating: 11, count: 22))
    }

    func testBoundsAndInvalidTypes() throws {
        for length in [1, 32, 8160] {
            XCTAssertEqual(try bytes(derive(length, Data([1]), Data(), Data())).count, length)
        }
        for length: Any in [0, 8161, 1.5, true, "32"] {
            let result = try derive(length, Data([1]), Data(), Data())
            XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_ERROR.rawValue))
        }
        let result = try derive(32, Data(), Data(), Data())
        XCTAssertEqual(result.status.intValue, Int(CDVCommandStatus_ERROR.rawValue))
    }
}
