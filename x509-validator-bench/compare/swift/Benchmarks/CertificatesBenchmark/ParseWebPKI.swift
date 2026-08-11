//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Benchmark
import X509
import SwiftASN1
import Foundation

/// The vendored Mozilla CA bundle roots, read from the same directory the
/// Rust side embeds at compile time (`x509_validator_testkit::roots::ROOTS`).
///
/// Upstream this loaded a PEM list bundled with swift-certificates. Reading
/// the testkit's DER files instead is what keeps the two languages on one
/// corpus: if the bundle is regenerated, neither side can drift from the
/// other, and the Rust and Swift rows stay comparable.
///
/// The path is resolved from this file's own location rather than the working
/// directory, so the benchmark runs the same whichever directory it is
/// launched from.
private let rootsDirectory = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // CertificatesBenchmark/
    .deletingLastPathComponent()  // Benchmarks/
    .deletingLastPathComponent()  // swift/
    .deletingLastPathComponent()  // compare/
    .deletingLastPathComponent()  // x509-validator-bench/
    .deletingLastPathComponent()  // repository root
    .appendingPathComponent("x509-validator-testkit/data/mozilla")

/// Every vendored root, in a stable order so runs stay comparable.
func loadWebPKIRootsAsDER() throws -> [[UInt8]] {
    let files = try FileManager.default
        .contentsOfDirectory(at: rootsDirectory, includingPropertiesForKeys: nil)
        .filter { $0.pathExtension == "der" }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }

    guard !files.isEmpty else {
        fatalError("no .der roots found under \(rootsDirectory.path)")
    }

    return try files.map { Array(try Data(contentsOf: $0)) }
}

public func parseWebPKIRootsFromDER() -> () -> Void {
    let derEncodedCAs = try! loadWebPKIRootsAsDER()
    return {
        for derEncodedCA in derEncodedCAs {
            blackHole(try! Certificate(derEncoded: derEncodedCA).extensions.count)
        }
    }
}