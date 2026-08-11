// swift-tools-version:6.1
import PackageDescription

let package = Package(
    name: "benchmarks",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.19.4"),
        .package(url: "https://github.com/ordo-one/benchmark.git", from: "1.36.2"),
    ],
    targets: [
        .executableTarget(
            name: "CertificatesBenchmark",
            dependencies: [
                .product(name: "Benchmark", package: "benchmark"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            // The benchmark plugin only recognises a target whose parent
            // directory is named `Benchmarks`; anywhere else it is silently
            // skipped and the run reports no rows at all.
            path: "Benchmarks/CertificatesBenchmark",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "benchmark")]
        )
    ]
)
