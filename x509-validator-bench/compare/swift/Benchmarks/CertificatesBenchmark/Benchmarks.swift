import Benchmark
import Foundation

let benchmarks: @Sendable () -> Void = {
    Benchmark.defaultConfiguration = .init(
        metrics: [.wallClock],
        scalingFactor: .kilo,
        maxDuration: .seconds(10),
        maxIterations: 100
    )

    Benchmark("Verifier") { benchmark in
        for _ in benchmark.scaledIterations {
            await verifier()
        }
    }

    Benchmark("Parse WebPKI Roots from DER") { benchmark, run in
        for _ in benchmark.scaledIterations {
            run()
        }
    } setup: {
        parseWebPKIRootsFromDER()
    }
}