// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "GimbalLocal",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "GimbalLocal", targets: ["GimbalLocalApp"])
    ],
    targets: [
        .executableTarget(
            name: "GimbalLocalApp"
        ),
        .testTarget(
            name: "GimbalLocalAppTests",
            dependencies: ["GimbalLocalApp"]
        ),
    ]
)
