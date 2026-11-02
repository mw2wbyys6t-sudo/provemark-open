// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Fixture",
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/Alamofire/Alamofire", exact: "5.9.1"),
    ]
)
