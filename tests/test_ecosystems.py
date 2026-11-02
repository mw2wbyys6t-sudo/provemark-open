from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from provemark import ecosystems
from provemark.config import load_config
from provemark.scanners import deps


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class EcosystemRegistryTests(unittest.TestCase):
    def test_osv_and_depsdev_mapping(self) -> None:
        self.assertTrue(ecosystems.osv_supported("Maven"))
        self.assertTrue(ecosystems.osv_supported("GitHub Actions"))
        self.assertFalse(ecosystems.osv_supported("Conda"))
        self.assertEqual(ecosystems.depsdev_system("NuGet"), "nuget")
        self.assertEqual(ecosystems.depsdev_system("Packagist"), "")
        self.assertEqual(ecosystems.registry_kind("Packagist"), "packagist")

    def test_manifest_and_lockfile_lookup(self) -> None:
        self.assertEqual(ecosystems.ecosystem_of_manifest("pom.xml"), "Maven")
        self.assertEqual(ecosystems.ecosystem_of_manifest("Demo.csproj"), "NuGet")
        self.assertEqual(ecosystems.ecosystem_of_manifest("requirements-dev.txt"), "PyPI")
        self.assertEqual(ecosystems.ecosystem_of_lockfile("Gemfile.lock"), "RubyGems")
        self.assertIsNone(ecosystems.ecosystem_of_manifest("notes.md"))
        self.assertIn("Cargo.lock", ecosystems.lockfiles_of("crates.io"))


class JvmTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pom_properties_and_managed_version(self) -> None:
        write(
            self.root,
            "pom.xml",
            """
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.demo</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties><spring.version>6.1.5</spring.version></properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit</groupId><artifactId>junit-bom</artifactId>
        <version>5.10.2</version><type>pom</type><scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId><artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><scope>test</scope>
    </dependency>
  </dependencies>
</project>
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["org.springframework:spring-core"], "6.1.5")
        self.assertEqual(versions["org.junit.jupiter:junit-jupiter"], "")
        self.assertNotIn("org.junit:junit-bom", versions)
        junit = next(p for p in result.packages if p.name.endswith("junit-jupiter"))
        self.assertEqual(junit.scope, "dev")
        self.assertTrue(junit.pinned_by_parent)

    def test_gradle_dependencies_and_platform(self) -> None:
        write(
            self.root,
            "build.gradle.kts",
            """
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web:3.2.4")
    testImplementation("junit:junit:4.13.2")
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.4"))
}
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["org.springframework.boot:spring-boot-starter-web"], "3.2.4")
        self.assertEqual(versions["junit:junit"], "4.13.2")
        self.assertEqual(versions["org.springframework.boot:spring-boot-dependencies"], "3.2.4")
        self.assertEqual(next(p.scope for p in result.packages if p.name == "junit:junit"), "dev")

    def test_gradle_version_catalog(self) -> None:
        write(
            self.root,
            "gradle/libs.versions.toml",
            """
[versions]
retrofit = "2.11.0"

[libraries]
retrofit = { module = "com.squareup.retrofit2:retrofit", version.ref = "retrofit" }
gson = { group = "com.google.code.gson", name = "gson", version = "2.11.0" }
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["com.squareup.retrofit2:retrofit"], "2.11.0")
        self.assertEqual(versions["com.google.code.gson:gson"], "2.11.0")

    def test_clojure_deps_edn_maps_to_maven(self) -> None:
        write(
            self.root,
            "deps.edn",
            '{:deps {org.clojure/clojure {:mvn/version "1.11.1"}\n'
            '        ring/ring-core {:mvn/version "1.11.0"}}}',
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["org.clojure:clojure"], "1.11.1")
        self.assertEqual(versions["ring:ring-core"], "1.11.0")


class DotnetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_csproj_with_and_without_version(self) -> None:
        write(
            self.root,
            "src/App.csproj",
            """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" />
  </ItemGroup>
</Project>
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["Newtonsoft.Json"], "13.0.3")
        self.assertEqual(versions["Serilog"], "")
        serilog = next(p for p in result.packages if p.name == "Serilog")
        self.assertTrue(serilog.pinned_by_parent)

    def test_central_package_versions(self) -> None:
        write(
            self.root,
            "Directory.Packages.props",
            "<Project><ItemGroup>"
            '<PackageVersion Include="Dapper" Version="2.1.35" />'
            "</ItemGroup></Project>",
        )
        result = deps.collect(self.root, load_config(self.root))
        self.assertEqual(
            next(p.version for p in result.packages if p.name == "Dapper"), "2.1.35"
        )

    def test_msbuild_property_version_resolution(self) -> None:
        write(
            self.root,
            "Directory.Build.props",
            "<Project><PropertyGroup><NUnitVersion>4.0.1</NUnitVersion></PropertyGroup></Project>",
        )
        write(
            self.root,
            "Tests/Tests.csproj",
            '<Project><ItemGroup><PackageReference Include="NUnit" Version="$(NUnitVersion)" />'
            '</ItemGroup></Project>',
        )
        result = deps.collect(self.root, load_config(self.root))
        nunit = next(p for p in result.packages if p.name == "NUnit")
        self.assertEqual(nunit.version, "4.0.1")
        self.assertFalse(nunit.pinned_by_parent)


class RubyPhpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_gemfile_and_lock(self) -> None:
        write(
            self.root,
            "Gemfile",
            """
source "https://rubygems.org"
gem "rails", "~> 7.1.3"
gem "propshaft", "0.8.0"
group :development, :test do
  gem "rspec", "3.13.0"
end
""",
        )
        write(
            self.root,
            "Gemfile.lock",
            """
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.3.2)
      actionpack (= 7.1.3.2)
    propshaft (0.8.0)
    rspec (3.13.0)

PLATFORMS
  ruby
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["rails"], "7.1.3.2")
        self.assertEqual(versions["propshaft"], "0.8.0")
        self.assertEqual(next(p.scope for p in result.packages if p.name == "rspec"), "dev")

    def test_composer_json_and_lock(self) -> None:
        write(
            self.root,
            "composer.json",
            json.dumps(
                {
                    "require": {
                        "php": "^8.2",
                        "monolog/monolog": "^3.5",
                        "guzzlehttp/guzzle": "7.8.1",
                    },
                    "require-dev": {"phpunit/phpunit": "^10.5"},
                }
            ),
        )
        write(
            self.root,
            "composer.lock",
            json.dumps(
                {
                    "packages": [{"name": "monolog/monolog", "version": "3.5.0"}],
                    "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.20"}],
                }
            ),
        )
        result = deps.collect(self.root, load_config(self.root))
        names = {p.name for p in result.packages}
        self.assertNotIn("php", names)
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["monolog/monolog"], "3.5.0")
        self.assertEqual(versions["guzzlehttp/guzzle"], "7.8.1")
        self.assertEqual(versions["phpunit/phpunit"], "10.5.20")


class DartSwiftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pubspec_and_lock(self) -> None:
        write(
            self.root,
            "pubspec.yaml",
            """
name: demo_app
environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
  flutter:
    sdk: flutter
  http: ^1.2.0
  provider: 6.1.2

dev_dependencies:
  flutter_test:
    sdk: flutter
  mocktail: ^1.0.4
""",
        )
        write(
            self.root,
            "pubspec.lock",
            """
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.1"
  async:
    dependency: transitive
    description:
      name: async
    source: hosted
    version: "2.11.0"
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        names = {p.name for p in result.packages}
        self.assertNotIn("flutter", names)
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["http"], "1.2.1")
        self.assertEqual(versions["provider"], "6.1.2")
        async_pkg = next(p for p in result.packages if p.name == "async")
        self.assertTrue(async_pkg.indirect)
        self.assertFalse(async_pkg.direct)
        self.assertEqual(next(p.scope for p in result.packages if p.name == "mocktail"), "dev")

    def test_swift_package_and_resolved(self) -> None:
        write(
            self.root,
            "Package.swift",
            """
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Demo",
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/Alamofire/Alamofire", exact: "5.9.1"),
        .package(path: "../LocalKit"),
    ]
)
""",
        )
        write(
            self.root,
            "Package.resolved",
            json.dumps(
                {
                    "pins": [
                        {
                            "identity": "swift-nio",
                            "location": "https://github.com/apple/swift-nio.git",
                            "state": {"version": "2.65.0"},
                        }
                    ]
                }
            ),
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["github.com/apple/swift-nio"], "2.65.0")
        self.assertEqual(versions["github.com/Alamofire/Alamofire"], "5.9.1")
        self.assertIn("../LocalKit", versions)


class BeamDataScienceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_mix_exs_and_lock(self) -> None:
        write(
            self.root,
            "mix.exs",
            """
defp deps do
  [
    {:phoenix, "~> 1.7.10"},
    {:plug, "== 1.15.3"},
    {:jason, "~> 1.4", only: [:dev, :test]}
  ]
end
""",
        )
        write(
            self.root,
            "mix.lock",
            '%{\n  "phoenix": {:hex, :phoenix, "1.7.10", "hash", [:mix], [], "hexpm"},\n'
            '  "plug": {:hex, :plug, "1.15.3", "hash", [:mix], [], "hexpm"}\n}\n',
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["phoenix"], "1.7.10")
        self.assertEqual(versions["plug"], "1.15.3")
        self.assertEqual(next(p.scope for p in result.packages if p.name == "jason"), "dev")

    def test_r_description_and_renv(self) -> None:
        write(
            self.root,
            "DESCRIPTION",
            """
Package: demo
Version: 0.1.0
License: MIT + file LICENSE
Imports:
    dplyr (>= 1.1.0),
    cli
Suggests:
    testthat (>= 3.0.0)
""",
        )
        write(
            self.root,
            "renv.lock",
            json.dumps({"Packages": {"dplyr": {"Package": "dplyr", "Version": "1.1.4"}}}),
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["dplyr"], "1.1.4")
        self.assertEqual(versions["cli"], "")
        self.assertEqual(next(p.scope for p in result.packages if p.name == "testthat"), "dev")

    def test_cabal_build_depends(self) -> None:
        write(
            self.root,
            "demo.cabal",
            """
library
  build-depends:
      base >=4.14 && <5,
      text ==2.0.2
  default-language: Haskell2010
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["text"], "2.0.2")
        self.assertEqual(versions["base"], "")

    def test_julia_project_and_manifest(self) -> None:
        write(
            self.root,
            "Project.toml",
            '[deps]\nJSON = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"\n',
        )
        write(self.root, "Manifest.toml", '[[deps.JSON]]\nversion = "0.21.4"\n')
        result = deps.collect(self.root, load_config(self.root))
        self.assertEqual(next(p.version for p in result.packages if p.name == "JSON"), "0.21.4")


class NativeMixedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_vcpkg_conan_and_conda(self) -> None:
        write(
            self.root,
            "vcpkg.json",
            json.dumps(
                {"dependencies": ["fmt", {"name": "openssl", "version>=": "3.2.1"}]}
            ),
        )
        write(self.root, "conanfile.txt", "[requires]\nzlib/1.2.13\n")
        write(
            self.root,
            "environment.yml",
            """
name: demo
channels:
  - conda-forge
dependencies:
  - python=3.11.9
  - numpy>=1.26
  - pip:
      - requests==2.31.0
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {(p.ecosystem, p.name): p.version for p in result.packages}
        self.assertEqual(versions[("vcpkg", "openssl")], "3.2.1")
        self.assertEqual(versions[("ConanCenter", "zlib")], "1.2.13")
        self.assertEqual(versions[("Conda", "python")], "3.11.9")
        self.assertEqual(versions[("Conda", "numpy")], "")
        self.assertEqual(versions[("PyPI", "requests")], "2.31.0")

    def test_deno_imports_and_github_actions(self) -> None:
        write(
            self.root,
            "deno.json",
            json.dumps({"imports": {"oak": "npm:oak@12.6.1", "std/": "https://deno.land/std@0.220.0/"}}),
        )
        write(
            self.root,
            ".github/workflows/ci.yml",
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/local\n",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {(p.ecosystem, p.name): p.version for p in result.packages}
        self.assertEqual(versions[("npm", "oak")], "12.6.1")
        self.assertIn(("GitHub Actions", "actions/checkout"), versions)
        self.assertNotIn(("GitHub Actions", "./.github/actions/local"), versions)

    def test_monorepo_discovers_all_ecosystems(self) -> None:
        write(self.root, "frontend/package.json", json.dumps({"dependencies": {"react": "^18.2.0"}}))
        write(
            self.root,
            "backend/pom.xml",
            "<project><dependencies><dependency>"
            "<groupId>com.google.guava</groupId><artifactId>guava</artifactId>"
            "<version>33.2.1-jre</version></dependency></dependencies></project>",
        )
        write(self.root, "mobile/pubspec.yaml", "dependencies:\n  dio: 5.4.0\n")
        result = deps.collect(self.root, load_config(self.root))
        found = {package.ecosystem for package in result.packages}
        self.assertEqual(found, {"npm", "Maven", "Pub"})
        self.assertTrue(any(p.name == "com.google.guava:guava" for p in result.packages))


if __name__ == "__main__":
    unittest.main()
