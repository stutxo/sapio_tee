{
  description = "Sapio program oracle for AWS Nitro Enclaves (x86_64-linux)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    enclaver = {
      url = "github:joshdoman/nix-enclaver/abe3b6ace922685a20f754549f774cae70cf32e7";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.flake-utils.follows = "flake-utils";
      inputs.nitro-util.inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, enclaver }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        # Only the libc target changes: compiler/build scripts run on native x86_64.
        # No ARM, Darwin, or architecture-cross build is advertised.
        pkgsMusl = import nixpkgs {
          inherit system overlays;
          crossSystem.config = "x86_64-unknown-linux-musl";
        };
        toolchain = pkgs.rust-bin.stable."1.98.1".default.override {
          targets = [ "x86_64-unknown-linux-musl" ];
        };
        rustPlatform = pkgsMusl.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };
        nativeTools = with pkgs; [ cmake pkg-config clang llvmPackages.llvm ];
        sapioDependency = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).dependencies.emulator_connect;
        sapioSource = builtins.fetchGit {
          url = sapioDependency.git;
          rev = sapioDependency.rev;
          allRefs = true;
        };
        app = rustPlatform.buildRustPackage {
          pname = "sapio-tee";
          version = "0.2.0";
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ./evaluators ];
          };
          cargoLock = {
            lockFile = ./Cargo.lock;
            # Every git source is fetched at its exact Cargo.lock commit; no
            # workstation paths or floating branch resolution enters this build.
            allowBuiltinFetchGit = true;
          };
          buildNoDefaultFeatures = true;
          cargoBuildFlags = [ "--locked" "--bin" "sapio-tee" ];
          doCheck = false;
          # Cargo vendoring splits workspace members into sibling directories.
          # Sapio's include_bytes! also needs the tracked workspace WASM files.
          prePatch = ''
            mkdir -p "$cargoDepsCopy/evaluators"
            cp -r ${sapioSource}/evaluators/artifacts "$cargoDepsCopy/evaluators/"
          '';
          nativeBuildInputs = nativeTools;
          # Wasmer's bindgen runs on the glibc build host, not in the enclave.
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          RUSTFLAGS = "-C target-feature=+crt-static";
          postInstall = ''
            cp -L "$out/bin/sapio-tee" "$out/bin/entrypoint"
          '';
          meta.platforms = [ "x86_64-linux" ];
        };
        # The pinned init package predates buildGoModule's env attribute set.
        # Preserve its source/flags while moving CGO_ENABLED to the current API.
        init = pkgs.callPackage "${enclaver.inputs.nitro-util}/init" {
          buildGoModule = args: pkgs.buildGoModule
            ((builtins.removeAttrs args [ "CGO_ENABLED" ]) // {
              env.CGO_ENABLED = args.CGO_ENABLED;
            });
        };
        nitro = enclaver.inputs.nitro-util;
        compatibleEnclaver = (import "${enclaver}/flake.nix").outputs {
          self = enclaver;
          inherit nixpkgs rust-overlay flake-utils;
          nitro-util = nitro // {
            lib = nitro.lib // {
              ${system} = nitro.lib.${system} // {
                buildEif = args: nitro.lib.${system}.buildEif
                  (args // { init = "${init}/bin/init"; });
              };
            };
          };
        };
        enclave = compatibleEnclaver.lib.${system}.x86_64.makeAppEif {
          appPackage = app;
          configFile = ./enclaver.yaml;
        };
        runner = enclaver.packages.${system}.x86_64-enclaver;
      in {
        packages = {
          inherit app;
          eif = enclave.eif;
          default = enclave.eif;
          rootfs = enclave.rootfs;
          enclaver = runner;
        };
        apps.enclaver = {
          type = "app";
          program = "${runner}/bin/enclaver";
        };
        devShells.default = pkgs.mkShell {
          packages = nativeTools ++ [
            toolchain pkgs.stdenv.cc pkgs.curl pkgs.jq
            (pkgs.python3.withPackages (ps: [ ps.cbor2 ps.cryptography ps.pyopenssl ]))
            pkgs.openssl pkgs.cacert pkgs.git
          ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      });
}
