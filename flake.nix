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
        # nitro-util's EIF builder, with the compiled-from-source init swapped in.
        buildEif = args: nitro.lib.${system}.buildEif
          (args // { init = "${init}/bin/init"; });
        # Enclave image assembly vendored from nix-enclaver's makeAppEif
        # (joshdoman/nix-enclaver abe3b6a), with one change: the kernel.
        # nix-enclaver overrides pkgs.linux_6_12 on top of nixpkgs' common
        # config, which compiles essentially every driver as a module —
        # >10 GB of outputs and ~1h of compile time, enough to exhaust the
        # ~14 GB disk of a GitHub ubuntu runner mid-build. The enclave needs
        # only upstream x86_64 defconfig plus the Nitro options below, so the
        # common config is disabled entirely.
        enclaveKernel = pkgs.linux_6_12.override {
          enableCommonConfig = false;
          autoModules = false;
          structuredExtraConfig = with pkgs.lib.kernel; {
            # Boot: ramdisks, console, devtmpfs, tmpfs, entropy.
            BLK_DEV_INITRD = yes;
            RD_GZIP = yes;
            DEVTMPFS = yes;
            DEVTMPFS_MOUNT = yes;
            SERIAL_8250 = yes;
            SERIAL_8250_CONSOLE = yes;
            TMPFS = yes;
            # Nitro Enclave devices: virtio-mmio, vsock, and the NSM driver.
            NET = yes;
            INET = yes;
            VIRTIO = yes;
            VIRTIO_MENU = yes;
            VIRTIO_MMIO = yes;
            VIRTIO_MMIO_CMDLINE_DEVICES = yes;
            VSOCKETS = yes;
            VIRTIO_VSOCKETS = yes;
            CRYPTO_USER_API = yes;
            CRYPTO_USER_API_HASH = yes;
            NSM = yes;
          };
          ignoreConfigErrors = false;
        };
        # The enclaver supervisor (odyn), statically linked against musl.
        enclaverCrate = pkgsMusl.rustPlatform.buildRustPackage {
          pname = "enclaver-app";
          version = "0.1.0";
          src = pkgs.lib.cleanSourceWith {
            src = enclaver;
            filter = path: type:
              let
                relativePath = pkgs.lib.removePrefix (toString enclaver + "/") (toString path);
              in
                !(pkgs.lib.hasPrefix "examples/" relativePath) &&
                !(pkgs.lib.hasPrefix ".github/" relativePath) &&
                !(relativePath == "README.md");
          };
          buildFeatures = [ "odyn" ];
          cargoLock.lockFile = enclaver + "/Cargo.lock";
          doCheck = false;
          RUSTFLAGS = "-C target-feature=+crt-static";
        };
        # Assemble a Nitro EIF around an application bin/entrypoint.
        makeAppEif = { appPackage, configFile }:
          let
            configContent = builtins.readFile configFile;
            nameMatch = builtins.match ".*name: \"?([^\"]+)\"?.*" configContent;
            eifName = pkgs.lib.replaceStrings [ "-" ] [ "_" ] (if nameMatch != null
              then builtins.head nameMatch
              else "application");
            muslInterpreter = "/lib/ld-musl-x86_64.so.1";
            entrypointScript = pkgs.writeShellScriptBin "start-enclaver" ''
              #!${pkgs.pkgsStatic.busybox}/bin/sh
              set -ex
              exec /bin/odyn --config-dir /etc/enclaver /bin/entrypoint
            '';
            enclaveRootFs = pkgs.runCommand "enclave-rootfs" {
              nativeBuildInputs = [
                enclaverCrate
                appPackage
                pkgs.pkgsStatic.busybox
                pkgsMusl.stdenv.cc.libc
                entrypointScript
                pkgs.patchelf
              ];
            } ''
              mkdir -p $out/bin $out/lib $out/etc/enclaver
              cp -L ${pkgsMusl.stdenv.cc.libc}/lib/* $out/lib/
              cp -L ${enclaverCrate}/bin/odyn $out/bin/odyn
              cp -L ${appPackage}/bin/* $out/bin/
              # The application package must provide bin/entrypoint.
              if [ ! -f ${appPackage}/bin/entrypoint ]; then
                echo "Error: appPackage must provide a binary named 'entrypoint'"
                exit 1
              fi
              chmod +w $out/bin/*
              for binary in $out/bin/*; do
                if [ -f "$binary" ] && [ -x "$binary" ]; then
                  patchelf --set-interpreter ${muslInterpreter} "$binary" || true
                fi
              done
              cp -L ${pkgs.pkgsStatic.busybox}/bin/busybox $out/bin/
              ${pkgs.pkgsStatic.busybox}/bin/busybox --list | while read applet; do
                ln -s /bin/busybox $out/bin/$applet
              done
              cp -L ${entrypointScript}/bin/start-enclaver $out/bin/start-enclaver
              chmod +x $out/bin/start-enclaver
              cp -L ${configFile} $out/etc/enclaver/enclaver.yaml
            '';
            baseEif = buildEif {
              name = "${eifName}-x86_64";
              kernel = "${enclaveKernel}/bzImage";
              kernelConfig = "${enclaveKernel.configfile}";
              nsmKo = null;
              copyToRoot = enclaveRootFs;
              entrypoint = "/bin/start-enclaver";
              env = "";
            };
            enclaverEif = pkgs.runCommand "${eifName}-x86_64" { } ''
              mkdir -p $out
              cp ${baseEif}/* $out/
              cp ${baseEif}/image.eif $out/${eifName}.eif
              rm -f $out/image.eif
            '';
          in
          {
            eif = enclaverEif;
            rootfs = enclaveRootFs;
          };
        enclave = makeAppEif {
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
          enclave-kernel = enclaveKernel;
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
