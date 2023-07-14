# To run this on nix/nixos, just run `nix-build` in the directory containing this file
# and then run any executable in the result/bin directory,
# e.g. `./result/bin/vanitygen++ -h`
# Or, if there is a corresponding flake.nix file and you have "flakes" enabled,
# you can just run "nix run" and it will run the default executable ("vanitygen++").
# If you want to pass arguments to it or run a different executable, run it these ways:
# nix run .#oclvanitygen -- 1BTC  # put the arguments to be passed to the executable after the --

{ pkgs ? import <nixpkgs> {}}:
with pkgs;
# fastStdenv.mkDerivation { # for faster running times (8-12%) BUT... nondeterministic builds :(
stdenv.mkDerivation {
  name = "vanitygen++";
  src = ./.;
  
  enableParallelBuilding = true;

  # any dependencies/build tools needed at compilation/build time here
  nativeBuildInputs = [ pkg-config gcc opencl-clhpp ocl-icd curlpp ];

  # any runtime dependencies here
  buildInputs = [ pcre openssl curl ];

  # the bash shell steps to build it
  buildPhase = ''
    make all
  '';

  # for a generic copy of all compiled executables:
  # cp $(find * -maxdepth 1 -executable -type f) $out/bin/
  # to copy specific build outputs:
  # cp keyconv oclvanitygen++ oclvanityminer vanitygen++ $out/bin/
  installPhase = ''
    mkdir -p $out/bin
    cp $(find * -maxdepth 1 -executable -type f) $out/bin/
  '';
}
