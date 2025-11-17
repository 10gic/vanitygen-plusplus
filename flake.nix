# If you run with Nix and you have "flakes" enabled,
# you can just run "nix run" in this directory, and it will run the default executable here ("vanitygen++").
# Also see the note(s) at the top of default.nix.
{
  inputs = {
    # nixpkgs.url = github:NixOS/nixpkgs/nixos-21.11;
    nixpkgs.url = "nixpkgs";
    flake-utils.url = github:numtide/flake-utils;
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      rec {
        packages.default = (import ./default.nix)
          { pkgs = nixpkgs.legacyPackages.${system}; };

        apps = rec {
          default = vanitygen;
          vanitygen = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/vanitygen++";
          };
          oclvanitygen = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/oclvanitygen++";
          };
          keyconv = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/keyconv";
          };
          oclvanityminer = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/oclvanityminer";
          };
        };
      }
    );
}
