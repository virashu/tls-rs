{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = [ pkgs.openssl pkgs.gcc ];
}
