let pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    (pkgs.python312.withPackages (python-pkgs: with python-pkgs; [
      pefile
      argparse
    ]))
  ];
}
