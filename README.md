# SpecGen

SpecGen is a reverse engineering tool for WINE developers that allows generating .spec files from exported symbols in PE files. Its primary purpose is to assist in the reverse engineering of programs that use non-standard ways of finding symbols.

## Example usage

The following snippet will append missing symbols into the WINE .spec file

```sh
python3 ./main.py -f ./target.dll -s wine_source/dlls/example/example.spec
```
