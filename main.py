import pefile
import argparse
import time

specgen_version = "1.0"
print("SpecGen " + specgen_version)

parser = argparse.ArgumentParser(description="Decode PE files into WINE .spec files.")
parser.add_argument("-f", "--file", help="Path to the DLL to parse.", default="")
parser.add_argument("-s", "--spec", help="Existing .spec file to add missing syms to.", default="")
parser.add_argument("-o", "--out", help="File to write the generated .spec to.", default="generated.spec")

args = parser.parse_args()
target_file = args.file
out_spec = args.out
pe = pefile.PE(target_file, fast_load=True)

print("Parsed " + target_file + " - Dumping symbols")

class SpecFile():
  def __init__(self, content: str | None):
    self.syms: list[str] = []
    if type(content) is str:
      for line in content.splitlines():
        self.syms.append(line)

  @staticmethod
  def get_sym_line_without_args(sym: str):
    split: list[str] = []
    for word in sym.split(" "):
      if word.startswith("-"):
        continue
      split.append(word)
    return split

  def get_sym_names(self):
    for sym in self.syms:
      if not sym.startswith("@"):
        continue
      sym_name = self.get_sym_line_without_args(sym)[2]
      stop_offset: int | None = None
      for i, char in enumerate(sym_name):
        if char == "(":
          stop_offset = i
          break
      if type(stop_offset) is int:
        sym_name = sym_name[:stop_offset]
      yield sym_name

  def add_sym_str(self, sym_str: str):
    self.syms.append(sym_str)
    
  def add_sym_if_not_present(self, sym_str: str):
    for sym_name in self.get_sym_names():
      new_sym_name = sym_str.split(" ")[2]
      if sym_name == new_sym_name:
        return
    self.add_sym_str(sym_str)
    
  def serialize(self) -> str:
    plaintxt = ""
    for sym in self.syms:
      plaintxt += sym + "\n"
    return plaintxt

spec: SpecFile
try:
  with open(args.spec, "r") as f:
    spec = SpecFile(str(f.read()))
except FileNotFoundError:
  spec = SpecFile(None)

with open (out_spec, "w") as f:
  pe.parse_data_directories()
  start = time.time()
  for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)
    if exp.name is None:
        continue
    spec.add_sym_if_not_present("@ stub " + exp.name.decode("utf-8") + " # off " + str(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)) + ", ordinal " + str(exp.ordinal))
  end = time.time()
  print("Parsed " + str(len(pe.DIRECTORY_ENTRY_EXPORT.symbols)) + " entries in " + str(end - start) + " seconds.")
  f.write("# Generated with SpecGen " + specgen_version + "\n")
  f.write(spec.serialize())
  print("Wrote new spec to " + out_spec)
