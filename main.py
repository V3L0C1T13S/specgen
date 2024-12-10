import pefile
import argparse

specgen_version = "1.0"
print("SpecGen " + specgen_version)

parser = argparse.ArgumentParser(description="Decode PE files into WINE .spec files.")
parser.add_argument("-f", "--file", help="Path to the DLL to parse.", default="")
parser.add_argument("-s", "--spec", help="Existing .spec file to add missing syms to.", default="")

args = parser.parse_args()
target_file = args.file
pe = pefile.PE(target_file, fast_load=True)

print("Parsed " + target_file + " - Dumping symbols")

class SpecFile():
  def __init__(self, content: str | None):
    self.syms: list[str] = []
    if type(content) is str:
      for line in content.splitlines():
        #if not line.startswith("@"):
        #  continue
        self.syms.append(line)

  def add_sym_str(self, sym_str: str):
    self.syms.append(sym_str)
    
  def add_sym_if_not_present(self, sym_str: str):
    for sym in self.syms:
      if not sym.startswith("@"):
        continue
      old_split = sym.split(" ")
      new_split: list[str] = []
      for word in old_split:
        if word.startswith("-"):
          continue
        new_split.append(word)
      sym_name = new_split[2]
      stop_offset: int | None = None
      for i, char in enumerate(sym_name):
        #print("char: " + char + ", i: " + str(i))
        if char == "(":
          stop_offset = i
          break
      if type(stop_offset) is int:
        sym_name = sym_name[:stop_offset]
      new_sym_name = sym_str.split(" ")[2]
      #print("sym: " + sym_name + ", new_sym: " + new_sym_name)
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

out_spec = "generated.spec"
with open (out_spec, "w") as f:
  pe.parse_data_directories()
  for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)
    if exp.name is None:
        continue
    spec.add_sym_if_not_present("@ stub " + exp.name.decode("utf-8") + " # off " + str(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)) + ", ordinal " + str(exp.ordinal))
  f.write("# Generated with SpecGen " + specgen_version + "\n")
  f.write(spec.serialize())
  print("Wrote new spec to " + out_spec)
