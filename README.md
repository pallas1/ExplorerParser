# ExplorerParser

ExplorerParser is a fast block file parser written in C++ which creates db files for [MiniExplorer](https://github.com/MiniblockchainProject/MiniExplorer/). It was created in Code::Blocks and has been tested to compile with mingw64 on Windows, the project file is included.

The binary should be placed in the root directory of the explorer. The first time you run the parser the first argument should be -firstrun and the second argument should be your coin data directory.

The 2nd argument may need to be encapsulated in quotes on Windows. Command line example:

ExplorerParser -firstrun "C:\Users\MyName\AppData\Roaming\Cryptonite\blocks"

On an average machine it should take around 30 minutes to finish computing and saving the explorer db files the first time you run it. To update the db files any time after that use the -update argument.

To compute a rich list of the top 1000 richest addresses use the -richlist argument. The second argument should always be the coin data directory and is always required regardless of the first argument.

DEPENDENCIES:
- GMP
- CryptoPP
- Sparsepp

Static library files compiled with mingw64 can be found here: 
https://mega.nz/#!ngs31AJL!NahJ5AF9T_cIOVpb-T-oZe6kAVyI6lYP2ji-EC3H3E8