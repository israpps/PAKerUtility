# PAKerUtility
 Command line tool to (un)pack `.PAK` files used by the Sony utility discs for PS2 and PSX.

 Rebuilt on Cmake By El_isra
 
 
Original Readme by SP193:
```log
PAKer Utility v1.01 - 2014/07/07
--------------------------------

The PAKer utility unpacks and creates PAK files. PAK files are the archive files that are used by the Sony utility discs, like the DVD player and HDD utility discs, as well as the PSX update discs.

If you still don't know what PAK files are, then you probably won't ever need to use this tool.

Credits:
--------

l_Oliveira, for providing me with the basic information for making such a tool.

And last, but not least: when I first wrote the tool, I didn't find the original author who wrote the the PAK file unpacking code.
Today, I learned that he might be "Codec80". Sorry about not asking you first about using your work in another tool, and I hope that you're fine with this. :/

Changelog:
----------
2014/07/07	- v1.01:
	*Bugfix: fixed memory corruption that occurs when building a PAK archive, as an 8-bit variable was used for indexing.
	*PAKer will now fail and remove the broken PAK archive, if at least one file could not be added successfully.
	*Changed the internal handling structure, so that there will be space for the NULL terminator of the name and ident fields.

2012/05/05	- v1.00:
	*Initial public release
```