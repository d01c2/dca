# dca
Using Differential Computation Analysis to quickly extract the secret key in WB implementation. For this repository, I'll use [Intel Pin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html) for generating execution traces of a running process.

## Environments
- Linux 5.15.153.1-microsoft-standard-WSL2 x86_64
- Intel Pin Version 3.31

## Installation
- [SideChannelMarvels/Tracer/TracerPIN](https://github.com/SideChannelMarvels/Tracer/tree/master/TracerPIN)
- [SideChannelMarvels/Deadpool/deadpool_dca.py](https://github.com/SideChannelMarvels/Deadpool/blob/master/deadpool_dca.py)
	- Minor fix for Python3 migration
- [SideChannelMarvels/DareDevil](https://github.com/SideChannelMarvels/Daredevil)

## Targets
- [x] Wyseur Challenge, 2007
	- [x] Reveal round key #0
	- [ ] Reveal other round keys
	- [ ] Transform round keys into secret key
- [ ] Hack.lu Challenge, 2009
- [ ] SSTIC Challenge, 2012
- [ ] Klinec Implementation, 2013

## Reference
- [SideChannelMarvels/Deadpool](https://github.com/SideChannelMarvels/Deadpool)