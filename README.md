This program expands the code section of a .cro file so that custom code can be added.

To use, simply select the .cro file you wish to expand, enter the (minimum) number of (32-bit) instructions you wish to make room for (cros are required to have a file size that is a multiple of 0x1000, so the program will round up to the nearest multiple of 0x1000), and then select an output file.

The new space will be located at the very end of the existing code section, and will be filled with 0xFF to make it easy to see where the new space is (the region immediately prior to the newly allocated space is used for writing values to once the CRO is loaded, and the region afterward is not allocated to _anything_ and will result in a crash if referenced).

Please note that at this time I have tested this with a limited number of CRO files (just a few from Pokemon USUM), so it is possible that there are quirks of other CRO files that the current version does not account for. If such a problem occurs, please file a bug report so I can investigate.
