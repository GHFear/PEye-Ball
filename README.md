# PEye-Ball

**PEye-Ball 0.1.2** <br>
PE Parser for Windows and Linux.<br>

**0.1.2 Changelog:** <br>
-Added support for parsing base relocations.<br>
-Fixed some bugs.<br>
-Now printing to file instead of console.<br>

**PEye-Ball Supports:** <br>
-Dos Header<br>
-NT Headers<br>
-Section Headers<br>
-Imports<br>
-Exports<br>
-Delayed Imports<br>


Build project with cmake 3.10 and above from (build) directory with terminal commands:<br>
**"cmake ../"**    -- To create cmake project files.<br>
**"make"**         -- To build executable.<br>

Will add more features to this project in the future.<br>

**0.1.1 Changelog:** <br>
-Made the parser use different threads for each header section we parse.<br>

**0.1.0 Changelog:** <br>
-Added support for parsing delayed load imports.<br>
-Fixed print types and some wrong casts.<br>

**0.0.9 Changelog:** <br>
-Added support for parsing exports.

By GHFear.
