flash-rtmfp-hook
================
WARNING: This project only work with flash player "11.2.202.233" win32 version!

This is a hook dll for analysis the Real-Time Media Flow Protocol(RTMFP) of Adobe Flash Player. You can inject this dll into flash player's process, so that it will log the AES key and every packet of RTMFP into a log file named "flash.log" in the current working directory. 

The flash player to be injected must has the version of "11.2.202.233 standalone debug". You can download it from http://fpdownload.macromedia.com/get/flashplayer/installers/archive/fp_11.2.202.233_archive.zip . 

If you are using Vista or Windows 7, you have to  disable ASLR(Address Space Load Randomization) by:
1. Modify the PE Header of that exe file.
2. Or, you can download "Enhanced Mitigation Experience Toolkit" from http://www.microsoft.com/download/, use it to disable ASLR globally.

To compile the source code, you should have the "visual studio 2010" installed , and the "Detours Express 3.0" library which can be downloaded from http://research.microsoft.com/en-us/projects/detours/ .

Precompiled binary : http://www.sunchangming.com/files/soft/flashplayer.zip 

