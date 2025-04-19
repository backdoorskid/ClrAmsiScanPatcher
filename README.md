# ClrAmsiScanPatcher

**ClrAmsiScanPatcher** aims to bypass the AMSI scan that is performed upon a program calling the **Assembly.Load** function.<br>
This is done by finding the **AmsiScan** function within **clr.dll** by finding an instruction that references a known string, and then patching the function to remove it's functionality.<br>
This is not the same as patching **AmsiScanBuffer** but will have a similar effect.<br>

### Please leave a star if this project helps you
