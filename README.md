# md5hashmt
Multi-threaded version of the basic md5hash, running on command-line console.  Requires .NET 6.0 runtime library.

This is meant to be a companion to md5hash.  I use this only a few times a year to sweep the MD5 on my drive pools.

Run this without arguments to get the commnad-line help.

```
md5hashmt -p [prjpath] -m [mode] -l verbosity
      modes:
          SCAN: Just scan the files to read attached MD5
          VERIFY: Verify all files against its attached MD5
          ATTACH: Generate and attach MD5 on all files, will skip files with existing MD5

      verbosity:
        INFO: General information, green color
        WARNING: Warning which will not negatively impact operations, orange/yellow color
        ERROR: File operation error, may require user intervention/verification

```

md5hashmt requires a project file.  The project file specifies the # of CPU threads to use and the list of folders to scan.  For best results, threads should be limited to # of CPU cores on your processor, and folders should reflect individual HDDs.  This way you make maximum use of your CPU cores, and no two threads will access the same HDD which results in thrashing.  See sample project file for more details.
