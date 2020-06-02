# Automated Windows Server Hardening with Chef

These Windows Server hardening Chef recipes forked from [MattTunny/windows_hardening](https://github.com/MattTunny/windows_hardening) repository differ from the original in being compatible with `chef-apply`, converted by wandersick as inspired by readers' feedback of his blog post, [Quick Windows Hardening with Infrastructure-as-Code – Chef and Inspec](https://tech.wandersick.com/2018/04/windows-server-hardening-with-chef.html). For details, please refer to the Performing Hardening section of the blog post.

A test run has been performed with the results logged and [documented here](https://github.com/wandersick/windows_hardening/blob/master/TESTRUN.md).

List of files:

```
windows_hardening
│   LICENSE
│   metadata.rb
│   README.md
│   TESTRUN.md
│
├───files
│       audit_settings.csv
│       localComputer.inf
│       windows_update.ps1
│
├───recipes
│       ciphers.rb
│       core_hardening.rb
│       deleteautologon.rb
│       enable_firewall.rb
│       enable_winrm.rb
│       harden_ntlm.rb
│       harden_winrm.rb
│       schedule_task_update.rb
│       windowsupdate.rb
│
└───test
    └───integration
        └───default
                default_spec.rb
```

If unmodified, the script should be stored and run under `c:\temp\windows_hardening` where:

- `C:\temp\windows_hardening\recipes` contains recipes such as `core_hardening.rb`
- `C:\temp\windows_hardening\test\integration\default` contains `inspec` tests, i.e. `default_spec.rb`
- `C:\temp\windows_hardening\files` contains supplementary files, i.e. `audit_settings.csv`, `localComputer.inf` and `windows_update.ps1`
- Also, temporary file `tempexport.inf` would be generated under `C:\temp\` when `inspec` (test) is run, and `secedit.sdb` (also `secedit.jfm`) in `C:\temp\windows_hardening\files` when `chef-apply` is run. Be sure to have write permission in those directories

If the script is run from another location, the hard-coded paths in the recipes (i.e. the above entries involving `temp` folder under `C:\`) should be modified.

For recipe-specific instructions, refer to comments in each recipe file.

<hr>

For the original README.md content, refer to [MattTunny/windows_hardening](https://github.com/MattTunny/windows_hardening)

Note: The commands in the original README.md there are unsuitable if you follow the [blog post](https://tech.wandersick.com/2018/04/windows-server-hardening-with-chef.html) which is compatible with `chef-apply`
