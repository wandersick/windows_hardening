# wandersick comments:
# - To enable use with chef-apply, the first line after comment and the 'if ... end' outer wrapping have been removed

powershell_script 'enableWinRM' do
  code <<-EOH
# PS Remoting and & winrm.cmd basic config
Enable-PSRemoting -Force -SkipNetworkProfileCheck
& winrm.cmd set winrm/config '@{MaxTimeoutms="1800000"}'
& winrm.cmd set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
& winrm.cmd set winrm/config/winrs '@{MaxShellsPerUser="50"}'
#Server settings - support username/password login
& winrm.cmd set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
EOH
end
