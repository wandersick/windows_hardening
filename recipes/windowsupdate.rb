# wandersick comments:
# - To enable use with chef-apply, the first line after comment and the 'if ... end' outer wrapping have been removed

# Windows Update
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' do
  values [{ name: 'NoAutoUpdate', type: :dword, data: 0 },
          { name: 'AUOptions', type: :dword, data: 4 },
          { name: 'ScheduledInstallDay', type: :dword, data: 0 },
          { name: 'ScheduledInstallTime', type: :dword, data: 3 },
          { name: 'NoAutoRebootWithLoggedOnUsers', type: :dword, data: 0 }]
  recursive true
  action :create
end
