# wandersick comments: 

# - Change user, password and cwd (path containing windows_update.ps1) for the Windows Update scheduled task
#   (if unchanged, they assume 'administrator', 'TechPassword12!' and 'c:\\temp\windows_hardening\\files' respectively)

# - Below Lines have been removed by WS to avoid errors when using this recipe with chef-apply
#   To specify the path of the file, please do so in 'cwd' as described above instead

#   # cookbook_file 'c:/Windows/temp/windows_update.ps1' do
#     action :create
#   end

# - For the second windows_task block, it had to be renamed from windows_update to WindowsUpdate in order for the task to run

# Windows Update script
windows_task 'windows_update' do
  task_name 'WindowsUpdate'
  user '_administrator'
  password 'TechPassword12!'
  force true
  cwd 'C:\\temp\\windows_hardening\\files'
  command 'windows_update.ps1'
  run_level :highest
  frequency :daily
  start_time '03:00'
end

# wandersick comments: This had to be changed from windows_update to WindowsUpdate in order for the task to run
windows_task 'WindowsUpdate' do
  action :run
end
