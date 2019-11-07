# wandersick comments:
# - To enable use with chef-apply, the first line after comment and the 'if ... end' outer wrapping have been removed

# Disable old protocols TLS 1.0
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.0\Server' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable old protocols TLS 1.1
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.1\Server' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable old protocols PCT 1.0
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\PCT 1.0\Server' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable old protocols SSLv2.0
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 2.0\Server' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable old protocols SSLv3.0 Client
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Client' do
  values [{ name: 'DisabledByDefault', type: :dword, data: 1 }]
  recursive true
  action :create
end

# Disable old protocols SSLv3.0 Server
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Server' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable Weak Ciphers - DES
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable Weak Ciphers - NULL
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable Weak Ciphers - RC2 40/128
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable Weak Ciphers - RC2 56/128
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable Weak Ciphers - RC4 40/128
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable Weak Ciphers - RC4 56/128
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end

# Disable Weak Ciphers - RC4 64/128
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' do
  values [{ name: 'Enabled', type: :dword, data: 0 }]
  recursive true
  action :create
end
