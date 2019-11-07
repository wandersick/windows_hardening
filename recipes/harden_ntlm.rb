# wandersick comments:
# - To enable use with chef-apply, the first line after comment and the 'if ... end' outer wrapping have been removed

# NTLM Hardening -- This settings breaks WinRM
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0' do
  values [{ name: 'RestrictReceivingNTLMTraffic', type: :dword, data: 2 },
          { name: 'RestrictSendingNTLMTraffic', type: :dword, data: 2 },
          { name: 'AuditReceivingNTLMTraffic', type: :dword, data: 2 },
          { name: 'allownullsessionfallback', type: :dword, data: 0 },
          { name: 'NTLMMinServerSec', type: :dword, data: 537_395_200 },
          { name: 'NTLMMinClientSec', type: :dword, data: 537_395_200 }]
  action :create
end