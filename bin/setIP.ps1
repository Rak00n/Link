$IP = "10.0.0.1"
$MaskBits = 24 # This means subnet mask = 255.255.255.0
$Gateway = "10.10.10.1"
$IPType = "IPv4"
# Retrieve the network adapter that you want to configure
$adapters = Get-NetAdapter
# Remove any existing IP, gateway from our ipv4 adapter

foreach ($adapter in $adapters) {
	if($adapter.Name -eq "Link") {
		echo $adapter.Name
		echo $adapter.MacAddress
	}
	
}
exit
# If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
 # $adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
# }
# If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
 # $adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
# }
 Configure the IP address and default gateway
# $adapter | New-NetIPAddress `
 # -AddressFamily $IPType `
 # -IPAddress $IP `
 # -PrefixLength $MaskBits `
 # -DefaultGateway $Gateway
Configure the DNS client server IP addresses
# $adapter | Set-DnsClientServerAddress -ServerAddresses $DNS