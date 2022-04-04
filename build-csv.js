const fs = require('fs')

const securityGroups = JSON.parse(fs.readFileSync('security-groups.json', 'ascii')).SecurityGroups

const networkInterfaces = JSON.parse(fs.readFileSync('network-interfaces.json', 'ascii')).NetworkInterfaces

let pciTable = [[
	'Firewall', 'Source', 'Destination', 'Ports',
	'Protocols', 'Business Justification', 'Risks', 'Mitigation Controls'
]]

// Aggregate PCI information
securityGroups.forEach(securityGroup => {
	const matchingInterfaces = networkInterfaces.filter(networkInterface =>
		networkInterface.Groups.some(group =>
			group.GroupId == securityGroup.GroupId
		)
	)
	
	const PrivateIpAddresses = matchingInterfaces.map(networkInterface =>
		networkInterface.PrivateIpAddresses.map(ip =>
			ip.PrivateIpAddress
		)
	)
	.flat()
	.sort()
	.join('\n')

	// Gather ingress information
	securityGroup.IpPermissions.forEach(ipPermission => {
		const firewall = 'TODO'
		const source = 'TODO'
		const destination = PrivateIpAddresses
		const ports = ipPermission.FromPort
		const protocols = ipPermission.IpProtocol
		const businessJustification = securityGroup.Description
		const risks = ''
		const mitigationControls = ''

		
		pciTable.push([
			firewall, source, destination, ports,
			protocols, businessJustification, risks, mitigationControls
		])
	})

	// Gather egress information
	securityGroup.IpPermissionsEgress.forEach(ipPermission => {
		const firewall = 'TODO'
		const source = PrivateIpAddresses
		const destination = 'TODO'
		const ports = ipPermission.FromPort
		const protocols = ipPermission.IpProtocol == -1 ?
			'all' : ipPermission.IpProtocol
		const businessJustification = securityGroup.Description
		const risks = ''
		const mitigationControls = ''

		
		pciTable.push([
			firewall, source, destination, ports,
			protocols, businessJustification, risks, mitigationControls
		])
	})
})

// Create CSV
const pciTableCsv = pciTable.map(row =>
	row.map(column =>
		`"${column}"`
	)
	.join(',')
)
.join('\n')

fs.writeFileSync('pci-table.csv', pciTableCsv)
