const fs = require('fs')

const securityGroups = JSON.parse(fs.readFileSync('security-groups.json', 'ascii')).SecurityGroups

const networkInterfaces = JSON.parse(fs.readFileSync('network-interfaces.json', 'ascii')).NetworkInterfaces

let pciTableSet = new Set([
	'"Firewall","Source","Destination","Ports",' +
	'"Protocols","Business Justification","Risks","Mitigation Controls"'
])

// Aggregate PCI information
securityGroups.forEach(securityGroup => {
	const matchingInterfaces = networkInterfaces.filter(networkInterface =>
		networkInterface.Groups.some(group =>
			group.GroupId === securityGroup.GroupId
		)
	)

	// Check if any interfaces belong to the security group
	if (matchingInterfaces.length === 0) return
	
	const privateIpAddresses = matchingInterfaces.map(networkInterface =>
		networkInterface.PrivateIpAddresses.map(ip =>
			ip.PrivateIpAddress
		)
	)
	.flat()
	.sort()
	.join('\n')

	const publicIpAddresses = matchingInterfaces.filter(networkInterface =>
		networkInterface.Association?.PublicIp != undefined
	)
	.map(networkInterface =>
		networkInterface.Association?.PublicIp
	)
	.sort()
	.join('\n')

	// Gather ingress information
	securityGroup.IpPermissions.forEach(ipPermission => {
		const privateFirewall = 'Internal'
		const source = ipPermission
			.IpRanges.map(ipRange => ipRange.CidrIp)
			.concat(ipPermission.UserIdGroupPairs
				.map(pair => `UserIdGroupPair ${pair.GroupId}/${pair.UserId}`)
			)
			.join('\n')
		const destination = privateIpAddresses
		const ports = ipPermission.toPort === undefined ?
			'all' : ipPermission.toPort
		const protocols = ipPermission.IpProtocol
		const businessJustification = securityGroup.Description
		const risks = ''
		const mitigationControls = ''
		
		pciTableSet.add(
			[
				privateFirewall, source, destination, ports,
				protocols, businessJustification, risks, mitigationControls
			]
			.map(column => `"${column}"`)
			.join(',')
		)

		// Check if there are public ip addresses
		if(publicIpAddresses === '') return
		
		const publicFirewall = 'Internet'
		const publicDestination = publicIpAddresses

		pciTableSet.add(
			[
				publicFirewall, source, publicDestination, ports,
				protocols, businessJustification, risks, mitigationControls
			]
			.map(column => `"${column}"`)
			.join(',')
		)
	})

	// Gather egress information
	securityGroup.IpPermissionsEgress.forEach(ipPermission => {
		const privateFirewall = 'Internal'
		const source = privateIpAddresses
		const destination = ipPermission
			.IpRanges.map(ipRange => ipRange.CidrIp)
			.concat(ipPermission.UserIdGroupPairs
				.map(pair => `UserIdGroupPair ${pair.GroupId}/${pair.UserId}`)
			)
			.join('\n')
		const ports = ipPermission.FromPort === undefined ?
			'all' : ipPermission.FromPort
		const protocols = ipPermission.IpProtocol === -1 ?
			'all' : ipPermission.IpProtocol
		const businessJustification = securityGroup.Description
		const risks = ''
		const mitigationControls = ''

		pciTableSet.add(
			[
				privateFirewall, source, destination, ports,
				protocols, businessJustification, risks, mitigationControls
			]
			.map(column => `"${column}"`)
			.join(',')
		)

		// Check if there are public ip addresses
		if(publicIpAddresses === '') return
		
		const publicFirewall = 'Internet'
		const publicSource = publicIpAddresses

		pciTableSet.add(
			[
				publicFirewall, publicSource, destination, ports,
				protocols, businessJustification, risks, mitigationControls
			]
			.map(column => `"${column}"`)
			.join(',')
		)
	})
})

// Create CSV
const pciTableCsv = Array.from(pciTableSet)
	.join('\n')

fs.writeFileSync('pci-table.csv', pciTableCsv)
