const fs = require('fs')
const config = require('./config.js')

const securityGroups = JSON.parse(fs.readFileSync('security-groups.json', 'ascii')).SecurityGroups

const networkInterfaces = JSON.parse(fs.readFileSync('network-interfaces.json', 'ascii')).NetworkInterfaces

const columnTitles = [
	'Firewall', 'Source', 'Destination', 'Ports',
	'Protocols', 'Business Justification', 'Risks', 'Mitigation Controls'
]

const excludedIndexes = columnTitles
	.map((title, index) => config.excludedCols.includes(title) ? index : -1)
	.filter(index => index !== -1)

const filteredTitles = columnTitles
	.filter((column, index) => !excludedIndexes.includes(index))

const consolidatedIndexes = filteredTitles
	.map((title, index) => config.consolidatedCols.includes(title) ? index : -1)
	.filter(index => index !== -1)

let pciTableSet = new Set([
	filteredTitles
	.map(column => `"${column}"`)
	.join(',')
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
		const protocols = ipPermission.IpProtocol === '-1' ?
			'all' : ipPermission.IpProtocol
		const businessJustification = securityGroup.Description
		const risks = ''
		const mitigationControls = ''
		
		pciTableSet.add(
			[
				privateFirewall, source, destination, ports,
				protocols, businessJustification, risks, mitigationControls
			]
			.filter((column, index) => !excludedIndexes.includes(index))
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
			.filter((column, index) => !excludedIndexes.includes(index))
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
		const protocols = ipPermission.IpProtocol === '-1' ?
			'all' : ipPermission.IpProtocol
		const businessJustification = securityGroup.Description
		const risks = ''
		const mitigationControls = ''

		pciTableSet.add(
			[
				privateFirewall, source, destination, ports,
				protocols, businessJustification, risks, mitigationControls
			]
			.filter((column, index) => !excludedIndexes.includes(index))
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
			.filter((column, index) => !excludedIndexes.includes(index))
			.map(column => `"${column}"`)
			.join(',')
		)
	})
})

// Combine rows
function squash(rows){
	const collection = rows[0]
		.map(bucket => new Set)

	rows.forEach(row =>
		row.forEach((value, index) => collection[index].add(value))
	)

	return collection
		.map(values =>
			values.has('all') ? // 'all' discards other values
				'all'
				: Array.from(values).join(',')
		)
}

// Consolidate rows recursively
function consolidate(rows, indexes){
	if (indexes.length === 0) return [squash(rows)]

	const index = indexes[0]
	const groups = {}

	rows.forEach(row =>
		Object.keys(groups).includes(row[index]) ?
			groups[row[index]].push(row)
			: groups[row[index]] = [row]
	)

	return Object.values(groups).map(groupedRows =>
			consolidate(groupedRows, indexes.slice(1))
		)
		.flat()
}

// Consolidate rows
const pciTableArr = Array.from(pciTableSet)
	.map(row =>
		row
		.slice(1, -1)
		.split('","')
	)

const consolidatedArr = consolidate(pciTableArr, consolidatedIndexes)

// Create CSV
const pciTableCsv = consolidatedArr
	.map(row =>
		row
		.map(column => `"${column}"`)
		.join(',')
	)
	.join('\n')

fs.writeFileSync('pci-table.csv', pciTableCsv)
