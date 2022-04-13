// Edit values in this file to fit your needs

// Titles of columns to exclude from the final csv
const excludedCols = ['Source', 'Destination']

// Titles of columns to be used for consolidation, in order
const consolidatedCols = ['Firewall', 'Ports', 'Business Justification']

module.exports = { excludedCols, consolidatedCols }
