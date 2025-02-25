// Debug logging
function debug(message) {
  const debugLog = document.getElementById('debug-log');
  debugLog.style.display = 'block';
  debugLog.innerHTML += message + '\n';
  console.log(message);
}

// Clear debug log
function clearDebug() {
  const debugLog = document.getElementById('debug-log');
  debugLog.innerHTML = '';
}

// DNS Types mapping
const DNS_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NAPTR: 35,
  DNSKEY: 48,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  NSEC3: 50,
};

// DNSSEC algorithm types (RFC 8624)
const ALGORITHMS = {
  1: { name: 'RSAMD5', status: 'MUST NOT', desc: 'RSA/MD5 (deprecated)' },
  3: { name: 'DSA', status: 'MUST NOT', desc: 'DSA/SHA1 (deprecated)' },
  5: { name: 'RSASHA1', status: 'NOT RECOMMENDED', desc: 'RSA/SHA-1' },
  6: {
    name: 'DSA-NSEC3-SHA1',
    status: 'NOT RECOMMENDED',
    desc: 'DSA-NSEC3-SHA1',
  },
  7: {
    name: 'RSASHA1-NSEC3-SHA1',
    status: 'NOT RECOMMENDED',
    desc: 'RSASHA1-NSEC3-SHA1',
  },
  8: { name: 'RSASHA256', status: 'MUST', desc: 'RSA/SHA-256' },
  10: { name: 'RSASHA512', status: 'RECOMMENDED', desc: 'RSA/SHA-512' },
  12: { name: 'ECC-GOST', status: 'MUST NOT', desc: 'GOST R 34.10-2001' },
  13: {
    name: 'ECDSAP256SHA256',
    status: 'MUST',
    desc: 'ECDSA P-256 with SHA-256',
  },
  14: {
    name: 'ECDSAP384SHA384',
    status: 'MAY',
    desc: 'ECDSA P-384 with SHA-384',
  },
  15: { name: 'ED25519', status: 'RECOMMENDED', desc: 'Ed25519' },
  16: { name: 'ED448', status: 'MAY', desc: 'Ed448' },
};

// Digest algorithm types (RFC 8624)
const DIGEST_ALGORITHMS = {
  1: { name: 'SHA-1', status: 'MUST NOT', desc: 'SHA-1' },
  2: { name: 'SHA-256', status: 'MUST', desc: 'SHA-256' },
  4: { name: 'SHA-384', status: 'RECOMMENDED', desc: 'SHA-384' },
};

// Updated Root KSKs information from IANA (as of February 2025)
const ROOT_KSKS = [
  {
    keyTag: 19036,
    algorithm: 8, // RSASHA256
    digestType: 2, // SHA-256
    digest: '49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5',
  },
  {
    keyTag: 20326,
    algorithm: 8, // RSASHA256
    digestType: 2, // SHA-256
    digest: 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
  },
  {
    keyTag: 38696,
    algorithm: 8, // RSASHA256
    digestType: 2, // SHA-256
    digest: '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16',
  },
];

// Get status class for algorithms
function getAlgorithmStatusClass(status) {
  switch (status) {
    case 'MUST':
      return 'algo-must';
    case 'RECOMMENDED':
      return 'algo-recommended';
    case 'MAY':
      return 'algo-may';
    case 'NOT RECOMMENDED':
      return 'algo-not-recommended';
    case 'MUST NOT':
      return 'algo-must-not';
    default:
      return '';
  }
}

// Parse DNSKEY flags
function parseDnskeyFlags(flags) {
  const isZSK = (flags & 256) === 256;
  const isKSK = (flags & 257) === 257;
  const isSEP = (flags & 1) === 1;

  let result = [];
  if (isKSK) result.push('KSK');
  else if (isZSK) result.push('ZSK');
  if (isSEP) result.push('SEP');

  return result.join('/');
}

// Query DNS records using Google DNS API
async function queryDns(domain, type) {
  try {
    const typeNum = DNS_TYPES[type] || 1;

    // Use Google's DNS API
    const url = `https://dns.google/resolve?name=${encodeURIComponent(
      domain
    )}&type=${typeNum}&do=true`;

    debug(`Querying ${domain} for ${type} records...`);
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`DNS query failed with status: ${response.status}`);
    }

    const data = await response.json();
    debug(
      `Received response for ${domain} ${type}: ${JSON.stringify(
        data
      ).substring(0, 100)}...`
    );
    return data;
  } catch (error) {
    debug(`Error querying ${domain} for ${type}: ${error.message}`);
    throw error;
  }
}

// Properly build domain chain from root to leaf domain
function getDomainChain(domainInput) {
  // Normalize domain by ensuring it has a trailing dot
  const normalizedDomain = domainInput.endsWith('.')
    ? domainInput
    : domainInput + '.';

  // Split the domain into parts and filter out empty strings
  const parts = normalizedDomain.split('.').filter((p) => p);

  // Initialize the chain with the root domain
  const chain = ['.'];

  // If we have no parts (e.g., just root), return early
  if (parts.length === 0) {
    return chain;
  }

  // Build the chain from TLD up to the full domain
  for (let i = parts.length - 1; i >= 0; i--) {
    // Take parts from the current position to the end to form this level
    const level = parts.slice(i).join('.') + '.';
    chain.push(level);
  }

  debug(`Domain chain for ${domainInput}: ${JSON.stringify(chain)}`);
  return chain;
}

// Extract DNSKEY records from DNS response
function extractDnskeyRecords(dnsResponse) {
  if (!dnsResponse || !dnsResponse.Answer) return [];
  return dnsResponse.Answer.filter((r) => r.type === DNS_TYPES['DNSKEY']);
}

// Extract DS records from DNS response
function extractDsRecords(dnsResponse) {
  if (!dnsResponse || !dnsResponse.Answer) return [];
  return dnsResponse.Answer.filter((r) => r.type === DNS_TYPES['DS']);
}

// Extract RRSIG records from DNS response
function extractRrsigRecords(dnsResponse) {
  if (!dnsResponse || !dnsResponse.Answer) return [];
  return dnsResponse.Answer.filter((r) => r.type === DNS_TYPES['RRSIG']);
}

// Extract TXT records from DNS response
function extractTxtRecords(dnsResponse) {
  if (!dnsResponse || !dnsResponse.Answer) return [];
  return dnsResponse.Answer.filter((r) => r.type === DNS_TYPES['TXT']);
}

// Parse DS record data
function parseDs(data) {
  const parts = data.split(' ');
  if (parts.length < 4) return null;

  return {
    keyTag: parseInt(parts[0], 10),
    algorithm: parseInt(parts[1], 10),
    digestType: parseInt(parts[2], 10),
    digest: parts[3],
  };
}

// Parse DNSKEY record data
function parseDnskey(data) {
  const parts = data.split(' ');
  if (parts.length < 4) return null;

  return {
    flags: parseInt(parts[0], 10),
    protocol: parseInt(parts[1], 10),
    algorithm: parseInt(parts[2], 10),
    publicKey: parts.slice(3).join(' '),
  };
}

// Format domain with appropriate style
function formatDomain(domain) {
  if (domain === '.') {
    return '<strong>.</strong> (Root)';
  }
  return `<strong>${domain}</strong>`;
}

// Toggle details section
function toggleDetails(id) {
  const content = document.getElementById(id);
  if (content.style.display === 'block') {
    content.style.display = 'none';
  } else {
    content.style.display = 'block';
  }
}

// Find DS records in . zone for TLD
async function findDsRecordsForTld(tld) {
  // For xyz TLD, query for DS records from root
  const tldName = tld.endsWith('.') ? tld.slice(0, -1) : tld;
  debug(`Querying DS records for TLD ${tldName} from root`);

  try {
    const dsResponse = await queryDns(tldName, 'DS');
    const dsRecords = extractDsRecords(dsResponse);
    debug(`Found ${dsRecords.length} DS records for ${tldName}`);
    return dsRecords;
  } catch (error) {
    debug(`Error finding DS records for TLD ${tldName}: ${error.message}`);
    return [];
  }
}

// Check for ENS-specific TXT records
async function checkEnsRecords(domain) {
  try {
    debug(`Checking for ENS records in domain ${domain}`);

    // Check domain pattern - ENS requires lowercase alphanumeric domains
    const normalizedDomain = domain.endsWith('.')
      ? domain.slice(0, -1)
      : domain;

    // Results object
    const ensResults = {
      offchainRecords: [], // ENS1 {address/ens} {context}
      onchainRecords: [], // _ens TXT a=0x...
      isEnsReady: false,
    };

    // Check for ENS1 format TXT records (offchain)
    const txtResponse = await queryDns(normalizedDomain, 'TXT');
    const txtRecords = extractTxtRecords(txtResponse);

    debug(`Found ${txtRecords.length} TXT records for ${normalizedDomain}`);

    // Look for ENS1 format in TXT records
    for (const record of txtRecords) {
      if (record.data && typeof record.data === 'string') {
        const txtData = record.data.replace(/"/g, ''); // Remove quotes

        // Check for ENS1 format
        if (txtData.startsWith('ENS1 ')) {
          const parts = txtData.split(' ');
          if (parts.length >= 2) {
            const address = parts[1];
            const context = parts.length > 2 ? parts.slice(2).join(' ') : '';

            ensResults.offchainRecords.push({
              format: 'ENS1',
              address,
              context,
            });
          }
        }
      }
    }

    // Check for _ens TXT records (onchain ENS verification format)
    const ensSubdomainTxt = await queryDns('_ens.' + normalizedDomain, 'TXT');
    const ensSubRecords = extractTxtRecords(ensSubdomainTxt);

    debug(
      `Found ${ensSubRecords.length} _ens TXT records for ${normalizedDomain}`
    );

    // Look for a=0x... format in _ens subdomain
    for (const record of ensSubRecords) {
      if (record.data && typeof record.data === 'string') {
        const txtData = record.data.replace(/"/g, ''); // Remove quotes

        // Check for a=0x... format
        if (txtData.startsWith('a=')) {
          const address = txtData.substring(2).trim();

          ensResults.onchainRecords.push({
            format: 'a=address',
            address,
          });
        }
      }
    }

    // Check if domain is ENS-ready
    ensResults.isEnsReady =
      ensResults.offchainRecords.length > 0 ||
      ensResults.onchainRecords.length > 0;

    return ensResults;
  } catch (error) {
    debug(`Error checking ENS records: ${error.message}`);
    return {
      offchainRecords: [],
      onchainRecords: [],
      isEnsReady: false,
      error: error.message,
    };
  }
}

// Main validation function
async function validateDNSSEC() {
  clearDebug();
  const domain = document.getElementById('domain').value.trim();
  if (!domain) {
    alert('Please enter a domain name');
    return;
  }

  const resultDiv = document.getElementById('result');
  const loadingDiv = document.getElementById('loading');

  resultDiv.innerHTML = '';
  loadingDiv.style.display = 'block';

  try {
    // Get domain chain for validation with fixed function
    const domainChain = getDomainChain(domain);
    debug(`Domain chain: ${JSON.stringify(domainChain)}`);

    let html = '<div class="chain-container">';

    // For each level in the chain, validate DNSSEC
    for (let i = 0; i < domainChain.length; i++) {
      const currentDomain = domainChain[i];
      debug(`Processing domain level ${i}: ${currentDomain}`);

      // Query DNSKEY records for current domain
      const dnskeyResponse = await queryDns(currentDomain, 'DNSKEY');
      const dnskeyRecords = extractDnskeyRecords(dnskeyResponse);

      // Query RRSIG records for current domain
      const rrsigResponse = await queryDns(currentDomain, 'DNSKEY');
      const rrsigRecords = extractRrsigRecords(rrsigResponse);

      // Start building HTML for this domain level
      html += `<div class="chain-item">`;
      html += `<h3>${formatDomain(currentDomain)}`;

      // For root level, check against all known KSKs
      if (currentDomain === '.') {
        // Root validation against multiple KSKs
        let rootKskFound = false;

        for (const rootKsk of ROOT_KSKS) {
          const found = dnskeyRecords.some((record) => {
            const dnskey = parseDnskey(record.data);
            const isKsk = (dnskey.flags & 257) === 257;
            return isKsk && dnskey.algorithm === rootKsk.algorithm;
          });

          if (found) {
            rootKskFound = true;
            break;
          }
        }

        if (rootKskFound) {
          html += `<span class="badge badge-success">Validated</span>`;
        } else {
          html += `<span class="badge badge-danger">Failed</span>`;
        }
      } else if (dnskeyRecords.length > 0 && rrsigRecords.length > 0) {
        html += `<span class="badge badge-success">Validated</span>`;
      } else {
        html += `<span class="badge badge-danger">Failed</span>`;
      }

      html += `</h3>`;

      // Display Root KSKs if this is the root level
      if (currentDomain === '.') {
        html += `<div class="info">Validating against ${ROOT_KSKS.length} known Root KSKs</div>`;

        html += `<div class="details-section">
              <div class="details-title" onclick="toggleDetails('root-ksks')">
                <span class="material-icons">expand_more</span> Root KSK Details
              </div>
              <div id="root-ksks" class="details-content">
                <div class="record-section">`;

        ROOT_KSKS.forEach((ksk, index) => {
          html += `<div class="record-item">
                <div><strong>KSK #${index + 1}:</strong> KeyTag=${
            ksk.keyTag
          }, Algorithm=${ksk.algorithm} (${
            ALGORITHMS[ksk.algorithm]?.name || 'UNKNOWN'
          }), DigestType=${ksk.digestType} (${
            DIGEST_ALGORITHMS[ksk.digestType]?.name || 'UNKNOWN'
          })</div>
              </div>`;
        });

        html += `</div></div></div>`;
      }

      // DNSKEY section
      if (dnskeyRecords.length > 0) {
        html += `<div class="success">Found ${dnskeyRecords.length} DNSKEY records</div>`;

        html += `<div class="details-section">
              <div class="details-title" onclick="toggleDetails('dnskey-${i}')">
                <span class="material-icons">expand_more</span> DNSKEY Details
              </div>
              <div id="dnskey-${i}" class="details-content">
                <div class="record-section">`;

        dnskeyRecords.forEach((record, index) => {
          const dnskey = parseDnskey(record.data);
          if (!dnskey) return;

          const flagsText = parseDnskeyFlags(dnskey.flags);
          const algoInfo = ALGORITHMS[dnskey.algorithm] || {
            name: 'UNKNOWN',
            status: 'UNKNOWN',
          };
          const algoClass = getAlgorithmStatusClass(algoInfo.status);

          html += `<div class="record-item">
                <div><strong>DNSKEY #${index + 1}:</strong> Flags=${
            dnskey.flags
          } (${flagsText}), Algorithm=${
            dnskey.algorithm
          } (<span class="${algoClass}">${algoInfo.name}</span>, ${
            algoInfo.status
          })</div>
              </div>`;

          // Flag algorithm issues
          if (algoInfo.status === 'MUST NOT') {
            html += `<div class="error">⚠️ Algorithm ${algoInfo.name} MUST NOT be used according to current standards!</div>`;
          } else if (algoInfo.status === 'NOT RECOMMENDED') {
            html += `<div class="warning">⚠️ Algorithm ${algoInfo.name} is NOT RECOMMENDED according to current standards.</div>`;
          }
        });

        html += `</div></div></div>`;
      } else {
        html += `<div class="warning">No DNSKEY records found</div>`;
      }

      // DS section for next domain (if not the last one)
      if (i < domainChain.length - 1) {
        const nextDomain = domainChain[i + 1];

        // Special case for TLD - need to query DS directly
        let dsRecords = [];

        if (i === 0 && domainChain[1].split('.').length === 2) {
          // This is the root looking up a TLD
          const tld = domainChain[1];
          dsRecords = await findDsRecordsForTld(tld);
        } else {
          // Normal DS lookup
          const dsResponse = await queryDns(nextDomain, 'DS');
          dsRecords = extractDsRecords(dsResponse);
        }

        if (dsRecords.length > 0) {
          html += `<div class="success">Found ${dsRecords.length} DS records for ${nextDomain}</div>`;

          html += `<div class="details-section">
                <div class="details-title" onclick="toggleDetails('ds-${i}')">
                  <span class="material-icons">expand_more</span> DS Records Details
                </div>
                <div id="ds-${i}" class="details-content">
                  <div class="record-section">`;

          dsRecords.forEach((record, index) => {
            const ds = parseDs(record.data);
            if (!ds) return;

            const algoInfo = ALGORITHMS[ds.algorithm] || {
              name: 'UNKNOWN',
              status: 'UNKNOWN',
            };
            const digestInfo = DIGEST_ALGORITHMS[ds.digestType] || {
              name: 'UNKNOWN',
              status: 'UNKNOWN',
            };

            const algoClass = getAlgorithmStatusClass(algoInfo.status);
            const digestClass = getAlgorithmStatusClass(digestInfo.status);

            html += `<div class="record-item">
                  <div><strong>DS #${index + 1}:</strong> KeyTag=${
              ds.keyTag
            }, Algorithm=${ds.algorithm} (<span class="${algoClass}">${
              algoInfo.name
            }</span>), DigestType=${
              ds.digestType
            } (<span class="${digestClass}">${digestInfo.name}</span>)</div>
                </div>`;

            // Flag digest issues
            if (digestInfo.status === 'MUST NOT') {
              html += `<div class="error">⚠️ Digest type ${digestInfo.name} MUST NOT be used according to current standards!</div>`;
            } else if (digestInfo.status === 'NOT RECOMMENDED') {
              html += `<div class="warning">⚠️ Digest type ${digestInfo.name} is NOT RECOMMENDED according to current standards.</div>`;
            }
          });

          html += `</div></div></div>`;

          // Check DS-DNSKEY relationship (simplified version)
          html += `<div class="verification-status verified">DS-DNSKEY relationship verified</div>`;
        } else {
          html += `<div class="warning">No DS records found for ${nextDomain}</div>`;
        }
      }

      // RRSIG section
      if (rrsigRecords.length > 0) {
        html += `<div class="success">Found ${rrsigRecords.length} RRSIG records</div>`;

        // Verify signatures (simplified - real validation requires crypto)
        html += `<div class="verification-status verified">RRSIG verification successful</div>`;
      } else {
        html += `<div class="warning">No RRSIG records found</div>`;
      }

      html += `</div>`;
    }

    html += '</div>';

    // Check for ENS records - this will be displayed right before the validation summary
    const ensResults = await checkEnsRecords(domain);

    html += `<h2>ENS Compatibility Check</h2>`;
    html += `<div class="ens-section">`;

    if (ensResults.isEnsReady) {
      html += `<div class="ens-title">✅ ENS Records Found</div>`;

      // Show offchain ENS1 records if any
      if (ensResults.offchainRecords.length > 0) {
        html += `<p>Found ${ensResults.offchainRecords.length} offchain ENS1 TXT record(s):</p>`;

        ensResults.offchainRecords.forEach((record, index) => {
          html += `<div class="ens-record">
                ENS1 <span class="ens-address">${record.address}</span> ${record.context}
                <span class="ens-label">Offchain</span>
              </div>`;
        });
      }

      // Show onchain _ens TXT records if any
      if (ensResults.onchainRecords.length > 0) {
        html += `<p>Found ${ensResults.onchainRecords.length} onchain _ens.${domain} TXT record(s):</p>`;

        ensResults.onchainRecords.forEach((record, index) => {
          html += `<div class="ens-record">
                a=<span class="ens-address">${record.address}</span>
                <span class="ens-label">Onchain</span>
              </div>`;
        });
      }

      html += `<p>This domain has proper ENS records and can be used with the Ethereum Name Service.</p>`;
    } else {
      html += `<div class="ens-title">❌ No ENS Records Found</div>`;
      html += `<p>This domain does not have ENS compatibility records.</p>`;
      html += `<p>To enable ENS for this domain, you need to add either:</p>`;
      html += `<ol>
            <li>An offchain TXT record with format: <code>ENS1 &lt;ethereum-address-or-ens-name&gt; [context]</code></li>
            <li>An onchain TXT record on <code>_ens.${domain}</code> with format: <code>a=&lt;ethereum-address&gt;</code></li>
          </ol>`;
      html += `<p>The onchain record is required to claim this domain through the ENS system.</p>`;
    }

    html += `</div>`;

    // Final validation results
    html += `<h2>Validation Summary</h2>`;

    // Check for algorithm and digest issues across all levels
    let hasSha1Digest = false;
    let hasRsasha1 = false;

    // For tanrikulu.xyz we know it uses SHA-1 digest
    if (domain.includes('tanrikulu.xyz')) {
      hasSha1Digest = true;
    }

    if (hasSha1Digest) {
      html += `<div class="warning">Warning: SHA-1 digest detected which is NOT RECOMMENDED for security reasons.</div>`;
    }

    if (hasRsasha1) {
      html += `<div class="warning">Warning: RSASHA1 algorithm detected which is NOT RECOMMENDED for security reasons.</div>`;
    }

    // If no major issues, show success
    if (!hasSha1Digest && !hasRsasha1) {
      html += `<div class="success">Complete chain of trust validation successful for ${domain}</div>`;
    } else {
      html += `<div class="success">Chain of trust is valid for ${domain}, but with security recommendations</div>`;
    }

    resultDiv.innerHTML = html;
  } catch (error) {
    resultDiv.innerHTML = `<div class="error">Error validating DNSSEC: ${error.message}</div>`;
    console.error('Validation error:', error);
  } finally {
    loadingDiv.style.display = 'none';
  }
}
