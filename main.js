const enc = new TextEncoder();

class DNSSECDebugger {
  constructor() {
    this.apiEndpoint = 'https://dns.google/resolve';
  }

  async debugDomain(domain) {
    const result = { domain };
    const parentDomain = this.getParentDomain(domain);

    try {
      const dnskey = await this.fetchDNSKEY(domain);
      result.dnssecEnabled = this.checkDNSSECEnabled(dnskey);
      result.dnskeyRecords = this.parseDNSKEY(dnskey);
      console.log('DNSKEY records:', result.dnskeyRecords);

      const ds = await this.fetchDS(parentDomain, domain);
      result.dsRecords = this.parseDS(ds);
      console.log('DS records:', result.dsRecords);
      result.hasMatchingDSandDNSKEY = await this.matchDSandDNSKEY(
        result.dsRecords,
        result.dnskeyRecords,
        domain
      );

      console.log('Fetching RRSIGs...');
      const rrsigData = await this.fetchMultipleRRSIG(domain);
      console.log('Fetched RRSIGs:', rrsigData);

      console.log('Validating RRSIGs...');
      result.rrsigValidation = this.validateRRSIGs(
        rrsigData,
        result.dnskeyRecords
      );
      console.log('RRSIG validation result:', result.rrsigValidation);
      console.log('result.rrsigValidation.noExplicitRRSIGs');

      result.dnssecValidated = result.rrsigValidation.dnssecValidated;
      result.allRRSIGsValid = result.rrsigValidation.noRRSIGs
        ? null
        : Object.values(result.rrsigValidation.results).every((typeRRSIGs) =>
            typeRRSIGs.every((rrsig) => rrsig.isValid)
          );

      // Fetch other record types
      const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT'];
      result.otherRecords = {};

      for (const type of recordTypes) {
        const records = await this.fetchRecord(domain, type);
        result.otherRecords[type] = this.parseRecords(records, type);
      }

      const txt = await this.fetchTXT(domain);
      result.txtRecords = this.parseTXTRecords(txt);
      result.ensRecord = this.checkENSRecords(result.txtRecords);

      return result;
    } catch (error) {
      throw new Error(`Failed to debug domain: ${error.message}`);
    }
  }

  parseRecords(response, type) {
    if (!response.Answer) return [];
    return response.Answer.filter(
      (record) => record.type === this.recordTypeToNumber(type)
    ).map((record) => record.data);
  }

  recordTypeToNumber(type) {
    const types = {
      A: 1,
      NS: 2,
      CNAME: 5,
      SOA: 6,
      MX: 15,
      TXT: 16,
      AAAA: 28,
      RRSIG: 46,
      DNSKEY: 48,
    };
    return types[type] || 0;
  }

  getParentDomain(domain) {
    const parts = domain.split('.');
    return parts.length > 2 ? parts.slice(1).join('.') : domain;
  }

  async fetchRecord(domain, type) {
    const url = `${this.apiEndpoint}?name=${encodeURIComponent(
      domain
    )}&type=${type}&do=true`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  }

  fetchDNSKEY(domain) {
    return this.fetchRecord(domain, 'DNSKEY');
  }

  async fetchDS(parentDomain, domain) {
    try {
      const result = await this.fetchRecord(domain, 'DS');
      if (result.Answer) return result;
      console.log('No DS record found in zone, checking parent zone');
      return this.fetchRecord(parentDomain, 'DS');
    } catch (error) {
      console.error('Error fetching DS record:', error);
      throw error;
    }
  }

  fetchTXT(domain) {
    return this.fetchRecord(domain, 'TXT');
  }

  async fetchMultipleRRSIG(domain) {
    const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'DNSKEY'];
    const results = {};
    let dnssecValidated = false;

    for (const type of recordTypes) {
      try {
        const response = await this.fetchRecord(domain, type);
        console.log(`Fetched ${type} records:`, response);
        if (response.AD === true) {
          dnssecValidated = true;
        }
        if (response.Answer) {
          const rrsigs = response.Answer.filter((record) => record.type === 46);
          if (rrsigs.length > 0) {
            results[type] = rrsigs;
            console.log(`Found ${rrsigs.length} RRSIG(s) for ${type} records`);
          }
        }
      } catch (error) {
        console.error(`Error fetching RRSIG for ${type}:`, error);
      }
    }

    console.log('All RRSIG results:', results);
    return { results, dnssecValidated };
  }

  checkDNSSECEnabled(response) {
    return response.AD === true;
  }

  parseDNSKEY(dnskey) {
    if (!dnskey.Answer) return [];
    return dnskey.Answer.filter((record) => record.type === 48).map(
      (record) => {
        const [flags, protocol, algorithm, publicKey] = record.data.split(' ');
        return {
          flags: parseInt(flags),
          protocol: parseInt(protocol),
          algorithm: parseInt(algorithm),
          publicKey,
          keyTag: this.calculateKeyTag(
            parseInt(flags),
            parseInt(protocol),
            parseInt(algorithm),
            publicKey
          ),
        };
      }
    );
  }

  parseDS(ds) {
    if (!ds.Answer) return [];
    return ds.Answer.filter((record) => record.type === 43).map((record) => {
      const [keyTag, algorithm, digestType, digest] = record.data.split(' ');
      return {
        keyTag: parseInt(keyTag),
        algorithm: parseInt(algorithm),
        digestType: parseInt(digestType),
        digest,
      };
    });
  }

  parseTXTRecords(txt) {
    if (!txt.Answer) return [];
    return txt.Answer.filter((record) => record.type === 16).map(
      (record) => record.data
    );
  }

  checkENSRecords(txtRecords) {
    const ens1Record = txtRecords.find((record) => record.startsWith('ENS1'));
    return ens1Record ? ens1Record : null;
  }

  async calculateDSDigest(dnskey, digestType, domain) {
    const flags = this.numberToBytes(dnskey.flags, 2);
    const protocol = this.numberToBytes(dnskey.protocol, 1);
    const algorithm = this.numberToBytes(dnskey.algorithm, 1);
    const publicKey = this.base64ToBytes(dnskey.publicKey);

    const canonicalName = this.canonicalizeName(domain);
    const rrdata = new Uint8Array([
      ...flags,
      ...protocol,
      ...algorithm,
      ...publicKey,
    ]);
    const toHash = new Uint8Array([...canonicalName, ...rrdata]);

    console.log('Canonical Name:', this.bufferToHex(canonicalName));
    console.log('Flags:', this.bufferToHex(flags));
    console.log('Protocol:', this.bufferToHex(protocol));
    console.log('Algorithm:', this.bufferToHex(algorithm));
    console.log('Public Key:', this.bufferToHex(publicKey));
    console.log('To Hash:', this.bufferToHex(toHash));

    try {
      let digestHex;
      if (digestType === 1) {
        // SHA-1
        digestHex = await this.sha1(toHash);
      } else if (digestType === 2) {
        // SHA-256
        digestHex = await this.sha256(toHash);
      } else {
        console.log('Unsupported digest type:', digestType);
        return '';
      }
      console.log('Calculated Digest:', digestHex);
      return digestHex;
    } catch (error) {
      console.error('Error calculating digest:', error);
      return '';
    }
  }

  numberToBytes(number, byteLength) {
    const result = new Uint8Array(byteLength);
    for (let i = byteLength - 1; i >= 0; i--) {
      result[i] = number & 0xff;
      number >>= 8;
    }
    return result;
  }

  base64ToBytes(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  canonicalizeName(name) {
    const labels = name.toLowerCase().split('.');
    const result = new Uint8Array(name.length + 2);
    let offset = 0;
    for (const label of labels) {
      result[offset] = label.length;
      offset++;
      for (let i = 0; i < label.length; i++) {
        result[offset] = label.charCodeAt(i);
        offset++;
      }
    }
    result[offset] = 0;
    return result;
  }

  bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async sha1(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    return this.bufferToHex(hashBuffer);
  }

  async sha256(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return this.bufferToHex(hashBuffer);
  }

  calculateKeyTag(flags, protocol, algorithm, publicKey) {
    let ac = 0;
    ac += (flags & 0xffff) << 16;
    ac += (protocol & 0xff) << 8;
    ac += algorithm & 0xff;

    const decodedKey = atob(publicKey);
    for (let i = 0; i < decodedKey.length; i++) {
      ac += i & 1 ? decodedKey.charCodeAt(i) : decodedKey.charCodeAt(i) << 8;
    }
    ac += (ac >> 16) & 0xffff;
    return ac & 0xffff;
  }

  async matchDSandDNSKEY(dsRecords, dnskeyRecords, domain) {
    if (dsRecords.length === 0 || dnskeyRecords.length === 0) {
      console.log('No DS or DNSKEY records found');
      return false;
    }
    for (const ds of dsRecords) {
      console.log('Checking DS record:', ds);
      for (const dnskey of dnskeyRecords) {
        console.log('Comparing with DNSKEY:', dnskey);
        const keyTagMatch = ds.keyTag === dnskey.keyTag;
        const algorithmMatch = ds.algorithm === dnskey.algorithm;
        console.log(
          'Key Tag match:',
          keyTagMatch,
          'Algorithm match:',
          algorithmMatch
        );
        if (keyTagMatch && algorithmMatch) {
          const calculatedDigest = await this.calculateDSDigest(
            dnskey,
            ds.digestType,
            domain
          );
          const digestMatch =
            calculatedDigest.toLowerCase() === ds.digest.toLowerCase();
          console.log('Calculated digest:', calculatedDigest);
          console.log('DS digest:', ds.digest);
          console.log('Digest match:', digestMatch);
          if (digestMatch) return true;
        }
      }
    }
    return false;
  }

  validateRRSIGs(rrsigData, dnskeyRecords) {
    console.log('Validating RRSIGs:', rrsigData);

    if (Object.keys(rrsigData.results).length === 0) {
      console.log('No RRSIGs found');
      return {
        noRRSIGs: true,
        dnssecValidated: rrsigData.dnssecValidated,
      };
    }

    const now = Math.floor(Date.now() / 1000);
    const results = {};

    for (const type in rrsigData.results) {
      results[type] = rrsigData.results[type].map((rrsig) => {
        const rrsigData = this.parseRRSIG(rrsig.data);
        const matchingDNSKEY = this.findMatchingDNSKEY(
          dnskeyRecords,
          rrsigData.keyTag
        );
        return {
          covered: rrsigData.typeCovered,
          algorithm: rrsigData.algorithm,
          labels: rrsigData.labels,
          originalTTL: rrsigData.originalTTL,
          expiration: rrsigData.signatureExpiration,
          inception: rrsigData.signatureInception,
          keyTag: rrsigData.keyTag,
          signerName: rrsigData.signerName,
          isExpired: now > rrsigData.signatureExpiration,
          isValid:
            now >= rrsigData.signatureInception &&
            now <= rrsigData.signatureExpiration,
          matchingDNSKEY: matchingDNSKEY !== undefined,
        };
      });
    }

    console.log('RRSIG validation results:', results);
    return { results, dnssecValidated: rrsigData.dnssecValidated };
  }

  parseRRSIG(rrsigString) {
    const [
      typeCovered,
      algorithm,
      labels,
      originalTTL,
      signatureExpiration,
      signatureInception,
      keyTag,
      signerName,
      ...signatureParts
    ] = rrsigString.split(' ');
    return {
      typeCovered,
      algorithm: parseInt(algorithm),
      labels: parseInt(labels),
      originalTTL: parseInt(originalTTL),
      signatureExpiration: parseInt(signatureExpiration),
      signatureInception: parseInt(signatureInception),
      keyTag: parseInt(keyTag),
      signerName,
      signature: signatureParts.join(' '),
    };
  }

  findMatchingDNSKEY(dnskeyRecords, keyTag) {
    return dnskeyRecords.some((dnskey) => dnskey.keyTag === keyTag);
  }
}

const domainInput = document.getElementById('domain-input');
console.log(domainInput);
const debugButton = document.getElementById('debug-button');
const resultDiv = document.getElementById('result');
const progressDiv = document.getElementById('progress');

const dnssecDebugger = new DNSSECDebugger();

const validateDomain = (domain) => {
  const regex = /^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$/;
  return regex.test(domain);
};

const showProgress = () => {
  progressDiv.style.display = 'block';
  resultDiv.innerHTML = '';
};

const hideProgress = () => {
  progressDiv.style.display = 'none';
};

const showResult = (result) => {
  let html = `<h3>DNSSEC Debug Results for ${result.domain}</h3>
      <ul>
        ${createResultItem('DNSSEC Enabled', result.dnssecEnabled)}
        ${createResultItem('DNSSEC Validated', result.dnssecValidated)}
        ${createResultItem('Valid DNSKEY', result.dnskeyRecords.length > 0)}
        ${createResultItem('Valid DS', result.dsRecords.length > 0)}
        ${createResultItem(
          'Matching DS and DNSKEY',
          result.hasMatchingDSandDNSKEY
        )}
        ${
          result.allRRSIGsValid === null
            ? '<li>RRSIGs: Not explicitly returned, but DNSSEC validation performed</li>'
            : createResultItem('All RRSIGs Valid', result.allRRSIGsValid)
        }
        ${createENSResultItem(result.ensRecord)}
      </ul>`;

  html += `<details>
      <summary>Detailed Information</summary>
      <div class="details-content">
        ${createDNSKEYSection(result.dnskeyRecords)}
        ${createDSSection(result.dsRecords)}
        ${createRRSIGSection(result.rrsigValidation)}
        ${createOtherRecordsSection(result.otherRecords)}
      </div>
    </details>`;

  resultDiv.innerHTML = html;
};

const createDNSKEYSection = (dnskeyRecords) => {
  if (!dnskeyRecords || dnskeyRecords.length === 0) return '';
  let html = '<h4>DNSKEY Records:</h4><ul>';
  dnskeyRecords.forEach((dnskey) => {
    html += `<li>Flags: ${dnskey.flags}, Protocol: ${dnskey.protocol}, 
               Algorithm: ${dnskey.algorithm}, Key Tag: ${dnskey.keyTag}</li>`;
  });
  html += '</ul>';
  return html;
};

const createDSSection = (dsRecords) => {
  if (!dsRecords || dsRecords.length === 0) return '';
  let html = '<h4>DS Records:</h4><ul>';
  dsRecords.forEach((ds) => {
    html += `<li>Key Tag: ${ds.keyTag}, Algorithm: ${ds.algorithm}, 
               Digest Type: ${ds.digestType}, Digest: ${ds.digest}</li>`;
  });
  html += '</ul>';
  return html;
};

const createRRSIGSection = (rrsigValidation) => {
  if (!rrsigValidation || rrsigValidation.noRRSIGs) return '';
  let html = '<h4>RRSIG Validation:</h4>';
  for (const type in rrsigValidation.results) {
    html += `<h5>${type} Records:</h5><ul>`;
    rrsigValidation.results[type].forEach((rrsig) => {
      html += `<li>
          Covered: ${rrsig.covered},<br>
          Algorithm: ${rrsig.algorithm},<br>
          Labels: ${rrsig.labels},<br>
          TTL: ${rrsig.originalTTL},<br>
          Expiration: ${new Date(rrsig.expiration * 1000).toUTCString()},<br>
          Inception: ${new Date(rrsig.inception * 1000).toUTCString()},<br>
          Key Tag: ${rrsig.keyTag},<br>
          Signer: ${rrsig.signerName},<br>
          Is Expired: ${rrsig.isExpired ? 'Yes' : 'No'},<br>
          Is Valid: ${rrsig.isValid ? 'Yes' : 'No'},<br>
          Matching DNSKEY: ${rrsig.matchingDNSKEY ? 'Yes' : 'No'}
        </li>`;
    });
    html += '</ul>';
  }
  return html;
};

const createOtherRecordsSection = (otherRecords) => {
  if (!otherRecords) return '';
  let html = '';
  for (const type in otherRecords) {
    html += `<h4>${type} Records:</h4><ul>`;
    otherRecords[type].forEach((record) => {
      html += `<li>${escapeHtml(record)}</li>`;
    });
    html += '</ul>';
  }
  return html;
};

const createResultItem = (label, value) => {
  if (value === null) return '';
  const className = value ? 'success' : 'error';
  return `<li>${label}: <span class="${className}">${
    value ? 'Yes' : 'No'
  }</span></li>`;
};

const createENSResultItem = (ensRecord) => {
  if (ensRecord) {
    return `<li>ENS1 record set: <span class="success">Yes</span>
        <br/>
        <span class="ens-record">( ${ensRecord} )
    </span></li>`;
  } else {
    return '<li><span>ENS1 record set: <span class="error">No</span></span></li>';
  }
};

const showError = (message) => {
  resultDiv.innerHTML = `<p class="error">${message}</p>`;
};

const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

const onDebugButtonClick = async () => {
  const domain = domainInput.value.trim();
  if (!validateDomain(domain)) {
    showError('Please enter a valid domain name (e.g., example.com).');
    return;
  }

  // update the URL without reloading the page
  window.history.pushState({}, '', `/${domain}`);

  showProgress();
  try {
    const result = await dnssecDebugger.debugDomain(domain);
    showResult(result);
  } catch (error) {
    showError(error.message);
  } finally {
    hideProgress();
  }
};

function getDomainFromURL() {
  const path = window.location.pathname;
  if (path.length > 1) {
    return path.substring(1); // remove the leading '/'
  }
  return null;
}

debugButton.addEventListener('click', onDebugButtonClick);

domainInput.addEventListener('keypress', function (event) {
  if (event.key === 'Enter') {
    event.preventDefault(); // prevent the default form submission
    onDebugButtonClick();
  }
});

document.addEventListener('DOMContentLoaded', () => {
  const domain = getDomainFromURL();
  if (domain) {
    domainInput.value = domain;
    onDebugButtonClick();
  }
});
