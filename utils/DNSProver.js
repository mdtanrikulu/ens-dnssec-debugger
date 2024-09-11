import packet from 'https://cdn.jsdelivr.net/npm/dns-packet@5.6.1/+esm'
import packet_types from 'https://cdn.jsdelivr.net/npm/dns-packet@5.6.1/types/+esm'
import { Buffer } from 'https://cdn.jsdelivr.net/npm/buffer@6.0.3/+esm'

export const DEFAULT_TRUST_ANCHORS = [
  {
    name: '.',
    type: 'DS',
    class: 'IN',
    data: {
      keyTag: 19036,
      algorithm: 8,
      digestType: 2,
      digest: Buffer.from(
        '49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5',
        'hex'
      ),
    },
  },
  {
    name: '.',
    type: 'DS',
    class: 'IN',
    data: {
      keyTag: 20326,
      algorithm: 8,
      digestType: 2,
      digest: Buffer.from(
        'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
        'hex'
      ),
    },
  },
];

function encodeURLParams(p) {
  return Object.entries(p)
    .map((kv) => kv.map(encodeURIComponent).join('='))
    .join('&');
}

export function getKeyTag(key) {
  const data = packet.dnskey.encode(key.data).slice(2);
  let keytag = 0;
  for (let i = 0; i < data.length; i++) {
    const v = data[i];
    if ((i & 1) !== 0) {
      keytag += v;
    } else {
      keytag += v << 8;
    }
  }
  keytag += (keytag >> 16) & 0xffff;
  keytag &= 0xffff;
  return keytag;
}

export function answersToString(answers) {
  return answers
    .map((a) => {
      const prefix = `${a.name} ${a.ttl} ${a.class} ${a.type}`;
      const d = a.data;
      switch (a.type) {
        case 'A':
          return `${prefix} ${d}`;
        case 'DNSKEY':
          return `${prefix} ${d.flags} 3 ${d.algorithm} ${d.key.toString(
            'base64'
          )}; keyTag=${getKeyTag(a)}`;
        case 'DS':
          return `${prefix} ${d.keyTag} ${d.algorithm} ${d.digestType} ${d.digest.toString(
            'hex'
          )}`;
        case 'OPT':
          return `${prefix}`;
        case 'RRSIG':
          return `${prefix} ${d.typeCovered} ${d.algorithm} ${d.labels} ${d.originalTTL} ${d.expiration} ${d.inception} ${d.keyTag} ${d.signersName} ${d.signature.toString(
            'base64'
          )}`;
        case 'TXT':
        default:
          return `${prefix} ${d.map((t) => `"${t}"`).join(' ')}`;
      }
    })
    .join('\n');
}

export function dohQuery(url) {
  return async function getDNS(q) {
    const buf = packet.encode(q);
    const response = await fetch(
      `${url}?${encodeURLParams({
        ct: 'application/dns-udpwireformat',
        dns: buf.toString('base64'),
        ts: Date.now().toString(),
      })}`
    );
    return packet.decode(Buffer.from(await response.arrayBuffer()));
  };
}

export class SignedSet {
  constructor(records, signature) {
    this.records = records;
    this.signature = signature;
  }

  static fromWire(data, signatureData) {
    const { rdata, length } = this.readRrsigRdata(data);
    rdata.signature = signatureData;

    const rrs = [];
    let off = length;
    while (off < data.length) {
      rrs.push(packet.answer.decode(data, off));
      off += packet.answer.decode.bytes;
    }

    return new SignedSet(rrs, {
      name: rrs[0].name,
      type: 'RRSIG',
      class: rrs[0].class,
      data: rdata,
    });
  }

  static readRrsigRdata(data) {
    return {
      rdata: {
        typeCovered: packet_types.toString(data.readUInt16BE(0)),
        algorithm: data.readUInt8(2),
        labels: data.readUInt8(3),
        originalTTL: data.readUInt32BE(4),
        expiration: data.readUInt32BE(8),
        inception: data.readUInt32BE(12),
        keyTag: data.readUInt16BE(16),
        signersName: packet.name.decode(data, 18),
        signature: Buffer.of(),
      },
      length: 18 + packet.name.decode.bytes,
    };
  }

  toWire(withRrsig = true) {
    const rrset = Buffer.concat(
      this.records
        .sort((a, b) => {
          const aenc = packet.record(a.type).encode(a.data).slice(2);
          const benc = packet.record(b.type).encode(b.data).slice(2);
          return aenc.compare(benc);
        })
        .map((r) =>
          packet.answer.encode(
            Object.assign(r, {
              name: r.name.toLowerCase(),
              ttl: this.signature.data.originalTTL,
            })
          )
        )
    );
    if (withRrsig) {
      const rrsig = packet.rrsig
        .encode({ ...this.signature.data, signature: Buffer.of() })
        .slice(2);
      return Buffer.concat([rrsig, rrset]);
    }
    return rrset;
  }
}

export const DEFAULT_DIGESTS = {
  1: {
    name: 'SHA1',
    f: () => true,
  },
  2: {
    name: 'SHA256',
    f: async (data, digest) => {
      const hash = await crypto.subtle.digest('SHA-256', data);
      return Buffer.from(hash).equals(digest);
    },
  },
};

export const DEFAULT_ALGORITHMS = {
  5: {
    name: 'RSASHA1Algorithm',
    f: () => true,
  },
  7: {
    name: 'RSASHA1Algorithm',
    f: () => true,
  },
  8: {
    name: 'RSASHA256',
    f: () => true,
  },
  13: {
    name: 'P256SHA256',
    f: () => true,
  },
};

function isTypedArray(array) {
  return array.every((a) => a.type === 'DNSKEY');
}

function makeIndex(values, fn) {
  const ret = {};
  for (const value of values) {
    const key = fn(value);
    let list = ret[key];
    if (list === undefined) {
      list = [];
      ret[key] = list;
    }
    list.push(value);
  }
  return ret;
}

export class DNSQuery {
  constructor(prover) {
    this.prover = prover;
    this.cache = {};
  }

  async queryWithProof(qtype, qname) {
    const response = await this.dnsQuery(qtype.toString(), qname);
    const answers = response.answers.filter(
      (r) => r.type === qtype && r.name === qname
    );
    console.log(`Found ${answers.length} ${qtype} records for ${qname}`);
    if (answers.length === 0) {
      return null;
    }

    const sigs = response.answers.filter(
      (r) => r.type === 'RRSIG' && r.name === qname && r.data.typeCovered === qtype
    );
    console.log(`Found ${sigs.length} RRSIGs over ${qtype} RRSET`);

    if (isTypedArray(answers) && sigs.some((sig) => sig.name === sig.data.signersName)) {
      console.log(
        `DNSKEY RRSET on ${answers[0].name} is self-signed; attempting to verify with a DS in parent zone`
      );
      return this.verifyWithDS(answers, sigs);
    }
    return this.verifyRRSet(answers, sigs);
  }

  async verifyRRSet(answers, sigs) {
    for (const sig of sigs) {
      const { algorithms } = this.prover;
      console.log(
        `Attempting to verify the ${answers[0].type} RRSET on ${
          answers[0].name
        } with RRSIG=${sig.data.keyTag}/${
          algorithms[sig.data.algorithm]?.name || sig.data.algorithm
        }`
      );
      const ss = new SignedSet(answers, sig);

      if (!(sig.data.algorithm in algorithms)) {
        console.log(
          `Skipping RRSIG=${sig.data.keyTag}/${sig.data.algorithm} on ${answers[0].type} RRSET for ${answers[0].name}: Unknown algorithm`
        );
        continue;
      }

      const result = await this.queryWithProof('DNSKEY', sig.data.signersName);
      if (result === null) {
        throw new NoValidDnskeyError(answers);
      }
      const { answer, proofs } = result;
      for (const key of answer.records) {
        if (this.verifySignature(ss, key)) {
          console.log(
            `RRSIG=${sig.data.keyTag}/${
              algorithms[sig.data.algorithm].name
            } verifies the ${answers[0].type} RRSET on ${answers[0].name}`
          );
          proofs.push(answer);
          return { answer: ss, proofs };
        }
      }
    }
    console.warn(
      `Could not verify the ${answers[0].type} RRSET on ${answers[0].name} with any RRSIGs`
    );
    throw new NoValidDnskeyError(answers);
  }

  async verifyWithDS(keys, sigs) {
    const keyname = keys[0].name;

    let answer;
    let proofs;
    if (keyname === '.') {
      [answer, proofs] = [this.prover.anchors, []];
    } else {
      const response = await this.queryWithProof('DS', keyname);
      if (response === null) {
        throw new NoValidDsError(keys);
      }
      answer = response.answer.records;
      proofs = response.proofs;
      proofs.push(response.answer);
    }

    const keysByTag = makeIndex(keys, getKeyTag);
    const sigsByTag = makeIndex(sigs, (sig) => sig.data.keyTag);

    const { algorithms } = this.prover;
    const { digests } = this.prover;
    for (const ds of answer) {
      for (const key of keysByTag[ds.data.keyTag] || []) {
        if (this.checkDs(ds, key)) {
          console.log(
            `DS=${ds.data.keyTag}/${
              algorithms[ds.data.algorithm]?.name || ds.data.algorithm
            }/${digests[ds.data.digestType].name} verifies DNSKEY=${
              ds.data.keyTag
            }/${
              algorithms[key.data.algorithm]?.name || key.data.algorithm
            } on ${key.name}`
          );
          for (const sig of sigsByTag[ds.data.keyTag] || []) {
            const ss = new SignedSet(keys, sig);
            if (this.verifySignature(ss, key)) {
              console.log(
                `RRSIG=${sig.data.keyTag}/${
                  algorithms[sig.data.algorithm].name
                } verifies the DNSKEY RRSET on ${keys[0].name}`
              );
              return { answer: ss, proofs };
            }
          }
        }
      }
    }

    console.warn(
      `Could not find any DS records to verify the DNSKEY RRSET on ${keys[0].name}`
    );
    throw new NoValidDsError(keys);
  }

  verifySignature(answer, key) {
    const keyTag = getKeyTag(key);
    if (
      key.data.algorithm !== answer.signature.data.algorithm ||
      keyTag !== answer.signature.data.keyTag ||
      key.name !== answer.signature.data.signersName
    ) {
      return false;
    }
    const signatureAlgorithm = this.prover.algorithms[key.data.algorithm];
    if (signatureAlgorithm === undefined) {
      console.warn(
        `Unrecognised signature algorithm for DNSKEY=${keyTag}/${key.data.algorithm} on ${key.name}`
      );
      return false;
    }
    return signatureAlgorithm.f(
      key.data.key,
      answer.toWire(),
      answer.signature.data.signature
    );
  }

  checkDs(ds, key) {
    if (key.data.algorithm !== ds.data.algorithm || key.name !== ds.name) {
      return false;
    }
    const data = Buffer.concat([
      packet.name.encode(ds.name),
      packet.dnskey.encode(key.data).slice(2),
    ]);
    const digestAlgorithm = this.prover.digests[ds.data.digestType];
    if (digestAlgorithm === undefined) {
      console.warn(
        `Unrecognised digest type for DS=${ds.data.keyTag}/${
          ds.data.digestType
        }/${
          this.prover.algorithms[ds.data.algorithm]?.name || ds.data.algorithm
        } on ${ds.name}`
      );
      return false;
    }
    return digestAlgorithm.f(data, ds.data.digest);
  }

  async dnsQuery(qtype, qname) {
    const query = {
      type: 'query',
      id: 1,
      flags: packet.RECURSION_DESIRED,
      questions: [
        {
          type: qtype,
          class: 'IN',
          name: qname,
        },
      ],
      additionals: [
        {
          type: 'OPT',
          class: 'IN',
          name: '.',
          udpPayloadSize: 4096,
          flags: packet.DNSSEC_OK,
        },
      ],
      answers: [],
    };
    if (this.cache[qname]?.[qtype] === undefined) {
      if (this.cache[qname] === undefined) {
        this.cache[qname] = {};
      }
      this.cache[qname][qtype] = await this.prover.sendQuery(query);
    }
    const response = this.cache[qname][qtype];
    console.log(
      `Query[${qname} ${qtype}]:\n${answersToString(response.answers)}`
    );
    if (response.rcode !== 'NOERROR') {
      throw new ResponseCodeError(query, response);
    }
    return response;
  }
}

export class DNSProver {
  constructor(
    sendQuery,
    digests = DEFAULT_DIGESTS,
    algorithms = DEFAULT_ALGORITHMS,
    anchors = DEFAULT_TRUST_ANCHORS
  ) {
    this.sendQuery = sendQuery;
    this.digests = digests;
    this.algorithms = algorithms;
    this.anchors = anchors;
  }

  async queryWithProof(qtype, qname) {
    return new DNSQuery(this).queryWithProof(qtype, qname);
  }

  static create(url) {
    return new DNSProver(dohQuery(url));
  }
}

export class ResponseCodeError extends Error {
  constructor(query, response) {
    super(`DNS server responded with ${response.rcode}`);
    this.name = 'ResponseError';
    this.query = query;
    this.response = response;
  }
}

export class NoValidDsError extends Error {
  constructor(keys) {
    super(`Could not find a DS record to validate any RRSIG on DNSKEY records for ${keys[0].name}`);
    this.keys = keys;
    this.name = 'NoValidDsError';
  }
}

export class NoValidDnskeyError extends Error {
  constructor(result) {
    super(`Could not find a DNSKEY record to validate any RRSIG on ${result[0].type} records for ${result[0].name}`);
    this.result = result;
    this.name = 'NoValidDnskeyError';
  }
}
