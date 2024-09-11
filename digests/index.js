import jsonSHA1Digest from './SHA1Digest.js';
import jsonSHA256Digest from './SHA256Digest.js';
import { deployContract } from '../utils/deployContract.js';

export const digests = [
  {
    id: 1,
    name: 'SHA1Digest',
    callData: deployContract(
      'SHA1Digest',
      jsonSHA1Digest.abi,
      jsonSHA1Digest.bytecode,
      jsonSHA1Digest.deployedBytecode,
      jsonSHA1Digest.address
    ),
  },
  {
    id: 2,
    name: 'SHA256Digest',
    callData: deployContract(
      'SHA256Digest',
      jsonSHA256Digest.abi,
      jsonSHA256Digest.bytecode,
      jsonSHA256Digest.deployedBytecode,
      jsonSHA256Digest.address
    ),
  },
];
