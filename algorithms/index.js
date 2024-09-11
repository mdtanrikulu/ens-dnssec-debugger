import jsonRSASHA1Algorithm from './RSASHA1Algorithm.js';
import jsonRSASHA256Algorithm from './RSASHA256Algorithm.js';
import jsonP256SHA256Algorithm from './P256SHA256Algorithm.js';
import { deployContract } from '../utils/deployContract.js';

export const algorithms = [
  {
    id: 5,
    name: 'RSASHA1Algorithm',
    callData: deployContract(
      'RSASHA1Algorithm',
      jsonRSASHA1Algorithm.abi,
      jsonRSASHA1Algorithm.bytecode,
      jsonRSASHA1Algorithm.deployedBytecode,
      jsonRSASHA1Algorithm.address
    ),
  },
  {
    id: 8,
    name: 'RSASHA256Algorithm',
    callData: deployContract(
      'RSASHA256Algorithm',
      jsonRSASHA256Algorithm.abi,
      jsonRSASHA256Algorithm.bytecode,
      jsonRSASHA256Algorithm.deployedBytecode,
      jsonRSASHA256Algorithm.address
    ),
  },
  {
    id: 7,
    name: 'RSASHA1Algorithm',
    callData: deployContract(
      'RSASHA1Algorithm',
      jsonRSASHA1Algorithm.abi,
      jsonRSASHA1Algorithm.bytecode,
      jsonRSASHA1Algorithm.deployedBytecode,
      jsonRSASHA1Algorithm.address
    ),
  },
  {
    id: 13,
    name: 'P256SHA256Algorithm',
    callData: deployContract(
      'P256SHA256Algorithm',
      jsonP256SHA256Algorithm.abi,
      jsonP256SHA256Algorithm.bytecode,
      jsonP256SHA256Algorithm.deployedBytecode,
      jsonP256SHA256Algorithm.address
    ),
  },
];
