import { createContract, encodeDeployData, formatAbi } from 'https://cdn.jsdelivr.net/npm/tevm@1.0.0-next.110/+esm';

export const deployContract = (
  name,
  abi,
  bytecode,
  deployedBytecode,
  address
) => {
  const script = createContract({
    name,
    humanReadableAbi: formatAbi(abi),
    bytecode,
    deployedBytecode,
  }).withAddress(address);

  const callData = encodeDeployData({
    abi: script.abi,
    bytecode: script.bytecode,
    args: [],
  });
  return callData;
};
