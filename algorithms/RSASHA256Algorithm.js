export default {
    "address": "0x9D1B5a639597f558bC37Cf81813724076c5C1e96",
    "abi": [
      {
        "inputs": [
          {
            "internalType": "bytes",
            "name": "key",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "data",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "sig",
            "type": "bytes"
          }
        ],
        "name": "verify",
        "outputs": [
          {
            "internalType": "bool",
            "name": "",
            "type": "bool"
          }
        ],
        "stateMutability": "view",
        "type": "function"
      }
    ],
    "transactionHash": "0x3bfc4088c954a7fd47fc5bc40fb0affdb5ca8369229e307e12019da09cee3665",
    "receipt": {
      "to": null,
      "from": "0x0904Dac3347eA47d208F3Fd67402D039a3b99859",
      "contractAddress": "0x9D1B5a639597f558bC37Cf81813724076c5C1e96",
      "transactionIndex": 33,
      "gasUsed": "448967",
      "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "blockHash": "0x386dd045029097dd9139f841cbf593572c54b455e846186854148c9fe4db391f",
      "transactionHash": "0x3bfc4088c954a7fd47fc5bc40fb0affdb5ca8369229e307e12019da09cee3665",
      "logs": [],
      "blockNumber": 19020682,
      "cumulativeGasUsed": "3660506",
      "status": 1,
      "byzantium": true
    },
    "args": [],
    "numDeployments": 2,
    "solcInputHash": "dd9e022689821cffaeb04b9ddbda87ae",
    "metadata": "{\"compiler\":{\"version\":\"0.8.17+commit.8df45f5f\"},\"language\":\"Solidity\",\"output\":{\"abi\":[{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"key\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"sig\",\"type\":\"bytes\"}],\"name\":\"verify\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}],\"devdoc\":{\"details\":\"Implements the DNSSEC RSASHA256 algorithm.\",\"kind\":\"dev\",\"methods\":{},\"version\":1},\"userdoc\":{\"kind\":\"user\",\"methods\":{},\"version\":1}},\"settings\":{\"compilationTarget\":{\"contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol\":\"RSASHA256Algorithm\"},\"evmVersion\":\"london\",\"libraries\":{},\"metadata\":{\"bytecodeHash\":\"ipfs\",\"useLiteralContent\":true},\"optimizer\":{\"enabled\":true,\"runs\":1200},\"remappings\":[]},\"sources\":{\"contracts/dnssec-oracle/BytesUtils.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\nlibrary BytesUtils {\\n    error OffsetOutOfBoundsError(uint256 offset, uint256 length);\\n\\n    /*\\n     * @dev Returns the keccak-256 hash of a byte range.\\n     * @param self The byte string to hash.\\n     * @param offset The position to start hashing at.\\n     * @param len The number of bytes to hash.\\n     * @return The hash of the byte range.\\n     */\\n    function keccak(\\n        bytes memory self,\\n        uint256 offset,\\n        uint256 len\\n    ) internal pure returns (bytes32 ret) {\\n        require(offset + len <= self.length);\\n        assembly {\\n            ret := keccak256(add(add(self, 32), offset), len)\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns a positive number if `other` comes lexicographically after\\n     *      `self`, a negative number if it comes before, or zero if the\\n     *      contents of the two bytes are equal.\\n     * @param self The first bytes to compare.\\n     * @param other The second bytes to compare.\\n     * @return The result of the comparison.\\n     */\\n    function compare(\\n        bytes memory self,\\n        bytes memory other\\n    ) internal pure returns (int256) {\\n        return compare(self, 0, self.length, other, 0, other.length);\\n    }\\n\\n    /*\\n     * @dev Returns a positive number if `other` comes lexicographically after\\n     *      `self`, a negative number if it comes before, or zero if the\\n     *      contents of the two bytes are equal. Comparison is done per-rune,\\n     *      on unicode codepoints.\\n     * @param self The first bytes to compare.\\n     * @param offset The offset of self.\\n     * @param len    The length of self.\\n     * @param other The second bytes to compare.\\n     * @param otheroffset The offset of the other string.\\n     * @param otherlen    The length of the other string.\\n     * @return The result of the comparison.\\n     */\\n    function compare(\\n        bytes memory self,\\n        uint256 offset,\\n        uint256 len,\\n        bytes memory other,\\n        uint256 otheroffset,\\n        uint256 otherlen\\n    ) internal pure returns (int256) {\\n        if (offset + len > self.length) {\\n            revert OffsetOutOfBoundsError(offset + len, self.length);\\n        }\\n        if (otheroffset + otherlen > other.length) {\\n            revert OffsetOutOfBoundsError(otheroffset + otherlen, other.length);\\n        }\\n\\n        uint256 shortest = len;\\n        if (otherlen < len) shortest = otherlen;\\n\\n        uint256 selfptr;\\n        uint256 otherptr;\\n\\n        assembly {\\n            selfptr := add(self, add(offset, 32))\\n            otherptr := add(other, add(otheroffset, 32))\\n        }\\n        for (uint256 idx = 0; idx < shortest; idx += 32) {\\n            uint256 a;\\n            uint256 b;\\n            assembly {\\n                a := mload(selfptr)\\n                b := mload(otherptr)\\n            }\\n            if (a != b) {\\n                // Mask out irrelevant bytes and check again\\n                uint256 mask;\\n                if (shortest - idx >= 32) {\\n                    mask = type(uint256).max;\\n                } else {\\n                    mask = ~(2 ** (8 * (idx + 32 - shortest)) - 1);\\n                }\\n                int256 diff = int256(a & mask) - int256(b & mask);\\n                if (diff != 0) return diff;\\n            }\\n            selfptr += 32;\\n            otherptr += 32;\\n        }\\n\\n        return int256(len) - int256(otherlen);\\n    }\\n\\n    /*\\n     * @dev Returns true if the two byte ranges are equal.\\n     * @param self The first byte range to compare.\\n     * @param offset The offset into the first byte range.\\n     * @param other The second byte range to compare.\\n     * @param otherOffset The offset into the second byte range.\\n     * @param len The number of bytes to compare\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        uint256 offset,\\n        bytes memory other,\\n        uint256 otherOffset,\\n        uint256 len\\n    ) internal pure returns (bool) {\\n        return keccak(self, offset, len) == keccak(other, otherOffset, len);\\n    }\\n\\n    /*\\n     * @dev Returns true if the two byte ranges are equal with offsets.\\n     * @param self The first byte range to compare.\\n     * @param offset The offset into the first byte range.\\n     * @param other The second byte range to compare.\\n     * @param otherOffset The offset into the second byte range.\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        uint256 offset,\\n        bytes memory other,\\n        uint256 otherOffset\\n    ) internal pure returns (bool) {\\n        return\\n            keccak(self, offset, self.length - offset) ==\\n            keccak(other, otherOffset, other.length - otherOffset);\\n    }\\n\\n    /*\\n     * @dev Compares a range of 'self' to all of 'other' and returns True iff\\n     *      they are equal.\\n     * @param self The first byte range to compare.\\n     * @param offset The offset into the first byte range.\\n     * @param other The second byte range to compare.\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        uint256 offset,\\n        bytes memory other\\n    ) internal pure returns (bool) {\\n        return\\n            self.length == offset + other.length &&\\n            equals(self, offset, other, 0, other.length);\\n    }\\n\\n    /*\\n     * @dev Returns true if the two byte ranges are equal.\\n     * @param self The first byte range to compare.\\n     * @param other The second byte range to compare.\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        bytes memory other\\n    ) internal pure returns (bool) {\\n        return\\n            self.length == other.length &&\\n            equals(self, 0, other, 0, self.length);\\n    }\\n\\n    /*\\n     * @dev Returns the 8-bit number at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 8 bits of the string, interpreted as an integer.\\n     */\\n    function readUint8(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (uint8 ret) {\\n        return uint8(self[idx]);\\n    }\\n\\n    /*\\n     * @dev Returns the 16-bit number at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 16 bits of the string, interpreted as an integer.\\n     */\\n    function readUint16(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (uint16 ret) {\\n        require(idx + 2 <= self.length);\\n        assembly {\\n            ret := and(mload(add(add(self, 2), idx)), 0xFFFF)\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the 32-bit number at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 32 bits of the string, interpreted as an integer.\\n     */\\n    function readUint32(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (uint32 ret) {\\n        require(idx + 4 <= self.length);\\n        assembly {\\n            ret := and(mload(add(add(self, 4), idx)), 0xFFFFFFFF)\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the 32 byte value at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 32 bytes of the string.\\n     */\\n    function readBytes32(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (bytes32 ret) {\\n        require(idx + 32 <= self.length);\\n        assembly {\\n            ret := mload(add(add(self, 32), idx))\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the 32 byte value at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 32 bytes of the string.\\n     */\\n    function readBytes20(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (bytes20 ret) {\\n        require(idx + 20 <= self.length);\\n        assembly {\\n            ret := and(\\n                mload(add(add(self, 32), idx)),\\n                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000\\n            )\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the n byte value at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes.\\n     * @param len The number of bytes.\\n     * @return The specified 32 bytes of the string.\\n     */\\n    function readBytesN(\\n        bytes memory self,\\n        uint256 idx,\\n        uint256 len\\n    ) internal pure returns (bytes32 ret) {\\n        require(len <= 32);\\n        require(idx + len <= self.length);\\n        assembly {\\n            let mask := not(sub(exp(256, sub(32, len)), 1))\\n            ret := and(mload(add(add(self, 32), idx)), mask)\\n        }\\n    }\\n\\n    function memcpy(uint256 dest, uint256 src, uint256 len) private pure {\\n        // Copy word-length chunks while possible\\n        for (; len >= 32; len -= 32) {\\n            assembly {\\n                mstore(dest, mload(src))\\n            }\\n            dest += 32;\\n            src += 32;\\n        }\\n\\n        // Copy remaining bytes\\n        unchecked {\\n            uint256 mask = (256 ** (32 - len)) - 1;\\n            assembly {\\n                let srcpart := and(mload(src), not(mask))\\n                let destpart := and(mload(dest), mask)\\n                mstore(dest, or(destpart, srcpart))\\n            }\\n        }\\n    }\\n\\n    /*\\n     * @dev Copies a substring into a new byte string.\\n     * @param self The byte string to copy from.\\n     * @param offset The offset to start copying at.\\n     * @param len The number of bytes to copy.\\n     */\\n    function substring(\\n        bytes memory self,\\n        uint256 offset,\\n        uint256 len\\n    ) internal pure returns (bytes memory) {\\n        require(offset + len <= self.length);\\n\\n        bytes memory ret = new bytes(len);\\n        uint256 dest;\\n        uint256 src;\\n\\n        assembly {\\n            dest := add(ret, 32)\\n            src := add(add(self, 32), offset)\\n        }\\n        memcpy(dest, src, len);\\n\\n        return ret;\\n    }\\n\\n    // Maps characters from 0x30 to 0x7A to their base32 values.\\n    // 0xFF represents invalid characters in that range.\\n    bytes constant base32HexTable =\\n        hex\\\"00010203040506070809FFFFFFFFFFFFFF0A0B0C0D0E0F101112131415161718191A1B1C1D1E1FFFFFFFFFFFFFFFFFFFFF0A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\\\";\\n\\n    /**\\n     * @dev Decodes unpadded base32 data of up to one word in length.\\n     * @param self The data to decode.\\n     * @param off Offset into the string to start at.\\n     * @param len Number of characters to decode.\\n     * @return The decoded data, left aligned.\\n     */\\n    function base32HexDecodeWord(\\n        bytes memory self,\\n        uint256 off,\\n        uint256 len\\n    ) internal pure returns (bytes32) {\\n        require(len <= 52);\\n\\n        uint256 ret = 0;\\n        uint8 decoded;\\n        for (uint256 i = 0; i < len; i++) {\\n            bytes1 char = self[off + i];\\n            require(char >= 0x30 && char <= 0x7A);\\n            decoded = uint8(base32HexTable[uint256(uint8(char)) - 0x30]);\\n            require(decoded <= 0x20);\\n            if (i == len - 1) {\\n                break;\\n            }\\n            ret = (ret << 5) | decoded;\\n        }\\n\\n        uint256 bitlen = len * 5;\\n        if (len % 8 == 0) {\\n            // Multiple of 8 characters, no padding\\n            ret = (ret << 5) | decoded;\\n        } else if (len % 8 == 2) {\\n            // Two extra characters - 1 byte\\n            ret = (ret << 3) | (decoded >> 2);\\n            bitlen -= 2;\\n        } else if (len % 8 == 4) {\\n            // Four extra characters - 2 bytes\\n            ret = (ret << 1) | (decoded >> 4);\\n            bitlen -= 4;\\n        } else if (len % 8 == 5) {\\n            // Five extra characters - 3 bytes\\n            ret = (ret << 4) | (decoded >> 1);\\n            bitlen -= 1;\\n        } else if (len % 8 == 7) {\\n            // Seven extra characters - 4 bytes\\n            ret = (ret << 2) | (decoded >> 3);\\n            bitlen -= 3;\\n        } else {\\n            revert();\\n        }\\n\\n        return bytes32(ret << (256 - bitlen));\\n    }\\n\\n    /**\\n     * @dev Finds the first occurrence of the byte `needle` in `self`.\\n     * @param self The string to search\\n     * @param off The offset to start searching at\\n     * @param len The number of bytes to search\\n     * @param needle The byte to search for\\n     * @return The offset of `needle` in `self`, or 2**256-1 if it was not found.\\n     */\\n    function find(\\n        bytes memory self,\\n        uint256 off,\\n        uint256 len,\\n        bytes1 needle\\n    ) internal pure returns (uint256) {\\n        for (uint256 idx = off; idx < off + len; idx++) {\\n            if (self[idx] == needle) {\\n                return idx;\\n            }\\n        }\\n        return type(uint256).max;\\n    }\\n}\\n\",\"keccak256\":\"0x4f10902639b85a17ae10745264feff322e793bfb1bc130a9a90efa7dda47c6cc\"},\"contracts/dnssec-oracle/algorithms/Algorithm.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\n/**\\n * @dev An interface for contracts implementing a DNSSEC (signing) algorithm.\\n */\\ninterface Algorithm {\\n    /**\\n     * @dev Verifies a signature.\\n     * @param key The public key to verify with.\\n     * @param data The signed data to verify.\\n     * @param signature The signature to verify.\\n     * @return True iff the signature is valid.\\n     */\\n    function verify(\\n        bytes calldata key,\\n        bytes calldata data,\\n        bytes calldata signature\\n    ) external view virtual returns (bool);\\n}\\n\",\"keccak256\":\"0xaf6825f9852c69f8e36540821d067b4550dd2263497af9d645309b6a0c457ba6\"},\"contracts/dnssec-oracle/algorithms/ModexpPrecompile.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\nlibrary ModexpPrecompile {\\n    /**\\n     * @dev Computes (base ^ exponent) % modulus over big numbers.\\n     */\\n    function modexp(\\n        bytes memory base,\\n        bytes memory exponent,\\n        bytes memory modulus\\n    ) internal view returns (bool success, bytes memory output) {\\n        bytes memory input = abi.encodePacked(\\n            uint256(base.length),\\n            uint256(exponent.length),\\n            uint256(modulus.length),\\n            base,\\n            exponent,\\n            modulus\\n        );\\n\\n        output = new bytes(modulus.length);\\n\\n        assembly {\\n            success := staticcall(\\n                gas(),\\n                5,\\n                add(input, 32),\\n                mload(input),\\n                add(output, 32),\\n                mload(modulus)\\n            )\\n        }\\n    }\\n}\\n\",\"keccak256\":\"0xb3d46284534eb99061d4c79968c2d0420b63a6649d118ef2ea3608396b85de3f\"},\"contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\nimport \\\"./Algorithm.sol\\\";\\nimport \\\"../BytesUtils.sol\\\";\\nimport \\\"./RSAVerify.sol\\\";\\n\\n/**\\n * @dev Implements the DNSSEC RSASHA256 algorithm.\\n */\\ncontract RSASHA256Algorithm is Algorithm {\\n    using BytesUtils for *;\\n\\n    function verify(\\n        bytes calldata key,\\n        bytes calldata data,\\n        bytes calldata sig\\n    ) external view override returns (bool) {\\n        bytes memory exponent;\\n        bytes memory modulus;\\n\\n        uint16 exponentLen = uint16(key.readUint8(4));\\n        if (exponentLen != 0) {\\n            exponent = key.substring(5, exponentLen);\\n            modulus = key.substring(\\n                exponentLen + 5,\\n                key.length - exponentLen - 5\\n            );\\n        } else {\\n            exponentLen = key.readUint16(5);\\n            exponent = key.substring(7, exponentLen);\\n            modulus = key.substring(\\n                exponentLen + 7,\\n                key.length - exponentLen - 7\\n            );\\n        }\\n\\n        // Recover the message from the signature\\n        bool ok;\\n        bytes memory result;\\n        (ok, result) = RSAVerify.rsarecover(modulus, exponent, sig);\\n\\n        // Verify it ends with the hash of our data\\n        return ok && sha256(data) == result.readBytes32(result.length - 32);\\n    }\\n}\\n\",\"keccak256\":\"0x1d6ba44f41e957f9c53e6e5b88150cbb6c9f46e9da196502984ee0a53e9ac5a9\"},\"contracts/dnssec-oracle/algorithms/RSAVerify.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\nimport \\\"../BytesUtils.sol\\\";\\nimport \\\"./ModexpPrecompile.sol\\\";\\n\\nlibrary RSAVerify {\\n    /**\\n     * @dev Recovers the input data from an RSA signature, returning the result in S.\\n     * @param N The RSA public modulus.\\n     * @param E The RSA public exponent.\\n     * @param S The signature to recover.\\n     * @return True if the recovery succeeded.\\n     */\\n    function rsarecover(\\n        bytes memory N,\\n        bytes memory E,\\n        bytes memory S\\n    ) internal view returns (bool, bytes memory) {\\n        return ModexpPrecompile.modexp(S, E, N);\\n    }\\n}\\n\",\"keccak256\":\"0xb386daa80070f79399a2cb97a534f31660161ccd50662fabcf63e26cce064506\"}},\"version\":1}",
    "bytecode": "0x608060405234801561001057600080fd5b50610728806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063de8f50a114610030575b600080fd5b61004361003e366004610539565b610057565b604051901515815260200160405180910390f35b600060608060006100a260048b8b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092939250506102f59050565b60ff169050801561016e576100f760058261ffff168c8c8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092949392505061031a9050565b92506101676101078260056105e9565b61ffff9081169060059061011d9085168d61060b565b610127919061060b565b8c8c8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092949392505061031a9050565b9150610227565b6101b260058b8b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929392505061039c9050565b90506101fe60078261ffff168c8c8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092949392505061031a9050565b925061022461020e8260076105e9565b61ffff9081169060079061011d9085168d61060b565b91505b6000606061026c84868a8a8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506103c492505050565b90925090508180156102e557506102916020825161028a919061060b565b82906103df565b60028b8b6040516102a392919061061e565b602060405180830381855afa1580156102c0573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906102e3919061062e565b145b9c9b505050505050505050505050565b600082828151811061030957610309610647565b016020015160f81c90505b92915050565b8251606090610329838561065d565b111561033457600080fd5b60008267ffffffffffffffff81111561034f5761034f610670565b6040519080825280601f01601f191660200182016040528015610379576020820181803683370190505b50905060208082019086860101610391828287610403565b509095945050505050565b81516000906103ac83600261065d565b11156103b757600080fd5b50016002015161ffff1690565b600060606103d3838587610459565b91509150935093915050565b81516000906103ef83602061065d565b11156103fa57600080fd5b50016020015190565b6020811061043b578151835261041a60208461065d565b925061042760208361065d565b915061043460208261060b565b9050610403565b905182516020929092036101000a6000190180199091169116179052565b60006060600085518551855188888860405160200161047d969594939291906106b6565b6040516020818303038152906040529050835167ffffffffffffffff8111156104a8576104a8610670565b6040519080825280601f01601f1916602001820160405280156104d2576020820181803683370190505b50915083516020830182516020840160055afa925050935093915050565b60008083601f84011261050257600080fd5b50813567ffffffffffffffff81111561051a57600080fd5b60208301915083602082850101111561053257600080fd5b9250929050565b6000806000806000806060878903121561055257600080fd5b863567ffffffffffffffff8082111561056a57600080fd5b6105768a838b016104f0565b9098509650602089013591508082111561058f57600080fd5b61059b8a838b016104f0565b909650945060408901359150808211156105b457600080fd5b506105c189828a016104f0565b979a9699509497509295939492505050565b634e487b7160e01b600052601160045260246000fd5b61ffff818116838216019080821115610604576106046105d3565b5092915050565b81810381811115610314576103146105d3565b8183823760009101908152919050565b60006020828403121561064057600080fd5b5051919050565b634e487b7160e01b600052603260045260246000fd5b80820180821115610314576103146105d3565b634e487b7160e01b600052604160045260246000fd5b6000815160005b818110156106a7576020818501810151868301520161068d565b50600093019283525090919050565b86815285602082015284604082015260006106e66106e06106da6060850188610686565b86610686565b84610686565b9897505050505050505056fea264697066735822122081d54f6872821586c976d8d9aa106e2ea811afa445a713b0da099f753dd8e48364736f6c63430008110033",
    "deployedBytecode": "0x608060405234801561001057600080fd5b506004361061002b5760003560e01c8063de8f50a114610030575b600080fd5b61004361003e366004610539565b610057565b604051901515815260200160405180910390f35b600060608060006100a260048b8b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092939250506102f59050565b60ff169050801561016e576100f760058261ffff168c8c8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092949392505061031a9050565b92506101676101078260056105e9565b61ffff9081169060059061011d9085168d61060b565b610127919061060b565b8c8c8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092949392505061031a9050565b9150610227565b6101b260058b8b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929392505061039c9050565b90506101fe60078261ffff168c8c8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092949392505061031a9050565b925061022461020e8260076105e9565b61ffff9081169060079061011d9085168d61060b565b91505b6000606061026c84868a8a8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506103c492505050565b90925090508180156102e557506102916020825161028a919061060b565b82906103df565b60028b8b6040516102a392919061061e565b602060405180830381855afa1580156102c0573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906102e3919061062e565b145b9c9b505050505050505050505050565b600082828151811061030957610309610647565b016020015160f81c90505b92915050565b8251606090610329838561065d565b111561033457600080fd5b60008267ffffffffffffffff81111561034f5761034f610670565b6040519080825280601f01601f191660200182016040528015610379576020820181803683370190505b50905060208082019086860101610391828287610403565b509095945050505050565b81516000906103ac83600261065d565b11156103b757600080fd5b50016002015161ffff1690565b600060606103d3838587610459565b91509150935093915050565b81516000906103ef83602061065d565b11156103fa57600080fd5b50016020015190565b6020811061043b578151835261041a60208461065d565b925061042760208361065d565b915061043460208261060b565b9050610403565b905182516020929092036101000a6000190180199091169116179052565b60006060600085518551855188888860405160200161047d969594939291906106b6565b6040516020818303038152906040529050835167ffffffffffffffff8111156104a8576104a8610670565b6040519080825280601f01601f1916602001820160405280156104d2576020820181803683370190505b50915083516020830182516020840160055afa925050935093915050565b60008083601f84011261050257600080fd5b50813567ffffffffffffffff81111561051a57600080fd5b60208301915083602082850101111561053257600080fd5b9250929050565b6000806000806000806060878903121561055257600080fd5b863567ffffffffffffffff8082111561056a57600080fd5b6105768a838b016104f0565b9098509650602089013591508082111561058f57600080fd5b61059b8a838b016104f0565b909650945060408901359150808211156105b457600080fd5b506105c189828a016104f0565b979a9699509497509295939492505050565b634e487b7160e01b600052601160045260246000fd5b61ffff818116838216019080821115610604576106046105d3565b5092915050565b81810381811115610314576103146105d3565b8183823760009101908152919050565b60006020828403121561064057600080fd5b5051919050565b634e487b7160e01b600052603260045260246000fd5b80820180821115610314576103146105d3565b634e487b7160e01b600052604160045260246000fd5b6000815160005b818110156106a7576020818501810151868301520161068d565b50600093019283525090919050565b86815285602082015284604082015260006106e66106e06106da6060850188610686565b86610686565b84610686565b9897505050505050505056fea264697066735822122081d54f6872821586c976d8d9aa106e2ea811afa445a713b0da099f753dd8e48364736f6c63430008110033",
    "devdoc": {
      "details": "Implements the DNSSEC RSASHA256 algorithm.",
      "kind": "dev",
      "methods": {},
      "version": 1
    },
    "userdoc": {
      "kind": "user",
      "methods": {},
      "version": 1
    },
    "storageLayout": {
      "storage": [],
      "types": null
    }
  }