export default {
    "address": "0x9c9fcEa62bD0A723b62A2F1e98dE0Ee3df813619",
    "abi": [
      {
        "inputs": [
          {
            "internalType": "bytes",
            "name": "data",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "hash",
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
        "stateMutability": "pure",
        "type": "function"
      }
    ],
    "transactionHash": "0x15d000fd3bf7aaf9a0c767946e7f21bfd15067543cf2dfec35f3c4a5b16ab993",
    "receipt": {
      "to": null,
      "from": "0x0904Dac3347eA47d208F3Fd67402D039a3b99859",
      "contractAddress": "0x9c9fcEa62bD0A723b62A2F1e98dE0Ee3df813619",
      "transactionIndex": 75,
      "gasUsed": "459448",
      "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "blockHash": "0x828287f05629e1ef300c98e2aa5f12815f0b59d031db2214229e4455e60197d1",
      "transactionHash": "0x15d000fd3bf7aaf9a0c767946e7f21bfd15067543cf2dfec35f3c4a5b16ab993",
      "logs": [],
      "blockNumber": 19020684,
      "cumulativeGasUsed": "5206754",
      "status": 1,
      "byzantium": true
    },
    "args": [],
    "numDeployments": 2,
    "solcInputHash": "dd9e022689821cffaeb04b9ddbda87ae",
    "metadata": "{\"compiler\":{\"version\":\"0.8.17+commit.8df45f5f\"},\"language\":\"Solidity\",\"output\":{\"abi\":[{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"hash\",\"type\":\"bytes\"}],\"name\":\"verify\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"pure\",\"type\":\"function\"}],\"devdoc\":{\"details\":\"Implements the DNSSEC SHA1 digest.\",\"kind\":\"dev\",\"methods\":{\"verify(bytes,bytes)\":{\"details\":\"Verifies a cryptographic hash.\",\"params\":{\"data\":\"The data to hash.\",\"hash\":\"The hash to compare to.\"},\"returns\":{\"_0\":\"True iff the hashed data matches the provided hash value.\"}}},\"version\":1},\"userdoc\":{\"kind\":\"user\",\"methods\":{},\"version\":1}},\"settings\":{\"compilationTarget\":{\"contracts/dnssec-oracle/digests/SHA1Digest.sol\":\"SHA1Digest\"},\"evmVersion\":\"london\",\"libraries\":{},\"metadata\":{\"bytecodeHash\":\"ipfs\",\"useLiteralContent\":true},\"optimizer\":{\"enabled\":true,\"runs\":1200},\"remappings\":[]},\"sources\":{\"@ensdomains/solsha1/contracts/SHA1.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\nlibrary SHA1 {\\n    event Debug(bytes32 x);\\n\\n    function sha1(bytes memory data) internal pure returns(bytes20 ret) {\\n        assembly {\\n            // Get a safe scratch location\\n            let scratch := mload(0x40)\\n\\n            // Get the data length, and point data at the first byte\\n            let len := mload(data)\\n            data := add(data, 32)\\n\\n            // Find the length after padding\\n            let totallen := add(and(add(len, 1), 0xFFFFFFFFFFFFFFC0), 64)\\n            switch lt(sub(totallen, len), 9)\\n            case 1 { totallen := add(totallen, 64) }\\n\\n            let h := 0x6745230100EFCDAB890098BADCFE001032547600C3D2E1F0\\n\\n            function readword(ptr, off, count) -> result {\\n                result := 0\\n                if lt(off, count) {\\n                    result := mload(add(ptr, off))\\n                    count := sub(count, off)\\n                    if lt(count, 32) {\\n                        let mask := not(sub(exp(256, sub(32, count)), 1))\\n                        result := and(result, mask)\\n                    }\\n                }\\n            }\\n\\n            for { let i := 0 } lt(i, totallen) { i := add(i, 64) } {\\n                mstore(scratch, readword(data, i, len))\\n                mstore(add(scratch, 32), readword(data, add(i, 32), len))\\n\\n                // If we loaded the last byte, store the terminator byte\\n                switch lt(sub(len, i), 64)\\n                case 1 { mstore8(add(scratch, sub(len, i)), 0x80) }\\n\\n                // If this is the last block, store the length\\n                switch eq(i, sub(totallen, 64))\\n                case 1 { mstore(add(scratch, 32), or(mload(add(scratch, 32)), mul(len, 8))) }\\n\\n                // Expand the 16 32-bit words into 80\\n                for { let j := 64 } lt(j, 128) { j := add(j, 12) } {\\n                    let temp := xor(xor(mload(add(scratch, sub(j, 12))), mload(add(scratch, sub(j, 32)))), xor(mload(add(scratch, sub(j, 56))), mload(add(scratch, sub(j, 64)))))\\n                    temp := or(and(mul(temp, 2), 0xFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFE), and(div(temp, 0x80000000), 0x0000000100000001000000010000000100000001000000010000000100000001))\\n                    mstore(add(scratch, j), temp)\\n                }\\n                for { let j := 128 } lt(j, 320) { j := add(j, 24) } {\\n                    let temp := xor(xor(mload(add(scratch, sub(j, 24))), mload(add(scratch, sub(j, 64)))), xor(mload(add(scratch, sub(j, 112))), mload(add(scratch, sub(j, 128)))))\\n                    temp := or(and(mul(temp, 4), 0xFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFC), and(div(temp, 0x40000000), 0x0000000300000003000000030000000300000003000000030000000300000003))\\n                    mstore(add(scratch, j), temp)\\n                }\\n\\n                let x := h\\n                let f := 0\\n                let k := 0\\n                for { let j := 0 } lt(j, 80) { j := add(j, 1) } {\\n                    switch div(j, 20)\\n                    case 0 {\\n                        // f = d xor (b and (c xor d))\\n                        f := xor(div(x, 0x100000000000000000000), div(x, 0x10000000000))\\n                        f := and(div(x, 0x1000000000000000000000000000000), f)\\n                        f := xor(div(x, 0x10000000000), f)\\n                        k := 0x5A827999\\n                    }\\n                    case 1{\\n                        // f = b xor c xor d\\n                        f := xor(div(x, 0x1000000000000000000000000000000), div(x, 0x100000000000000000000))\\n                        f := xor(div(x, 0x10000000000), f)\\n                        k := 0x6ED9EBA1\\n                    }\\n                    case 2 {\\n                        // f = (b and c) or (d and (b or c))\\n                        f := or(div(x, 0x1000000000000000000000000000000), div(x, 0x100000000000000000000))\\n                        f := and(div(x, 0x10000000000), f)\\n                        f := or(and(div(x, 0x1000000000000000000000000000000), div(x, 0x100000000000000000000)), f)\\n                        k := 0x8F1BBCDC\\n                    }\\n                    case 3 {\\n                        // f = b xor c xor d\\n                        f := xor(div(x, 0x1000000000000000000000000000000), div(x, 0x100000000000000000000))\\n                        f := xor(div(x, 0x10000000000), f)\\n                        k := 0xCA62C1D6\\n                    }\\n                    // temp = (a leftrotate 5) + f + e + k + w[i]\\n                    let temp := and(div(x, 0x80000000000000000000000000000000000000000000000), 0x1F)\\n                    temp := or(and(div(x, 0x800000000000000000000000000000000000000), 0xFFFFFFE0), temp)\\n                    temp := add(f, temp)\\n                    temp := add(and(x, 0xFFFFFFFF), temp)\\n                    temp := add(k, temp)\\n                    temp := add(div(mload(add(scratch, mul(j, 4))), 0x100000000000000000000000000000000000000000000000000000000), temp)\\n                    x := or(div(x, 0x10000000000), mul(temp, 0x10000000000000000000000000000000000000000))\\n                    x := or(and(x, 0xFFFFFFFF00FFFFFFFF000000000000FFFFFFFF00FFFFFFFF), mul(or(and(div(x, 0x4000000000000), 0xC0000000), and(div(x, 0x400000000000000000000), 0x3FFFFFFF)), 0x100000000000000000000))\\n                }\\n\\n                h := and(add(h, x), 0xFFFFFFFF00FFFFFFFF00FFFFFFFF00FFFFFFFF00FFFFFFFF)\\n            }\\n            ret := mul(or(or(or(or(and(div(h, 0x100000000), 0xFFFFFFFF00000000000000000000000000000000), and(div(h, 0x1000000), 0xFFFFFFFF000000000000000000000000)), and(div(h, 0x10000), 0xFFFFFFFF0000000000000000)), and(div(h, 0x100), 0xFFFFFFFF00000000)), and(h, 0xFFFFFFFF)), 0x1000000000000000000000000)\\n        }\\n    }\\n}\\n\",\"keccak256\":\"0x746d9b85de197afbc13182cbe4ba4f7917f19594e07c655d6a0c85fdf7460a8a\"},\"contracts/dnssec-oracle/BytesUtils.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\nlibrary BytesUtils {\\n    error OffsetOutOfBoundsError(uint256 offset, uint256 length);\\n\\n    /*\\n     * @dev Returns the keccak-256 hash of a byte range.\\n     * @param self The byte string to hash.\\n     * @param offset The position to start hashing at.\\n     * @param len The number of bytes to hash.\\n     * @return The hash of the byte range.\\n     */\\n    function keccak(\\n        bytes memory self,\\n        uint256 offset,\\n        uint256 len\\n    ) internal pure returns (bytes32 ret) {\\n        require(offset + len <= self.length);\\n        assembly {\\n            ret := keccak256(add(add(self, 32), offset), len)\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns a positive number if `other` comes lexicographically after\\n     *      `self`, a negative number if it comes before, or zero if the\\n     *      contents of the two bytes are equal.\\n     * @param self The first bytes to compare.\\n     * @param other The second bytes to compare.\\n     * @return The result of the comparison.\\n     */\\n    function compare(\\n        bytes memory self,\\n        bytes memory other\\n    ) internal pure returns (int256) {\\n        return compare(self, 0, self.length, other, 0, other.length);\\n    }\\n\\n    /*\\n     * @dev Returns a positive number if `other` comes lexicographically after\\n     *      `self`, a negative number if it comes before, or zero if the\\n     *      contents of the two bytes are equal. Comparison is done per-rune,\\n     *      on unicode codepoints.\\n     * @param self The first bytes to compare.\\n     * @param offset The offset of self.\\n     * @param len    The length of self.\\n     * @param other The second bytes to compare.\\n     * @param otheroffset The offset of the other string.\\n     * @param otherlen    The length of the other string.\\n     * @return The result of the comparison.\\n     */\\n    function compare(\\n        bytes memory self,\\n        uint256 offset,\\n        uint256 len,\\n        bytes memory other,\\n        uint256 otheroffset,\\n        uint256 otherlen\\n    ) internal pure returns (int256) {\\n        if (offset + len > self.length) {\\n            revert OffsetOutOfBoundsError(offset + len, self.length);\\n        }\\n        if (otheroffset + otherlen > other.length) {\\n            revert OffsetOutOfBoundsError(otheroffset + otherlen, other.length);\\n        }\\n\\n        uint256 shortest = len;\\n        if (otherlen < len) shortest = otherlen;\\n\\n        uint256 selfptr;\\n        uint256 otherptr;\\n\\n        assembly {\\n            selfptr := add(self, add(offset, 32))\\n            otherptr := add(other, add(otheroffset, 32))\\n        }\\n        for (uint256 idx = 0; idx < shortest; idx += 32) {\\n            uint256 a;\\n            uint256 b;\\n            assembly {\\n                a := mload(selfptr)\\n                b := mload(otherptr)\\n            }\\n            if (a != b) {\\n                // Mask out irrelevant bytes and check again\\n                uint256 mask;\\n                if (shortest - idx >= 32) {\\n                    mask = type(uint256).max;\\n                } else {\\n                    mask = ~(2 ** (8 * (idx + 32 - shortest)) - 1);\\n                }\\n                int256 diff = int256(a & mask) - int256(b & mask);\\n                if (diff != 0) return diff;\\n            }\\n            selfptr += 32;\\n            otherptr += 32;\\n        }\\n\\n        return int256(len) - int256(otherlen);\\n    }\\n\\n    /*\\n     * @dev Returns true if the two byte ranges are equal.\\n     * @param self The first byte range to compare.\\n     * @param offset The offset into the first byte range.\\n     * @param other The second byte range to compare.\\n     * @param otherOffset The offset into the second byte range.\\n     * @param len The number of bytes to compare\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        uint256 offset,\\n        bytes memory other,\\n        uint256 otherOffset,\\n        uint256 len\\n    ) internal pure returns (bool) {\\n        return keccak(self, offset, len) == keccak(other, otherOffset, len);\\n    }\\n\\n    /*\\n     * @dev Returns true if the two byte ranges are equal with offsets.\\n     * @param self The first byte range to compare.\\n     * @param offset The offset into the first byte range.\\n     * @param other The second byte range to compare.\\n     * @param otherOffset The offset into the second byte range.\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        uint256 offset,\\n        bytes memory other,\\n        uint256 otherOffset\\n    ) internal pure returns (bool) {\\n        return\\n            keccak(self, offset, self.length - offset) ==\\n            keccak(other, otherOffset, other.length - otherOffset);\\n    }\\n\\n    /*\\n     * @dev Compares a range of 'self' to all of 'other' and returns True iff\\n     *      they are equal.\\n     * @param self The first byte range to compare.\\n     * @param offset The offset into the first byte range.\\n     * @param other The second byte range to compare.\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        uint256 offset,\\n        bytes memory other\\n    ) internal pure returns (bool) {\\n        return\\n            self.length == offset + other.length &&\\n            equals(self, offset, other, 0, other.length);\\n    }\\n\\n    /*\\n     * @dev Returns true if the two byte ranges are equal.\\n     * @param self The first byte range to compare.\\n     * @param other The second byte range to compare.\\n     * @return True if the byte ranges are equal, false otherwise.\\n     */\\n    function equals(\\n        bytes memory self,\\n        bytes memory other\\n    ) internal pure returns (bool) {\\n        return\\n            self.length == other.length &&\\n            equals(self, 0, other, 0, self.length);\\n    }\\n\\n    /*\\n     * @dev Returns the 8-bit number at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 8 bits of the string, interpreted as an integer.\\n     */\\n    function readUint8(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (uint8 ret) {\\n        return uint8(self[idx]);\\n    }\\n\\n    /*\\n     * @dev Returns the 16-bit number at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 16 bits of the string, interpreted as an integer.\\n     */\\n    function readUint16(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (uint16 ret) {\\n        require(idx + 2 <= self.length);\\n        assembly {\\n            ret := and(mload(add(add(self, 2), idx)), 0xFFFF)\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the 32-bit number at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 32 bits of the string, interpreted as an integer.\\n     */\\n    function readUint32(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (uint32 ret) {\\n        require(idx + 4 <= self.length);\\n        assembly {\\n            ret := and(mload(add(add(self, 4), idx)), 0xFFFFFFFF)\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the 32 byte value at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 32 bytes of the string.\\n     */\\n    function readBytes32(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (bytes32 ret) {\\n        require(idx + 32 <= self.length);\\n        assembly {\\n            ret := mload(add(add(self, 32), idx))\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the 32 byte value at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes\\n     * @return The specified 32 bytes of the string.\\n     */\\n    function readBytes20(\\n        bytes memory self,\\n        uint256 idx\\n    ) internal pure returns (bytes20 ret) {\\n        require(idx + 20 <= self.length);\\n        assembly {\\n            ret := and(\\n                mload(add(add(self, 32), idx)),\\n                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000\\n            )\\n        }\\n    }\\n\\n    /*\\n     * @dev Returns the n byte value at the specified index of self.\\n     * @param self The byte string.\\n     * @param idx The index into the bytes.\\n     * @param len The number of bytes.\\n     * @return The specified 32 bytes of the string.\\n     */\\n    function readBytesN(\\n        bytes memory self,\\n        uint256 idx,\\n        uint256 len\\n    ) internal pure returns (bytes32 ret) {\\n        require(len <= 32);\\n        require(idx + len <= self.length);\\n        assembly {\\n            let mask := not(sub(exp(256, sub(32, len)), 1))\\n            ret := and(mload(add(add(self, 32), idx)), mask)\\n        }\\n    }\\n\\n    function memcpy(uint256 dest, uint256 src, uint256 len) private pure {\\n        // Copy word-length chunks while possible\\n        for (; len >= 32; len -= 32) {\\n            assembly {\\n                mstore(dest, mload(src))\\n            }\\n            dest += 32;\\n            src += 32;\\n        }\\n\\n        // Copy remaining bytes\\n        unchecked {\\n            uint256 mask = (256 ** (32 - len)) - 1;\\n            assembly {\\n                let srcpart := and(mload(src), not(mask))\\n                let destpart := and(mload(dest), mask)\\n                mstore(dest, or(destpart, srcpart))\\n            }\\n        }\\n    }\\n\\n    /*\\n     * @dev Copies a substring into a new byte string.\\n     * @param self The byte string to copy from.\\n     * @param offset The offset to start copying at.\\n     * @param len The number of bytes to copy.\\n     */\\n    function substring(\\n        bytes memory self,\\n        uint256 offset,\\n        uint256 len\\n    ) internal pure returns (bytes memory) {\\n        require(offset + len <= self.length);\\n\\n        bytes memory ret = new bytes(len);\\n        uint256 dest;\\n        uint256 src;\\n\\n        assembly {\\n            dest := add(ret, 32)\\n            src := add(add(self, 32), offset)\\n        }\\n        memcpy(dest, src, len);\\n\\n        return ret;\\n    }\\n\\n    // Maps characters from 0x30 to 0x7A to their base32 values.\\n    // 0xFF represents invalid characters in that range.\\n    bytes constant base32HexTable =\\n        hex\\\"00010203040506070809FFFFFFFFFFFFFF0A0B0C0D0E0F101112131415161718191A1B1C1D1E1FFFFFFFFFFFFFFFFFFFFF0A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\\\";\\n\\n    /**\\n     * @dev Decodes unpadded base32 data of up to one word in length.\\n     * @param self The data to decode.\\n     * @param off Offset into the string to start at.\\n     * @param len Number of characters to decode.\\n     * @return The decoded data, left aligned.\\n     */\\n    function base32HexDecodeWord(\\n        bytes memory self,\\n        uint256 off,\\n        uint256 len\\n    ) internal pure returns (bytes32) {\\n        require(len <= 52);\\n\\n        uint256 ret = 0;\\n        uint8 decoded;\\n        for (uint256 i = 0; i < len; i++) {\\n            bytes1 char = self[off + i];\\n            require(char >= 0x30 && char <= 0x7A);\\n            decoded = uint8(base32HexTable[uint256(uint8(char)) - 0x30]);\\n            require(decoded <= 0x20);\\n            if (i == len - 1) {\\n                break;\\n            }\\n            ret = (ret << 5) | decoded;\\n        }\\n\\n        uint256 bitlen = len * 5;\\n        if (len % 8 == 0) {\\n            // Multiple of 8 characters, no padding\\n            ret = (ret << 5) | decoded;\\n        } else if (len % 8 == 2) {\\n            // Two extra characters - 1 byte\\n            ret = (ret << 3) | (decoded >> 2);\\n            bitlen -= 2;\\n        } else if (len % 8 == 4) {\\n            // Four extra characters - 2 bytes\\n            ret = (ret << 1) | (decoded >> 4);\\n            bitlen -= 4;\\n        } else if (len % 8 == 5) {\\n            // Five extra characters - 3 bytes\\n            ret = (ret << 4) | (decoded >> 1);\\n            bitlen -= 1;\\n        } else if (len % 8 == 7) {\\n            // Seven extra characters - 4 bytes\\n            ret = (ret << 2) | (decoded >> 3);\\n            bitlen -= 3;\\n        } else {\\n            revert();\\n        }\\n\\n        return bytes32(ret << (256 - bitlen));\\n    }\\n\\n    /**\\n     * @dev Finds the first occurrence of the byte `needle` in `self`.\\n     * @param self The string to search\\n     * @param off The offset to start searching at\\n     * @param len The number of bytes to search\\n     * @param needle The byte to search for\\n     * @return The offset of `needle` in `self`, or 2**256-1 if it was not found.\\n     */\\n    function find(\\n        bytes memory self,\\n        uint256 off,\\n        uint256 len,\\n        bytes1 needle\\n    ) internal pure returns (uint256) {\\n        for (uint256 idx = off; idx < off + len; idx++) {\\n            if (self[idx] == needle) {\\n                return idx;\\n            }\\n        }\\n        return type(uint256).max;\\n    }\\n}\\n\",\"keccak256\":\"0x4f10902639b85a17ae10745264feff322e793bfb1bc130a9a90efa7dda47c6cc\"},\"contracts/dnssec-oracle/digests/Digest.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\n/**\\n * @dev An interface for contracts implementing a DNSSEC digest.\\n */\\ninterface Digest {\\n    /**\\n     * @dev Verifies a cryptographic hash.\\n     * @param data The data to hash.\\n     * @param hash The hash to compare to.\\n     * @return True iff the hashed data matches the provided hash value.\\n     */\\n    function verify(\\n        bytes calldata data,\\n        bytes calldata hash\\n    ) external pure virtual returns (bool);\\n}\\n\",\"keccak256\":\"0x8ea926b2db0578c4ad7fce4582fc0f6f0f9efee8dca2085dbdb9984f18941e28\"},\"contracts/dnssec-oracle/digests/SHA1Digest.sol\":{\"content\":\"pragma solidity ^0.8.4;\\n\\nimport \\\"./Digest.sol\\\";\\nimport \\\"../BytesUtils.sol\\\";\\nimport \\\"@ensdomains/solsha1/contracts/SHA1.sol\\\";\\n\\n/**\\n * @dev Implements the DNSSEC SHA1 digest.\\n */\\ncontract SHA1Digest is Digest {\\n    using BytesUtils for *;\\n\\n    function verify(\\n        bytes calldata data,\\n        bytes calldata hash\\n    ) external pure override returns (bool) {\\n        require(hash.length == 20, \\\"Invalid sha1 hash length\\\");\\n        bytes32 expected = hash.readBytes20(0);\\n        bytes20 computed = SHA1.sha1(data);\\n        return expected == computed;\\n    }\\n}\\n\",\"keccak256\":\"0x56f4e188f9c5ea120354ff4d00555c3b76b5837be00a1564fed608e22a7dc8aa\"}},\"version\":1}",
    "bytecode": "0x608060405234801561001057600080fd5b5061076c806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063f7e83aee14610030575b600080fd5b61004361003e36600461068a565b610057565b604051901515815260200160405180910390f35b6000601482146100c7576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f496e76616c696420736861312068617368206c656e6774680000000000000000604482015260640160405180910390fd5b600061010d600085858080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929392505061017c9050565b6bffffffffffffffffffffffff19169050600061015f87878080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506101af92505050565b6bffffffffffffffffffffffff1916919091149695505050505050565b815160009061018c8360146106f6565b111561019757600080fd5b5001602001516bffffffffffffffffffffffff191690565b60006040518251602084019350604067ffffffffffffffc0600183011601600982820310600181036101e2576040820191505b50776745230100efcdab890098badcfe001032547600c3d2e1f0610235565b60008383101561022e5750808201519282900392602084101561022e5760001960208590036101000a0119165b9392505050565b60005b828110156105c15761024b848289610201565b855261025b846020830189610201565b6020860152604081850310600181036102775760808286038701535b506040830381146001810361029457602086018051600887021790525b5060405b608081101561031c57858101603f19810151603719820151601f19830151600b198401516002911891909218189081027ffffffffefffffffefffffffefffffffefffffffefffffffefffffffefffffffe1663800000009091047c010000000100000001000000010000000100000001000000010000000116179052600c01610298565b5060805b6101408110156103a557858101607f19810151606f19820151603f198301516017198401516004911891909218189081027ffffffffcfffffffcfffffffcfffffffcfffffffcfffffffcfffffffcfffffffc1663400000009091047c030000000300000003000000030000000300000003000000030000000316179052601801610320565b508160008060005b6050811015610597576014810480156103dd576001811461040d576002811461043b576003811461046e57610498565b6501000000000085046a010000000000000000000086048118600160781b870416189350635a8279999250610498565b650100000000008504600160781b86046a0100000000000000000000870418189350636ed9eba19250610498565b6a01000000000000000000008504600160781b8604818117650100000000008804169116179350638f1bbcdc9250610498565b650100000000008504600160781b86046a010000000000000000000087041818935063ca62c1d692505b50601f770800000000000000000000000000000000000000000000008504168063ffffffe073080000000000000000000000000000000000000087041617905080840190508063ffffffff86160190508083019050807c0100000000000000000000000000000000000000000000000000000000600484028c015104019050740100000000000000000000000000000000000000008102650100000000008604179450506a0100000000000000000000633fffffff6a040000000000000000000086041663c00000006604000000000000870416170277ffffffff00ffffffff000000000000ffffffff00ffffffff85161793506001810190506103ad565b5050509190910177ffffffff00ffffffff00ffffffff00ffffffff00ffffffff1690604001610238565b506c0100000000000000000000000063ffffffff821667ffffffff000000006101008404166bffffffff0000000000000000620100008504166fffffffff000000000000000000000000630100000086041673ffffffff000000000000000000000000000000006401000000008704161717171702945050505050919050565b60008083601f84011261065357600080fd5b50813567ffffffffffffffff81111561066b57600080fd5b60208301915083602082850101111561068357600080fd5b9250929050565b600080600080604085870312156106a057600080fd5b843567ffffffffffffffff808211156106b857600080fd5b6106c488838901610641565b909650945060208701359150808211156106dd57600080fd5b506106ea87828801610641565b95989497509550505050565b80820180821115610730577f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b9291505056fea26469706673582212201eb056a89a6b6b67ba5acc9d1d278299eadfc218cf0f5baba761aa60461f441964736f6c63430008110033",
    "deployedBytecode": "0x608060405234801561001057600080fd5b506004361061002b5760003560e01c8063f7e83aee14610030575b600080fd5b61004361003e36600461068a565b610057565b604051901515815260200160405180910390f35b6000601482146100c7576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f496e76616c696420736861312068617368206c656e6774680000000000000000604482015260640160405180910390fd5b600061010d600085858080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929392505061017c9050565b6bffffffffffffffffffffffff19169050600061015f87878080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506101af92505050565b6bffffffffffffffffffffffff1916919091149695505050505050565b815160009061018c8360146106f6565b111561019757600080fd5b5001602001516bffffffffffffffffffffffff191690565b60006040518251602084019350604067ffffffffffffffc0600183011601600982820310600181036101e2576040820191505b50776745230100efcdab890098badcfe001032547600c3d2e1f0610235565b60008383101561022e5750808201519282900392602084101561022e5760001960208590036101000a0119165b9392505050565b60005b828110156105c15761024b848289610201565b855261025b846020830189610201565b6020860152604081850310600181036102775760808286038701535b506040830381146001810361029457602086018051600887021790525b5060405b608081101561031c57858101603f19810151603719820151601f19830151600b198401516002911891909218189081027ffffffffefffffffefffffffefffffffefffffffefffffffefffffffefffffffe1663800000009091047c010000000100000001000000010000000100000001000000010000000116179052600c01610298565b5060805b6101408110156103a557858101607f19810151606f19820151603f198301516017198401516004911891909218189081027ffffffffcfffffffcfffffffcfffffffcfffffffcfffffffcfffffffcfffffffc1663400000009091047c030000000300000003000000030000000300000003000000030000000316179052601801610320565b508160008060005b6050811015610597576014810480156103dd576001811461040d576002811461043b576003811461046e57610498565b6501000000000085046a010000000000000000000086048118600160781b870416189350635a8279999250610498565b650100000000008504600160781b86046a0100000000000000000000870418189350636ed9eba19250610498565b6a01000000000000000000008504600160781b8604818117650100000000008804169116179350638f1bbcdc9250610498565b650100000000008504600160781b86046a010000000000000000000087041818935063ca62c1d692505b50601f770800000000000000000000000000000000000000000000008504168063ffffffe073080000000000000000000000000000000000000087041617905080840190508063ffffffff86160190508083019050807c0100000000000000000000000000000000000000000000000000000000600484028c015104019050740100000000000000000000000000000000000000008102650100000000008604179450506a0100000000000000000000633fffffff6a040000000000000000000086041663c00000006604000000000000870416170277ffffffff00ffffffff000000000000ffffffff00ffffffff85161793506001810190506103ad565b5050509190910177ffffffff00ffffffff00ffffffff00ffffffff00ffffffff1690604001610238565b506c0100000000000000000000000063ffffffff821667ffffffff000000006101008404166bffffffff0000000000000000620100008504166fffffffff000000000000000000000000630100000086041673ffffffff000000000000000000000000000000006401000000008704161717171702945050505050919050565b60008083601f84011261065357600080fd5b50813567ffffffffffffffff81111561066b57600080fd5b60208301915083602082850101111561068357600080fd5b9250929050565b600080600080604085870312156106a057600080fd5b843567ffffffffffffffff808211156106b857600080fd5b6106c488838901610641565b909650945060208701359150808211156106dd57600080fd5b506106ea87828801610641565b95989497509550505050565b80820180821115610730577f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b9291505056fea26469706673582212201eb056a89a6b6b67ba5acc9d1d278299eadfc218cf0f5baba761aa60461f441964736f6c63430008110033",
    "devdoc": {
      "details": "Implements the DNSSEC SHA1 digest.",
      "kind": "dev",
      "methods": {
        "verify(bytes,bytes)": {
          "details": "Verifies a cryptographic hash.",
          "params": {
            "data": "The data to hash.",
            "hash": "The hash to compare to."
          },
          "returns": {
            "_0": "True iff the hashed data matches the provided hash value."
          }
        }
      },
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