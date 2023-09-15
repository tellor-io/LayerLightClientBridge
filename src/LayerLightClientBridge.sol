// SPDX-License-Identifier: MIT
pragma solidity 0.8.3;

// Adopted from https://github.com/lazyledger/protobuf3-solidity-lib/blob/master/contracts/ProtobufLib.sol
library ProtobufLib {
    /// @notice Protobuf wire types.
    enum WireType {
        Varint,
        Bits64,
        LengthDelimited,
        StartGroup,
        EndGroup,
        Bits32,
        WIRE_TYPE_MAX
    }

    /// @dev Maximum number of bytes for a varint.
    /// @dev 64 bits, in groups of base-128 (7 bits).
    uint64 internal constant MAX_VARINT_BYTES = 10;

    ////////////////////////////////////
    // Decoding
    ////////////////////////////////////

    /// @notice Decode key.
    /// @dev https://developers.google.com/protocol-buffers/docs/encoding#structure
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Field number
    /// @return Wire type
    function decode_key(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64,
            WireType
        )
    {
        // The key is a varint with encoding
        // (field_number << 3) | wire_type
        (bool success, uint64 pos, uint64 key) = decode_varint(p, buf);
        if (!success) {
            return (false, pos, 0, WireType.WIRE_TYPE_MAX);
        }

        uint64 field_number = key >> 3;
        uint64 wire_type_val = key & 0x07;
        // Check that wire type is bounded
        if (wire_type_val >= uint64(WireType.WIRE_TYPE_MAX)) {
            return (false, pos, 0, WireType.WIRE_TYPE_MAX);
        }
        WireType wire_type = WireType(wire_type_val);

        // Start and end group types are deprecated, so forbid them
        if (
            wire_type == WireType.StartGroup || wire_type == WireType.EndGroup
        ) {
            return (false, pos, 0, WireType.WIRE_TYPE_MAX);
        }

        return (true, pos, field_number, wire_type);
    }

    /// @notice Decode varint.
    /// @dev https://developers.google.com/protocol-buffers/docs/encoding#varints
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_varint(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        uint64 val;
        uint64 i;

        for (i = 0; i < MAX_VARINT_BYTES; i++) {
            // Check that index is within bounds
            if (i + p >= buf.length) {
                return (false, p, 0);
            }

            // Get byte at offset
            uint8 b = uint8(buf[p + i]);

            // Highest bit is used to indicate if there are more bytes to come
            // Mask to get 7-bit value: 0111 1111
            uint8 v = b & 0x7F;

            // Groups of 7 bits are ordered least significant first
            val |= uint64(v) << uint64(i * 7);

            // Mask to get keep going bit: 1000 0000
            if (b & 0x80 == 0) {
                // [STRICT]
                // Check for trailing zeroes if more than one byte is used
                // (the value 0 still uses one byte)
                if (i > 0 && v == 0) {
                    return (false, p, 0);
                }

                break;
            }
        }

        // Check that at most MAX_VARINT_BYTES are used
        if (i >= MAX_VARINT_BYTES) {
            return (false, p, 0);
        }

        // [STRICT]
        // If all 10 bytes are used, the last byte (most significant 7 bits)
        // must be at most 0000 0001, since 7*9 = 63
        if (i == MAX_VARINT_BYTES - 1) {
            if (uint8(buf[p + i]) > 1) {
                return (false, p, 0);
            }
        }

        return (true, p + i + 1, val);
    }

    /// @notice Decode varint int32.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_int32(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            int32
        )
    {
        (bool success, uint64 pos, uint64 val) = decode_varint(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        // [STRICT]
        // Highest 4 bytes must be 0 if positive
        if (val >> 63 == 0) {
            if (val & 0xFFFFFFFF00000000 != 0) {
                return (false, pos, 0);
            }
        }

        return (true, pos, int32(uint32(val)));
    }

    /// @notice Decode varint int64.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_int64(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            int64
        )
    {
        (bool success, uint64 pos, uint64 val) = decode_varint(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        return (true, pos, int64(val));
    }

    /// @notice Decode varint uint32.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_uint32(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint32
        )
    {
        (bool success, uint64 pos, uint64 val) = decode_varint(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        // [STRICT]
        // Highest 4 bytes must be 0
        if (val & 0xFFFFFFFF00000000 != 0) {
            return (false, pos, 0);
        }

        return (true, pos, uint32(val));
    }

    /// @notice Decode varint uint64.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_uint64(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        (bool success, uint64 pos, uint64 val) = decode_varint(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        return (true, pos, val);
    }

    // /// @notice Decode varint sint32.
    // /// @param p Position
    // /// @param buf Buffer
    // /// @return Success
    // /// @return New position
    // /// @return Decoded int
    // function decode_sint32(uint64 p, bytes memory buf)
    //     internal
    //     pure
    //     returns (
    //         bool,
    //         uint64,
    //         int32
    //     )
    // {
    //     (bool success, uint64 pos, uint64 val) = decode_varint(p, buf);
    //     if (!success) {
    //         return (false, pos, 0);
    //     }

    //     // [STRICT]
    //     // Highest 4 bytes must be 0
    //     if (val & 0xFFFFFFFF00000000 != 0) {
    //         return (false, pos, 0);
    //     }

    //     // https://stackoverflow.com/questions/2210923/zig-zag-decoding/2211086#2211086
    //     uint64 zigzag_val = (val >> 1) ^ (-(val & 1));

    //     return (true, pos, int32(uint32(zigzag_val)));
    // }

    // /// @notice Decode varint sint64.
    // /// @param p Position
    // /// @param buf Buffer
    // /// @return Success
    // /// @return New position
    // /// @return Decoded int
    // function decode_sint64(uint64 p, bytes memory buf)
    //     internal
    //     pure
    //     returns (
    //         bool,
    //         uint64,
    //         int64
    //     )
    // {
    //     (bool success, uint64 pos, uint64 val) = decode_varint(p, buf);
    //     if (!success) {
    //         return (false, pos, 0);
    //     }

    //     // https://stackoverflow.com/questions/2210923/zig-zag-decoding/2211086#2211086
    //     uint64 zigzag_val = (val >> 1) ^ (-(val & 1));

    //     return (true, pos, int64(zigzag_val));
    // }

    /// @notice Decode Boolean.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded bool
    function decode_bool(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            bool
        )
    {
        (bool success, uint64 pos, uint64 val) = decode_varint(p, buf);
        if (!success) {
            return (false, pos, false);
        }

        // [STRICT]
        // Value must be 0 or 1
        if (val > 1) {
            return (false, pos, false);
        }

        if (val == 0) {
            return (true, pos, false);
        }

        return (true, pos, true);
    }

    /// @notice Decode enumeration.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded enum as raw int
    function decode_enum(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            int32
        )
    {
        return decode_int32(p, buf);
    }

    /// @notice Decode fixed 64-bit int.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_bits64(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        uint64 val;

        // Check that index is within bounds
        if (8 + p > buf.length) {
            return (false, p, 0);
        }

        for (uint64 i = 0; i < 8; i++) {
            uint8 b = uint8(buf[p + i]);

            // Little endian
            val |= uint64(b) << uint64(i * 8);
        }

        return (true, p + 8, val);
    }

    /// @notice Decode fixed uint64.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_fixed64(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        (bool success, uint64 pos, uint64 val) = decode_bits64(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        return (true, pos, val);
    }

    /// @notice Decode fixed int64.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_sfixed64(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            int64
        )
    {
        (bool success, uint64 pos, uint64 val) = decode_bits64(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        return (true, pos, int64(val));
    }

    /// @notice Decode fixed 32-bit int.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_bits32(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint32
        )
    {
        uint32 val;

        // Check that index is within bounds
        if (4 + p > buf.length) {
            return (false, p, 0);
        }

        for (uint64 i = 0; i < 4; i++) {
            uint8 b = uint8(buf[p + i]);

            // Little endian
            val |= uint32(b) << uint32(i * 8);
        }

        return (true, p + 4, val);
    }

    /// @notice Decode fixed uint32.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_fixed32(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint32
        )
    {
        (bool success, uint64 pos, uint32 val) = decode_bits32(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        return (true, pos, val);
    }

    /// @notice Decode fixed int32.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Decoded int
    function decode_sfixed32(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            int32
        )
    {
        (bool success, uint64 pos, uint32 val) = decode_bits32(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        return (true, pos, int32(val));
    }

    /// @notice Decode length-delimited field.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position (after size)
    /// @return Size in bytes
    function decode_length_delimited(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        // Length-delimited fields begin with a varint of the number of bytes that follow
        (bool success, uint64 pos, uint64 size) = decode_varint(p, buf);
        if (!success) {
            return (false, pos, 0);
        }

        // Check for overflow
        if (pos + size < pos) {
            return (false, pos, 0);
        }

        // Check that index is within bounds
        if (size + pos > buf.length) {
            return (false, pos, 0);
        }

        return (true, pos, size);
    }

    /// @notice Decode string.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position
    /// @return Size in bytes
    function decode_string(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            string memory
        )
    {
        (bool success, uint64 pos, uint64 size) =
            decode_length_delimited(p, buf);
        if (!success) {
            return (false, pos, "");
        }

        bytes memory field = new bytes(size);
        for (uint64 i = 0; i < size; i++) {
            field[i] = buf[pos + i];
        }

        return (true, pos + size, string(field));
    }

    /// @notice Decode bytes array.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position (after size)
    /// @return Size in bytes
    function decode_bytes(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        return decode_length_delimited(p, buf);
    }

    /// @notice Decode embedded message.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position (after size)
    /// @return Size in bytes
    function decode_embedded_message(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        return decode_length_delimited(p, buf);
    }

    /// @notice Decode packed repeated field.
    /// @param p Position
    /// @param buf Buffer
    /// @return Success
    /// @return New position (after size)
    /// @return Size in bytes
    function decode_packed_repeated(uint64 p, bytes memory buf)
        internal
        pure
        returns (
            bool,
            uint64,
            uint64
        )
    {
        return decode_length_delimited(p, buf);
    }

    ////////////////////////////////////
    // Encoding
    ////////////////////////////////////

    /// @notice Encode key.
    /// @dev https://developers.google.com/protocol-buffers/docs/encoding#structure
    /// @param field_number Field number
    /// @param wire_type Wire type
    /// @return Marshaled bytes
    function encode_key(uint64 field_number, uint64 wire_type)
        internal
        pure
        returns (bytes memory)
    {
        uint64 key = (field_number << 3) | wire_type;

        bytes memory buf = encode_varint(key);

        return buf;
    }

    /// @notice Encode varint.
    /// @dev https://developers.google.com/protocol-buffers/docs/encoding#varints
    /// @param n Number
    /// @return Marshaled bytes
    function encode_varint(uint64 n) internal pure returns (bytes memory) {
        // Count the number of groups of 7 bits
        // We need this pre-processing step since Solidity doesn't allow dynamic memory resizing
        uint64 tmp = n;
        uint64 num_bytes = 1;
        while (tmp > 0x7F) {
            tmp = tmp >> 7;
            num_bytes += 1;
        }

        bytes memory buf = new bytes(num_bytes);

        tmp = n;
        for (uint64 i = 0; i < num_bytes; i++) {
            // Set the first bit in the byte for each group of 7 bits
            buf[i] = bytes1(0x80 | uint8(tmp & 0x7F));
            tmp = tmp >> 7;
        }
        // Unset the first bit of the last byte
        buf[num_bytes - 1] &= 0x7F;

        return buf;
    }

    /// @notice Encode varint int32.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_int32(int32 n) internal pure returns (bytes memory) {
        return encode_varint(uint64(uint32(n)));
    }

    /// @notice Decode varint int64.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_int64(int64 n) internal pure returns (bytes memory) {
        return encode_varint(uint64(n));
    }

    /// @notice Encode varint uint32.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_uint32(uint32 n) internal pure returns (bytes memory) {
        return encode_varint(n);
    }

    /// @notice Encode varint uint64.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_uint64(uint64 n) internal pure returns (bytes memory) {
        return encode_varint(n);
    }

    /// @notice Encode varint sint32.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_sint32(int32 n) internal pure returns (bytes memory) {
        // https://developers.google.com/protocol-buffers/docs/encoding#signed_integers
        uint32 mask = 0;
        if (n < 0) {
            mask -= 1;
        }
        uint32 zigzag_val = (uint32(n) << 1) ^ mask;

        return encode_varint(zigzag_val);
    }

    /// @notice Encode varint sint64.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_sint64(int64 n) internal pure returns (bytes memory) {
        // https://developers.google.com/protocol-buffers/docs/encoding#signed_integers
        uint64 mask = 0;
        if (n < 0) {
            mask -= 1;
        }
        uint64 zigzag_val = (uint64(n) << 1) ^ mask;

        return encode_varint(zigzag_val);
    }

    /// @notice Encode Boolean.
    /// @param b Boolean
    /// @return Marshaled bytes
    function encode_bool(bool b) internal pure returns (bytes memory) {
        uint64 n = b ? 1 : 0;

        return encode_varint(n);
    }

    /// @notice Encode enumeration.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_enum(int32 n) internal pure returns (bytes memory) {
        return encode_int32(n);
    }

    /// @notice Encode fixed 64-bit int.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_bits64(uint64 n) internal pure returns (bytes memory) {
        bytes memory buf = new bytes(8);

        uint64 tmp = n;
        for (uint64 i = 0; i < 8; i++) {
            // Little endian
            buf[i] = bytes1(uint8(tmp & 0xFF));
            tmp = tmp >> 8;
        }

        return buf;
    }

    /// @notice Encode fixed uint64.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_fixed64(uint64 n) internal pure returns (bytes memory) {
        return encode_bits64(n);
    }

    /// @notice Encode fixed int64.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_sfixed64(int64 n) internal pure returns (bytes memory) {
        return encode_bits64(uint64(n));
    }

    /// @notice Decode fixed 32-bit int.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_bits32(uint32 n) internal pure returns (bytes memory) {
        bytes memory buf = new bytes(4);

        uint64 tmp = n;
        for (uint64 i = 0; i < 4; i++) {
            // Little endian
            buf[i] = bytes1(uint8(tmp & 0xFF));
            tmp = tmp >> 8;
        }

        return buf;
    }

    /// @notice Encode fixed uint32.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_fixed32(uint32 n) internal pure returns (bytes memory) {
        return encode_bits32(n);
    }

    /// @notice Encode fixed int32.
    /// @param n Number
    /// @return Marshaled bytes
    function encode_sfixed32(int32 n) internal pure returns (bytes memory) {
        return encode_bits32(uint32(n));
    }

    /// @notice Encode length-delimited field.
    /// @param b Bytes
    /// @return Marshaled bytes
    function encode_length_delimited(bytes memory b)
        internal
        pure
        returns (bytes memory)
    {
        // Length-delimited fields begin with a varint of the number of bytes that follow
        bytes memory length_buf = encode_uint64(uint64(b.length));
        bytes memory buf = new bytes(b.length + length_buf.length);

        for (uint64 i = 0; i < length_buf.length; i++) {
            buf[i] = length_buf[i];
        }

        for (uint64 i = 0; i < b.length; i++) {
            buf[i + length_buf.length] = b[i];
        }

        return buf;
    }

    /// @notice Encode string.
    /// @param s String
    /// @return Marshaled bytes
    function encode_string(string memory s)
        internal
        pure
        returns (bytes memory)
    {
        return encode_length_delimited(bytes(s));
    }

    /// @notice Encode bytes array.
    /// @param b Bytes
    /// @return Marshaled bytes
    function encode_bytes(bytes memory b) internal pure returns (bytes memory) {
        return encode_length_delimited(b);
    }

    /// @notice Encode embedded message.
    /// @param m Message
    /// @return Marshaled bytes
    function encode_embedded_message(bytes memory m)
        internal
        pure
        returns (bytes memory)
    {
        return encode_length_delimited(m);
    }

    /// @notice Encode packed repeated field.
    /// @param b Bytes
    /// @return Marshaled bytes
    function encode_packed_repeated(bytes memory b)
        internal
        pure
        returns (bytes memory)
    {
        return encode_length_delimited(b);
    }
}

contract LayerLightClientBridge {

    bytes public encodedChainId;
    uint256 public totalValidatorPower;

    mapping (address => uint256) public validatorPowers;
    mapping (uint256 => BlockDetail) public blockDetails; // mapping block height to block details

    struct BlockDetail {
        bytes32 oracleHash;
        uint64 timeSecond;
        uint32 timeNanoSecondFraction;
    }

    enum ResolveStatus {
        RESOLVE_STATUS_OPEN_UNSPECIFIED,
        RESOLVE_STATUS_SUCCESS,
        RESOLVE_STATUS_FAILURE,
        RESOLVE_STATUS_EXPIRED
    }

    struct Value {
        string clientID;
        uint64 oracleScriptID;
        bytes params;
        uint64 askCount;
        uint64 minCount;
        uint64 requestID;
        uint64 ansCount;
        uint64 requestTime;
        uint64 resolveTime;
        ResolveStatus resolveStatus;
        bytes result;
    }

    struct MultistoreData {
        bytes32 oracleIAVLStateHash; // [C]
        bytes32 paramsStoreMerkleHash; // [D]
        bytes32 slashingToStakingStoresMerkleHash; // [I7]
        bytes32 govToMintStoresMerkleHash; // [I10]
        bytes32 authToFeegrantStoresMerkleHash; // [I12]
        bytes32 transferToUpgradeStoresMerkleHash; // [I15]
    }

    struct BlockHeaderMerkleParts {
        bytes32 versionAndChainIdHash; // [1A]
        uint64 height; // [2]
        uint64 timeSecond; // [3]
        uint32 timeNanoSecondFraction; // between 0 to 10^9 [3]
        bytes32 lastBlockIdAndOther; // [2B]
        bytes32 nextValidatorHashAndConsensusHash; // [1E]
        bytes32 lastResultsHash; // [B]
        bytes32 evidenceAndProposerHash; // [2D]
    }

    struct CommonEncodedVotePartData {
        bytes signedDataPrefix;
        bytes signedDataSuffix;
    }

    struct TMSignatureData {
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes encodedTimestamp;
    }

    struct IAVLMerklePath {
        bool isDataOnRight;
        uint8 subtreeHeight;
        uint256 subtreeSize;
        uint256 subtreeVersion;
        bytes32 siblingHash;
    }

    function init() external {
        // set initial state, validator addresses and weights
    }

    function relayBlock(
        MultistoreData calldata _multiStore,
        BlockHeaderMerkleParts calldata _merkleParts,
        CommonEncodedVotePartData calldata _commonEncodedVotePart,
        TMSignatureData[] calldata _signatures
    ) public {
        // if same data for block height already exists, return

        require(verifyBlockHeader(_multiStore, _merkleParts, _commonEncodedVotePart, _signatures), "Invalid block header");
        blockDetails[_merkleParts.height] = BlockDetail({
            oracleHash: _multiStore.oracleIAVLStateHash,
            timeSecond: _merkleParts.timeSecond,
            timeNanoSecondFraction: _merkleParts.timeNanoSecondFraction
        });
    }
    

    function verifyBlockHeader(
        MultistoreData memory _multiStore,
        BlockHeaderMerkleParts memory _merkleParts,
        CommonEncodedVotePartData memory _commonEncodedVotePart,
        TMSignatureData[] memory _signatures
    ) public view returns(bool) {
        // input block header parts and signatures
        // validate block header
        bytes32 _appHash = getAppHash(_multiStore);
        bytes32 _blockHeader = getBlockHeader(_merkleParts, _appHash);
        bytes memory _commonEncodedPart = checkPartsAndEncodedCommonParts(_commonEncodedVotePart, _blockHeader);

        // load encoded chain id
        bytes memory _encodedChainId = encodedChainId;

        // Tally the total voting power behind the signatures
        address _lastSigner = address(0);
        uint256 _sumVotingPower = 0;
        for (uint256 _i = 0; _i < _signatures.length; _i++) {
            address _signer = checkTimeAndRecoverSigner(_signatures[_i], _commonEncodedPart, _encodedChainId);
            require(_signer > _lastSigner, "Invalid signer order");
            if (validatorPowers[_signer] > 0) {
                _sumVotingPower += validatorPowers[_signer];
            }
            _lastSigner = _signer;
        }
        // Verify that sufficient voting power signed the block
        return _sumVotingPower * 3 >= totalValidatorPower * 2;
    }

    function verifyProof(
        bytes32 _rootHash,
        uint256 _version,
        bytes memory _key,
        bytes32 _dataHash,
        IAVLMerklePath[] memory _merklePaths
    ) internal view returns(bool) {
        bytes memory _encodedVersion = _encodeVarintUnsigned(_version);

        bytes32 _currentMerkleHash = sha256(
            abi.encodePacked(
                uint8(0), // Height of tree (only leaf node) is 0 (signed-varint encode)
                uint8(2), // Size of subtree is 1 (signed-varint encode)
                _encodedVersion,
                uint8(_key.length), // Size of data key
                _key,
                uint8(32), // Size of data hash
                _dataHash
            )
        );

        for (uint256 _i = 0; _i < _merklePaths.length; _i++) {
            _currentMerkleHash = getParentHash(_merklePaths[_i], _currentMerkleHash);
        }

        // verify that calculated merkle root hash equals expected root hash
        return _currentMerkleHash == _rootHash;
    }

    function verifyOracleData(
        uint256 _blockHeight,
        Value calldata _value,
        uint256 _oracleHeight,
        IAVLMerklePath[] calldata _merklePaths
    ) public view returns(Value memory) {
        bytes32 _oracleStateRoot = blockDetails[_blockHeight].oracleHash;
        require(
            _oracleStateRoot != bytes32(0), "No root at this height"
        );

        bytes32 _dataHash = sha256(protoEncode(_value));

        require(
            verifyProof(
                _oracleStateRoot,
                _oracleHeight,
                abi.encodePacked(uint8(255), _value.requestID),
                _dataHash,
                _merklePaths
            ),
            "Invalid proof"
        );

        return _value;
    }

    // ************************************************************ 
    // * internal pure helper functions
    // ************************************************************

    function getBlockHeader(BlockHeaderMerkleParts memory _merkleParts, bytes32 _appHash) public pure returns(bytes32) {
        bytes32 _blockHeader = _merkleInnerHash( // [BlockHeader]
                _merkleInnerHash( // [3A]
                    _merkleInnerHash( // [2A]
                        _merkleParts.versionAndChainIdHash, // [1A]
                        _merkleInnerHash( // [1B]
                            _merkleLeafHash( // [2]
                                abi.encodePacked(
                                    uint8(8),
                                    _encodeVarintUnsigned(_merkleParts.height)
                                )
                            ),
                            _merkleLeafHash( // [3]
                                _encodeTime(
                                    _merkleParts.timeSecond,
                                    _merkleParts.timeNanoSecondFraction
                                )
                            )
                        )
                    ),
                    _merkleParts.lastBlockIdAndOther // [2B]
                ),
                _merkleInnerHash( // [3B]
                    _merkleInnerHash( // [2C]
                        _merkleParts.nextValidatorHashAndConsensusHash, // [1E]
                        _merkleInnerHash( // [1F]
                            _merkleLeafHash( // [A]
                                abi.encodePacked(uint8(10), uint8(32), _appHash)
                            ),
                            _merkleParts.lastResultsHash // [B]
                        )
                    ),
                    _merkleParts.evidenceAndProposerHash // [2D]
                )
            );
        return _blockHeader;
    } 

    function getAppHash(MultistoreData memory _store) internal pure returns(bytes32) {
        bytes32 _appHash = _merkleInnerHash(
            _merkleInnerHash(
                _store.authToFeegrantStoresMerkleHash,
                _merkleInnerHash( 
                    _store.govToMintStoresMerkleHash,
                    _merkleInnerHash(
                        _merkleInnerHash(
                            _merkleLeafHash(
                                abi.encodePacked(
                                        hex"066f7261636c6520", // oracle prefix (uint8(6) + "oracle" + uint8(32)) NOTE: Switch to Tellor Layer oracle prefix
                                        sha256(
                                            abi.encodePacked(
                                                _store.oracleIAVLStateHash
                                            )
                                        )
                                    )
                            ),
                            _store.paramsStoreMerkleHash
                        ),
                        _store.slashingToStakingStoresMerkleHash
                    )
                )
            ),
            _store.transferToUpgradeStoresMerkleHash
        );
        return _appHash;
    }

    function _merkleInnerHash(bytes32 _left, bytes32 _right) internal pure returns(bytes32) {
        return sha256(abi.encodePacked(uint8(1), _left, _right));
    }

    function _merkleLeafHash(bytes memory _value) internal pure returns(bytes32) {
        return sha256(abi.encodePacked(uint8(0), _value));
    }

    /// @dev Returns the upper Merkle hash given a proof component and hash of data subtree.
    /// @param dataSubtreeHash The hash of data subtree up until this point.
    function getParentHash(IAVLMerklePath memory _merklePath, bytes32 dataSubtreeHash)
        internal
        pure
        returns (bytes32)
    {
        (bytes32 leftSubtree, bytes32 rightSubtree) =
            _merklePath.isDataOnRight ? (_merklePath.siblingHash, dataSubtreeHash) : (dataSubtreeHash, _merklePath.siblingHash);
        return
            sha256(
                abi.encodePacked(
                    _merklePath.subtreeHeight << 1, // Tendermint signed-int8 encoding requires multiplying by 2
                    _encodeVarintSigned(_merklePath.subtreeSize),
                    _encodeVarintSigned(_merklePath.subtreeVersion),
                    uint8(32), // Size of left subtree hash
                    leftSubtree,
                    uint8(32), // Size of right subtree hash
                    rightSubtree
                )
            );
    }

    /// @dev Returns the encoded bytes using unsigned varint encoding of the given input.
    function _encodeVarintUnsigned(uint256 _value)
        internal
        pure
        returns (bytes memory)
    {
        // Computes the size of the encoded value.
        uint256 tempValue = _value;
        uint256 size = 0;
        while (tempValue > 0) {
            ++size;
            tempValue >>= 7;
        }
        // Allocates the memory buffer and fills in the encoded value.
        bytes memory result = new bytes(size);
        tempValue = _value;
        for (uint256 idx = 0; idx < size; ++idx) {
            result[idx] = bytes1(uint8(128) | uint8(tempValue & 127));
            tempValue >>= 7;
        }
        result[size - 1] &= bytes1(uint8(127)); // Drop the first bit of the last byte.
        return result;
    }

    /// @dev Returns the encoded bytes using signed varint encoding of the given input.
    function _encodeVarintSigned(uint256 value)
        internal
        pure
        returns (bytes memory)
    {
        return _encodeVarintUnsigned(value * 2);
    }

    /// @dev Returns the encoded bytes following how tendermint encodes time.
    function _encodeTime(uint64 second, uint32 nanoSecond)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result =
            abi.encodePacked(hex"08", _encodeVarintUnsigned(uint256(second)));
        if (nanoSecond > 0) {
            result = abi.encodePacked(
                result,
                hex"10",
                _encodeVarintUnsigned(uint256(nanoSecond))
            );
        }
        return result;
    }

    /// @dev Returns the address that signed on the given block hash.
    /// @param _blockHash The block hash that the validator signed data on.
    function checkPartsAndEncodedCommonParts(CommonEncodedVotePartData memory _votePart, bytes32 _blockHash)
        internal
        pure
        returns (bytes memory)
    {
        // We need to limit the possible size of the prefix and suffix to ensure only one possible block hash.

        // There are only two possible prefix sizes.
        // 1. If Round == 0, the prefix size should be 15 because the encoded Round was cut off.
        // 2. If not then the prefix size should be 24 (15 + 9).
        require(
            _votePart.signedDataPrefix.length == 15 || _votePart.signedDataPrefix.length == 24,
            "CommonEncodedVotePart: Invalid prefix's size"
        );

        // The suffix is encoded of a CanonicalPartSetHeader, which has a fixed size in practical.
        // There are two reasons why.
        // 1. The maximum value of CanonicalPartSetHeader.Total is 48 (3145728 / 65536) because Band's MaxBlockSizeBytes
        // is 3145728 bytes, and the max BlockPartSizeBytes's size is 65536 bytes.
        // 2. The CanonicalPartSetHeader.Hash's size is fixed (32 bytes) because it is a product of SHA256.
        // Therefore, the overall size is fixed.
        require(_votePart.signedDataSuffix.length == 38, "CommonEncodedVotePart: Invalid suffix's size");

        return abi.encodePacked(
            _votePart.signedDataPrefix,
            _blockHash,
            _votePart.signedDataSuffix
        );
    }

    /// @dev Returns the address that signed on the given encoded canonical vote message on Cosmos.
    /// @param _commonEncodedPart The first common part of the encoded canonical vote.
    /// @param _encodedChainID The last part of the encoded canonical vote.
    function checkTimeAndRecoverSigner(TMSignatureData memory _sigData, bytes memory _commonEncodedPart, bytes memory _encodedChainID)
        internal
        pure
        returns (address)
    {
        // We need to limit the possible size of the encodedCanonicalVote to ensure only one possible block hash.
        // The size of the encodedTimestamp will be between 6 and 12 according to the following two constraints.
        // 1. The size of an encoded Unix's second is 6 bytes until over a thousand years in the future.
        // 2. The NanoSecond size can vary from 0 to 6 bytes.
        // Therefore, 6 + 0 <= the size <= 6 + 6.
        require(
            6 <= _sigData.encodedTimestamp.length && _sigData.encodedTimestamp.length <= 12,
            "TMSignature: Invalid timestamp's size"
        );
        bytes memory encodedCanonicalVote = abi.encodePacked(
            _commonEncodedPart,
            uint8(42),
            uint8(_sigData.encodedTimestamp.length),
            _sigData.encodedTimestamp,
            _encodedChainID
        );
        return
            ecrecover(
                sha256(abi.encodePacked(uint8(encodedCanonicalVote.length), encodedCanonicalVote)),
                _sigData.v,
                _sigData.r,
                _sigData.s
            );
    }

    function protoEncode(Value memory instance)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory finalEncoded;

        // Omit encoding clientID if default value
        if (bytes(instance.clientID).length > 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(
                    1,
                    uint64(ProtobufLib.WireType.LengthDelimited)
                ),
                ProtobufLib.encode_uint64(
                    uint64(bytes(instance.clientID).length)
                ),
                bytes(instance.clientID)
            );
        }

        // Omit encoding oracleScriptID if default value
        if (uint64(instance.oracleScriptID) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(2, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_uint64(instance.oracleScriptID)
            );
        }

        // Omit encoding params if default value
        if (bytes(instance.params).length > 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(
                    3,
                    uint64(ProtobufLib.WireType.LengthDelimited)
                ),
                ProtobufLib.encode_uint64(
                    uint64(bytes(instance.params).length)
                ),
                bytes(instance.params)
            );
        }

        // Omit encoding askCount if default value
        if (uint64(instance.askCount) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(4, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_uint64(instance.askCount)
            );
        }

        // Omit encoding minCount if default value
        if (uint64(instance.minCount) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(5, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_uint64(instance.minCount)
            );
        }

        // Omit encoding requestID if default value
        if (uint64(instance.requestID) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(6, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_uint64(instance.requestID)
            );
        }

        // Omit encoding ansCount if default value
        if (uint64(instance.ansCount) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(7, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_uint64(instance.ansCount)
            );
        }

        // Omit encoding requestTime if default value
        if (uint64(instance.requestTime) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(8, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_uint64(instance.requestTime)
            );
        }

        // Omit encoding resolveTime if default value
        if (uint64(instance.resolveTime) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(9, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_uint64(instance.resolveTime)
            );
        }

        // Omit encoding resolveStatus if default value
        if (uint64(instance.resolveStatus) != 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(10, uint64(ProtobufLib.WireType.Varint)),
                ProtobufLib.encode_int32(int32(uint32(instance.resolveStatus)))
            );
        }

        // Omit encoding result if default value
        if (bytes(instance.result).length > 0) {
            finalEncoded = abi.encodePacked(
                finalEncoded,
                ProtobufLib.encode_key(
                    11,
                    uint64(ProtobufLib.WireType.LengthDelimited)
                ),
                ProtobufLib.encode_uint64(
                    uint64(bytes(instance.result).length)
                ),
                bytes(instance.result)
            );
        }

        return finalEncoded;
    }
}