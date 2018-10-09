#include <iostream>
#include <sparsepp/spp.h>
#include <cryptocpp/hex.h>
#include "hash/sph_sha2.h"
#include "hash/sph_keccak.h"
#include "hash/sph_haval.h"
#include "hash/sph_tiger.h"
#include "hash/sph_whirlpool.h"
#include "hash/sph_ripemd.h"
#include "gmp/gmp.h"
#include "base58.h"
#include "utils.h"

#if !(defined(IS_BIG_ENDIAN) || defined(IS_LITTLE_ENDIAN))
    #if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
    (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || \
    defined(__BIG_ENDIAN__) || defined(__ARMEB__) || \
    defined(__THUMBEB__) || defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)
        #define IS_BIG_ENDIAN
    #elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || \
    defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || \
    defined(__THUMBEL__) || defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #define IS_LITTLE_ENDIAN
    #else
        #error "Cannot determine platform endianness"
    #endif
#endif

#if defined(IS_BIG_ENDIAN)
    #error "System must be little endian!"
#endif

#define HEADER_SIZE 122
#define MAX_BLOCK_SIZE 10485760

std::string last_block_hash;

uint64_t blk_count(0);
uint64_t txn_count(0);
uint64_t oblk_count(0);

uint32_t bfile_num(0);
uint64_t bfile_index(0);
uint64_t blocks_processed(0);

Integer inp_total(0L);
Integer out_total(0L);
uint64_t inp_count(0);
uint64_t out_count(0);

spp::sparse_hash_map<std::string, BlockData*> block_hash_map;
spp::sparse_hash_map<std::string, AddrData*> tx_addr_map;
std::vector<spp::sparse_hash_map<std::string, AddrStats>> addr_undo_data;

FILE* bhdb_handle = nullptr;
FILE* ohdb_handle = nullptr;
FILE* bidb_handle = nullptr;
FILE* oidb_handle = nullptr;

uint64_t max_out = uint64_t(1800000000) * uint64_t(10000000000);
bool fork_detected = false;

inline void error_exit(const char* error_txt, uint64_t fail_height)
{
    std::cout << error_txt << "\nBlock height: " << fail_height << std::endl;
    exit(EXIT_FAILURE);
}

inline void get_block_hash(uint64_t index, char* result)
{
    fseek(bhdb_handle, 64*index, SEEK_SET);
    fread(result, 1, 64, bhdb_handle);
}

inline void get_orph_hash(uint64_t index, char* result)
{
    fseek(ohdb_handle, 64*index, SEEK_SET);
    fread(result, 1, 64, ohdb_handle);
}

inline void put_block_hash(uint64_t index, const std::string& hash)
{
    fseek(bhdb_handle, 64*index, SEEK_SET);
    fwrite(hash.c_str(), 1, 64, bhdb_handle);
}

inline void put_orph_hash(uint64_t index, const std::string& hash)
{
    fseek(ohdb_handle, 64*index, SEEK_SET);
    fwrite(hash.c_str(), 1, 64, ohdb_handle);
}

inline void get_block_link(uint64_t index, uint32_t& file_number, uint64_t& file_index)
{
    fseek(bidb_handle, 12*index, SEEK_SET);
    fread(&file_number, 4, 1, bidb_handle);
    fread(&file_index, 8, 1, bidb_handle);
}

inline void put_block_link(uint64_t index, uint32_t file_number, uint64_t file_index)
{
    fseek(bidb_handle, 12*index, SEEK_SET);
    fwrite(&file_number, 4, 1, bidb_handle);
    fwrite(&file_index, 8, 1, bidb_handle);
}

inline void get_orph_link(uint64_t index, char* data)
{
    fseek(oidb_handle, 40*index, SEEK_SET);
    fread(data, 1, 40, oidb_handle);
}

inline void put_orph_link(uint64_t index, const char* data)
{
    fseek(oidb_handle, 40*index, SEEK_SET);
    fwrite(data, 1, 40, oidb_handle);
}

inline void mpz_set_uint512(mpz_t r, uint512& u)
{
    mpz_import(r, 64 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u.data);
}

inline std::string hash160toaddress(const std::string& hash160)
{
    std::string ext_hash160 = std::string(1, 0x1C) + hash160;
    Blob256 sha_hash(SHA_256::HashX2((const byte*)ext_hash160.c_str(), ext_hash160.size()));
    return ext_hash160 + std::string(sha_hash.Bytes(), 4);
}

inline std::string hash160tobase58(const std::string& hash160)
{
    char base58_addr[40];
    size_t addr_len = 40;
    std::string full_addr(hash160toaddress(hash160));
    Base58::Encode(base58_addr, addr_len, full_addr.c_str(), full_addr.size());
    return std::string(base58_addr, addr_len);
}

inline void calc_tx_hash(CTransaction& txn, char* txn_ptr, uint32_t cmp_size)
{
    char compactTxn[cmp_size];
    uint32_t byteIndex = 0;
    uint32_t viSize = 0;

    memcpy(compactTxn, txn_ptr, 4);
    txn_ptr += 4; byteIndex += 4;

    if (txn.fSetLimit) {

        size_t inpCnt = ReadVarInt(txn_ptr, viSize);
        if (inpCnt != 1) throw std::runtime_error("Invalid limit txn (inputs != 1)");
        memcpy(&(compactTxn[byteIndex]), txn_ptr-viSize, viSize);
        byteIndex += viSize;

        memcpy(&(compactTxn[byteIndex]), txn_ptr, 20);
        txn_ptr += 20; byteIndex += 20;
        memcpy(&(compactTxn[byteIndex]), &txn.vin[0].nValue, 8);
        txn_ptr += 8; byteIndex += 8;
        txn_ptr += ReadVarInt(txn_ptr);

        viSize = 0;
        size_t outCnt = ReadVarInt(txn_ptr, viSize);
        if (outCnt != 1) throw std::runtime_error("Invalid limit txn (outputs != 1)");
        memcpy(&(compactTxn[byteIndex]), txn_ptr-viSize, viSize);
        byteIndex += viSize;

        memcpy(&(compactTxn[byteIndex]), &txn.vout[0].nValue, 8);
        txn_ptr += 8; byteIndex += 8;
        memcpy(&(compactTxn[byteIndex]), txn_ptr, 20);
        txn_ptr += 20; byteIndex += 20;

    } else {

        size_t inpCnt = ReadVarInt(txn_ptr, viSize);
        memcpy(&(compactTxn[byteIndex]), txn_ptr-viSize, viSize);
        byteIndex += viSize;

        for (size_t i=0; i < inpCnt; ++i)
        {
            memcpy(&(compactTxn[byteIndex]), txn_ptr, 20);
            txn_ptr += 20; byteIndex += 20;
            memcpy(&(compactTxn[byteIndex]), txn_ptr, 8);
            txn_ptr += 8; byteIndex += 8;
            txn_ptr += ReadVarInt(txn_ptr);
        }

        viSize = 0;
        size_t outCnt = ReadVarInt(txn_ptr, viSize);
        memcpy(&(compactTxn[byteIndex]), txn_ptr-viSize, viSize);
        byteIndex += viSize;

        for (size_t o=0; o < outCnt; ++o)
        {
            memcpy(&(compactTxn[byteIndex]), txn_ptr, 8);
            txn_ptr += 8; byteIndex += 8;
            memcpy(&(compactTxn[byteIndex]), txn_ptr, 20);
            txn_ptr += 20; byteIndex += 20;
        }
    }

    viSize = 0;
    uint32_t msgSize = ReadVarInt(txn_ptr, viSize);
    memcpy(&(compactTxn[byteIndex]), txn_ptr-viSize, viSize);
    memcpy(&(compactTxn[byteIndex+viSize]), txn_ptr-viSize, 8+viSize+msgSize);

    txn.ComputeHash(compactTxn, cmp_size);
}

inline void parse_txns(char* txn_bytes, std::vector<CTransaction>& txn_sink)
{
    uint32_t txnSetSize = 0;
    size_t txnCount = ReadVarInt(txn_bytes, txnSetSize);

    for (size_t t=0; t < txnCount; ++t)
    {
        CTransaction txn;
        char* txnPtr = txn_bytes;
        uint32_t txnSize = 4;
        uint32_t sigsSize = 0;
        uint32_t viSize = 0;
        txn.nVersion = ReadInt32(txn_bytes);

        size_t inpCnt = ReadVarInt(txn_bytes, txnSize);
        for (size_t i=0; i < inpCnt; ++i)
        {
            CTxIn input;
            viSize = 0;
            input.pubKey = ReadHexStr(txn_bytes, 20);
            input.nValue = ReadUInt64(txn_bytes);
            input.scriptSig = ReadString(txn_bytes, viSize);
            txn.vin.push_back(input);
            sigsSize += viSize + input.scriptSig.size();
            txnSize += 28 + viSize + input.scriptSig.size();
        }

        size_t outCnt = ReadVarInt(txn_bytes, txnSize);
        for (size_t o=0; o < outCnt; ++o)
        {
            CTxOut output;
            output.nValue = ReadUInt64(txn_bytes);
            output.pubKey = ReadHexStr(txn_bytes, 20);
            txn.vout.push_back(output);
            txnSize += 28;
        }

        viSize = 0;
        txn.msg = ReadString(txn_bytes, viSize);
        txn.nLockHeight = ReadUInt64(txn_bytes);
        txnSize += 8 + viSize + txn.msg.size();
        txnSetSize += txnSize;

        if (txn.vin.size()==1 && txn.vout.size()==1 && txn.vin[0].pubKey ==
        txn.vout[0].pubKey && txn.vout[0].nValue < txn.vin[0].nValue) {

            txn.fSetLimit = true;
            txn.nLimitValue = txn.vout[0].nValue;
            txn.vin[0].nValue -= txn.nLimitValue;
            txn.vout[0].nValue = 0;
            inp_count++; out_count++;

            calc_tx_hash(txn, txnPtr, txnSize-sigsSize+viSize);

            inp_total += Integer((byte*)&txn.vin[0].nValue, 8,
                        Integer::UNSIGNED, ByteOrder::LITTLE_ENDIAN_ORDER);

            if (!tx_addr_map.contains(txn.vin[0].pubKey))
                tx_addr_map[txn.vin[0].pubKey] = new AddrData();

            tx_addr_map[txn.vin[0].pubKey]->TxnListSS() << txn.GetHash() << ":2\n";
            tx_addr_map[txn.vin[0].pubKey]->stats.inpCnt += 1;
            tx_addr_map[txn.vin[0].pubKey]->stats.inpSum += txn.vin[0].nValue;

        } else {

            calc_tx_hash(txn, txnPtr, txnSize-sigsSize+viSize);

            for (const CTxIn& input : txn.vin)
            {
                if (!tx_addr_map.contains(input.pubKey))
                    tx_addr_map[input.pubKey] = new AddrData();

                tx_addr_map[input.pubKey]->TxnListSS() << txn.GetHash() << ":0\n";
                tx_addr_map[input.pubKey]->stats.inpCnt += 1;
                tx_addr_map[input.pubKey]->stats.inpSum += input.nValue;
                inp_total += Integer((byte*)&input.nValue, 8,
                            Integer::UNSIGNED, ByteOrder::LITTLE_ENDIAN_ORDER);
                inp_count++;
            }

            for (const CTxOut& output : txn.vout)
            {
                if (!tx_addr_map.contains(output.pubKey))
                    tx_addr_map[output.pubKey] = new AddrData();

                tx_addr_map[output.pubKey]->TxnListSS() << txn.GetHash() << ":1\n";
                tx_addr_map[output.pubKey]->stats.outCnt += 1;
                out_count++;

                if (!(output.nValue > max_out)) {
                    tx_addr_map[output.pubKey]->stats.outSum += output.nValue;
                    out_total += Integer((byte*)&output.nValue, 8,
                                 Integer::UNSIGNED, ByteOrder::LITTLE_ENDIAN_ORDER);

                }
            }
        }

        txn_sink.push_back(txn);
    }
}

inline uint256 hash_header(const void* hdr_bytes, size_t hdr_size)
{
    sph_sha256_context       ctx_sha256;
    sph_sha512_context       ctx_sha512;
    sph_keccak512_context    ctx_keccak;
    sph_whirlpool_context    ctx_whirlpool;
    sph_haval256_5_context   ctx_haval;
    sph_tiger_context        ctx_tiger;
    sph_ripemd160_context    ctx_ripemd;

    uint512 hash[7];
    uint256 finalhash;

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hdr_bytes, hdr_size);
    sph_sha256_close(&ctx_sha256, &hash[0]);

    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hdr_bytes, hdr_size);
    sph_sha512_close(&ctx_sha512, &hash[1]);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hdr_bytes, hdr_size);
    sph_keccak512_close(&ctx_keccak, &hash[2]);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hdr_bytes, hdr_size);
    sph_whirlpool_close(&ctx_whirlpool, &hash[3]);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hdr_bytes, hdr_size);
    sph_haval256_5_close(&ctx_haval, &hash[4]);

    sph_tiger_init(&ctx_tiger);
    sph_tiger(&ctx_tiger, hdr_bytes, hdr_size);
    sph_tiger_close(&ctx_tiger, &hash[5]);

    sph_ripemd160_init(&ctx_ripemd);
    sph_ripemd160(&ctx_ripemd, hdr_bytes, hdr_size);
    sph_ripemd160_close(&ctx_ripemd, &hash[6]);

    mpz_t bns[7];

    for (int i=0; i < 7; i++)
    {
        /*bool all_zeros = true;

        for (int b=0; b < 64; ++b) {
            if (hash[i].data[b] != 0) {
                all_zeros = false;
                break;
            }
        }

        if (all_zeros) hash[i].data[63] = 1;*/

        mpz_init(bns[i]);
        mpz_set_uint512(bns[i], hash[i]);
    }

    mpz_t product;
    mpz_init(product);
    mpz_set_ui(product, 1);

    for (int i=0; i < 7; i++) {
        mpz_mul(product, product, bns[i]);
    }

    int bytes = mpz_sizeinbase(product, 256);
    char *data = (char*)malloc(bytes);
    mpz_export(data, NULL, -1, 1, 0, 0, product);

    for (int i=0; i < 7; i++) {
        mpz_clear(bns[i]);
    }
    mpz_clear(product);

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, data,bytes);
    sph_sha256_close(&ctx_sha256, &finalhash);

    free(data);
    return finalhash;
}

std::string read_block_files(std::string block_folder)
{
    uint32_t magic_bytes = 0xd9b4bef9;
    uint32_t blast_num = bfile_num;
    uint64_t block_index = bfile_index;
    uint32_t block_size = 0;
    uint64_t block_count = 0;
    std::string block_hash;

    while (true)
    {
        if (blast_num != bfile_num) {
            blast_num = bfile_num;
            bfile_index = 0;
        }

        std::stringstream ss;
        ss << bfile_num++;
        std::string int_str(5-ss.str().size(), '0');
        int_str.append(ss.str());

        std::string file_name = block_folder+"/blk"+int_str+".dat";
        FILE* pFile = fopen(file_name.c_str(), "rb");

        if (pFile != NULL) {

            fseek(pFile, bfile_index, SEEK_SET);
            std::cout << "Reading " << file_name << std::endl;

            while (true)
            {
                bool magic_found = false;
                uint32_t magic_bbuff = 0;
                int32_t empty_space = 0;

                //scan file for magic bytes
                while (fread(&magic_bbuff, 1, 4, pFile) == 4)
                {
                    if (magic_bbuff == magic_bytes) {
                        magic_found = true;
                        ++block_count;
                        bfile_index += 4;
                        break;
                    } else {
                        fseek(pFile, -3, SEEK_CUR);
                        bfile_index++;
                        if (empty_space++ > 1025) {
                            break;
                        }
                    }
                }

                //no more magic, probably at end of file
                if (!magic_found) { break; }

                //get block size and check it
                fread(&block_size, 1, 4, pFile);
                if (block_size < HEADER_SIZE || block_size > MAX_BLOCK_SIZE) {
                    std::cout << "Incomplete block read detected, stopping ..." << std::endl;
                    exit(EXIT_SUCCESS);
                }

                //read data into block buffer
                BlockData* block_data = new BlockData();
                block_data->fileNumber = blast_num;
                block_data->fileIndex = bfile_index - 4;
                block_data->bytes = new char[block_size];
                char* block_buff = block_data->bytes;
                fread(block_buff, 1, block_size, pFile);

                BBUInt16 verNumber(&(block_buff[0]));
                BBUInt64 timeStamp(&(block_buff[98]));
                BBUInt64 blkHeight(&(block_buff[106]));
                BBUInt64 randNonce(&(block_buff[114]));

                CBlockHeader& block_hdr = block_data->header;
                block_hdr.hashPrevBlock.Set(&(block_buff[2]));
                block_hdr.hashMerkleRoot.Set(&(block_buff[34]));
                block_hdr.hashAccountRoot.Set(&(block_buff[66]));
                block_hdr.nTime = timeStamp.value;
                block_hdr.nHeight = blkHeight.value;
                block_hdr.nNonce = randNonce.value;
                block_hdr.nVersion = verNumber.value;

                if (block_hdr.nVersion == 0) {
                    std::cout << "Incomplete block read detected, stopping ..." << std::endl;
                    exit(EXIT_SUCCESS);
                }

                uint256 hash_bytes(hash_header(block_hdr.hashPrevBlock.data, HEADER_SIZE));
                block_hash.assign(hash_bytes.data, 32);
                block_hash_map[block_hash] = block_data;

                bfile_index += 4 + block_size;
                block_index = bfile_index;
            }

        } else {
            bfile_index = block_index;
            bfile_num -= 2;
            if (blast_num == 0) {
                std::cout << "Block files not found!" << std::endl;
                exit(EXIT_FAILURE);
            }
            break;
        }

        fclose(pFile);
    }

    std::cout << "Blocks processed: " + IntToStr(block_count) << std::endl;
    blocks_processed = block_count;

    return block_hash;
}

std::vector<BlockData*> build_chain_links()
{
    std::cout << "Building chain links ..." << std::endl;
    std::vector<BlockData*> chain_links;
    BlockData* last_block = block_hash_map[last_block_hash];
    std::string zero_str32(32, 0);
    uint64_t block_count = 0;

    while (true)
    {
        ++block_count;
        last_block->isOrphan = false;
        std::string prev_hash(last_block->header.hashPrevBlock.data, 32);
        chain_links.push_back(last_block);
        if (prev_hash == zero_str32) break;
        last_block = block_hash_map[prev_hash];
    }

    std::cout << "Blocks linked: " << block_count << std::endl;
    std::reverse(chain_links.begin(), chain_links.end());
    return chain_links;
}

std::vector<BlockData*> build_block_links(const std::string last_hash, std::string db_dir)
{
    std::cout << "Building block links ..." << std::endl;
    std::vector<BlockData*> chain_links;
    BlockData* last_block = block_hash_map[last_block_hash];
    uint64_t block_count = 0;

    while (true)
    {
        ++block_count;
        last_block->isOrphan = false;
        std::string prev_hash(last_block->header.hashPrevBlock.data, 32);
        chain_links.push_back(last_block);

        if (prev_hash == last_hash) {
            break;
        } else if (block_hash_map.contains(prev_hash)) {
            last_block = block_hash_map[prev_hash];
        } else {

            fork_detected = true;

            if (chain_links.size() > 9) {
                if ((chain_links.size() / double(blocks_processed)) < 0.5) {
                    std::cout << "Linked wrong blocks, exiting ..." << std::endl;
                    exit(EXIT_SUCCESS);
                }
                std::cout << "Fork detected, locating origin ..." << std::endl;
            } else {
                std::cout << "Fork detected, ignoring for now ..." << std::endl;
                exit(EXIT_SUCCESS);
            }

            std::string bhdb_file(db_dir + "bhashes");
            std::string ohdb_file(db_dir + "ohashes");
            std::string oidb_file(db_dir + "ohlinks");

            bhdb_handle = fopen(bhdb_file.c_str(), "r+");
            ohdb_handle = fopen(ohdb_file.c_str(), "r+");
            oidb_handle = fopen(oidb_file.c_str(), "r+");

            std::string orig_hash(prev_hash);
            uint64_t lHeightIndex = 0;
            uint64_t undo_count = 0;
            char tmp_bytes[64];
            bool undo_error = false;
            bool done = false;

            while (true)
            {
                //TODO: remove revived orphans from ohashes and ohlinks, oblk_count--
                done = false;

                for (uint64_t i=oblk_count; i > 0; --i)
                {
                    get_orph_hash(i-1, tmp_bytes);

                    if (HexDecode(tmp_bytes, 64) == prev_hash) {
                        get_orph_link(i-1, tmp_bytes);
                        prev_hash.assign(tmp_bytes, 32);
                        memcpy(&lHeightIndex, &(tmp_bytes[32]), 8);
                        if (lHeightIndex < 10) {
                            std::cout << "Error: invalid orphan link height!" << std::endl;
                            exit(EXIT_FAILURE);
                        }
                        done = true;
                        break;
                    }
                }

                if (!done) break;

                get_block_hash(lHeightIndex-1, tmp_bytes);

                if (HexDecode(tmp_bytes, 64) == prev_hash) {
                    std::cout << "Found origin via orphan chain ..." << std::endl;
                    last_block_hash = prev_hash;
                    std::string bidb_file(db_dir + "bilinks");
                    bidb_handle = fopen(bidb_file.c_str(), "r+");
                    get_block_link(lHeightIndex-9, bfile_num, bfile_index);
                    fclose(bidb_handle);
                    break;
                }
            }

            if (!done) {

                for (lHeightIndex=blk_count; undo_count++ < 10000 && lHeightIndex > 9;)
                {
                    get_block_hash(--lHeightIndex, tmp_bytes);

                    if (HexDecode(tmp_bytes, 64) == orig_hash) {
                        std::cout << "Found origin via main chain ..." << std::endl;
                        get_block_hash(lHeightIndex-1, tmp_bytes);
                        last_block_hash = HexDecode(tmp_bytes, 64);
                        std::string bidb_file(db_dir + "bilinks");
                        bidb_handle = fopen(bidb_file.c_str(), "r+");
                        get_block_link(lHeightIndex-9, bfile_num, bfile_index);
                        fclose(bidb_handle);
                        done = true;
                        break;
                    }
                }

                if (!done) {
                    std::cout << "Error: unable to locate fork origin!" << std::endl;
                    exit(EXIT_FAILURE);
                }
            }

            std::cout << "Fork origin at height " << lHeightIndex << ", undoing blocks ..." << std::endl;

            for (uint64_t i=lHeightIndex; i < blk_count; ++i)
            {
                std::string undo_str(ReadFileStr(db_dir+"undo/b"+IntToStr(i)));
                TrimStrEnd(undo_str, "/");

                if (undo_str.empty()) {
                    std::cout << "Couldn't read undo file for block " << i << std::endl;
                    undo_error = true;
                    break;
                } else {
                    std::vector<std::string> undo_chunks(Tokenize(undo_str, '|'));
                    std::vector<std::string> undo_dat(Tokenize(undo_chunks[0], ':'));
                    std::vector<std::string> uadr_chunks(Tokenize(undo_chunks[1], '/'));

                    txn_count -= stoull(undo_dat[0]);
                    inp_count -= stoull(undo_dat[1]);
                    out_count -= stoull(undo_dat[2]);
                    inp_total -= Integer(undo_dat[3].c_str());
                    out_total -= Integer(undo_dat[4].c_str());

                    for (const std::string& chunk : uadr_chunks)
                    {
                        if (!chunk.empty()) {

                            std::vector<std::string> uadr_dat(Tokenize(chunk, ':'));

                            std::string sub_str(&(uadr_dat[0][1]), 2);
                            std::transform(sub_str.begin(), sub_str.end(), sub_str.begin(), ::tolower);
                            std::string sub_dir(db_dir + "txs/" + sub_str);
                            std::string adb_file(sub_dir + "/" + uadr_dat[0]);
                            std::string ast_file(adb_file + "-stats");

                            std::string ast_str(ReadFileStr(ast_file));
                            std::ofstream ast_ofs(ast_file, std::ofstream::trunc);

                            if (ast_ofs.is_open() && !ast_str.empty()) {

                                    std::vector<std::string> astats(Tokenize(ast_str, ':'));
                                    uint64_t isum = stoull(astats[0]) - stoull(uadr_dat[1]);
                                    uint64_t osum = stoull(astats[1]) - stoull(uadr_dat[2]);
                                    uint64_t icnt = stoull(astats[2]) - stoull(uadr_dat[3]);
                                    uint64_t ocnt = stoull(astats[3]) - stoull(uadr_dat[4]);

                                    ast_ofs << isum << ":" << osum << ":" << icnt << ":" << ocnt;
                                    ast_ofs.close();

                            } else {
                                std::cout << "Missing address stat file: " << ast_file << std::endl;
                                undo_error = true;
                                break;
                            }
                        }
                    }
                }
            }

            fclose(bhdb_handle);
            fclose(ohdb_handle);
            fclose(oidb_handle);

            if (undo_error) {
                std::cout << "ERROR: unable to process fork!" << std::endl;
                exit(EXIT_FAILURE);
            }

            break;
        }
    }

    std::cout << "Blocks linked: " << block_count << std::endl;
    std::reverse(chain_links.begin(), chain_links.end());
    return chain_links;
}

void parse_blockchain(std::vector<BlockData*>& blocks)
{
    std::cout << "Parsing blockchain ..." << std::endl;
    blk_count = blocks[blocks.size()-1]->header.nHeight + 1;

    for (size_t i=0; i < blocks.size(); ++i)
    {
        BlockData& block_data = *(blocks[i]);
        CBlock block(block_data.header);

        if (block.nHeight != i) {
            std::stringstream ss;
            ss << "Error: invalid block height (" << i << ")";
            error_exit(ss.str().c_str(), block.nHeight);
        }

        parse_txns(&(block_data.bytes[HEADER_SIZE]), block.vtx);
        txn_count += block.vtx.size();
    }
}

void parse_blocks(std::vector<BlockData*>& blocks)
{
    std::cout << "Parsing new block(s) ..." << std::endl;
    uint64_t bdv_size = blocks.size();
    blk_count = blocks[bdv_size-1]->header.nHeight + 1;
    addr_undo_data.resize(bdv_size);

    for (size_t i=0; i < bdv_size; ++i)
    {
        BlockData& block_data = *(blocks[i]);
        CBlock block(block_data.header);

        parse_txns(&(block_data.bytes[HEADER_SIZE]), block.vtx);
        txn_count += block.vtx.size();

        for (const CTransaction& txn: block.vtx)
        {
            if (!txn.fSetLimit) {

                for (const CTxIn& input : txn.vin)
                {
                    block_data.inpTotal += input.nValue;
                    if (addr_undo_data[i].contains(input.pubKey)) {
                        addr_undo_data[i][input.pubKey].inpCnt += 1;
                        addr_undo_data[i][input.pubKey].inpSum += input.nValue;
                    } else {
                        addr_undo_data[i][input.pubKey].inpCnt = 1;
                        addr_undo_data[i][input.pubKey].inpSum = input.nValue;
                    }
                }

                for (const CTxOut& output : txn.vout)
                {
                    if (!(output.nValue > max_out)) {
                        block_data.outTotal += output.nValue;
                    }
                    if (addr_undo_data[i].contains(output.pubKey)) {
                        addr_undo_data[i][output.pubKey].outCnt += 1;
                        addr_undo_data[i][output.pubKey].outSum += output.nValue;
                    } else {
                        addr_undo_data[i][output.pubKey].outCnt = 1;
                        addr_undo_data[i][output.pubKey].outSum = output.nValue;
                    }
                }
            }

            block_data.inpCount += txn.vin.size();
            block_data.outCount += txn.vout.size();
        }

        block_data.txnCount = block.vtx.size();
    }
}

void build_rich_list(std::vector<std::pair<uint64_t, std::string>>& rich_list)
{
    std::cout << "Computing rich list ..." << std::endl;
    std::string zero_str32(20, 0);

    for (const auto& item : tx_addr_map)
    {
        AddrData& addr_data(*item.second);

        if (addr_data.stats.inpSum > addr_data.stats.outSum) {
            if (item.first == zero_str32) {
                continue;
            } else {
                std::string address(HexEncode(item.first));
                throw std::runtime_error("Invalid balance found for "+address);
            }
        }

        rich_list.emplace_back(addr_data.stats.outSum-addr_data.stats.inpSum, item.first);
    }

    std::sort(rich_list.begin(), rich_list.end(),
        [](const std::pair<uint64_t, std::string> &a, const std::pair<uint64_t, std::string> &b) {
            return a.first > b.first;
        }
    );
}

void save_rich_list(const std::string db_dir, const std::vector<std::pair<uint64_t, std::string>>& rich_list, uint32_t limit=1000)
{
    std::cout << "Saving rich list ..." << std::endl;
    std::stringstream rich_list_ss;

    if (rich_list.size() < limit) limit = rich_list.size();

    for (uint32_t i=0; i < limit; ++i)
    {
        rich_list_ss << hash160tobase58(rich_list[i].second) << ":" << rich_list[i].first << "\n";
    }

    std::string rl_file(db_dir+"rich_list");
    std::ofstream rl_ofs(rl_file, std::ofstream::trunc);

    if (rl_ofs.is_open()) {
        rl_ofs << rich_list_ss.rdbuf();
        rl_ofs.close();
    } else {
        throw std::runtime_error("Unable to create file: "+rl_file);
    }
}

void save_undo_data(const std::vector<BlockData*>& blocks, const std::string db_dir)
{
    std::cout << "Saving undo data ..." << std::endl;

    for (size_t i=0; i < blocks.size(); ++i)
    {
        BlockData* bdat(blocks[i]);

        std::stringstream undo_ss;
        undo_ss << bdat->txnCount << ":" << bdat->inpCount << ":" << bdat->outCount
            << ":" << bdat->inpTotal << ":" << bdat->outTotal << "|";

        for (const auto& data : addr_undo_data[i])
        {
            undo_ss << hash160tobase58(data.first) << ":" << data.second.inpSum << ":" <<
                data.second.outSum << ":" << data.second.inpCnt << ":" << data.second.outCnt << "/";
        }

        std::string undo_file(db_dir+"undo/b"+IntToStr(bdat->header.nHeight));
        std::ofstream undo_ofs(undo_file, std::ofstream::trunc | std::ios::binary);

        if (undo_ofs.is_open()) {
            undo_ofs << undo_ss.rdbuf();
            undo_ofs.close();
        } else {
            throw std::runtime_error("Unable to create file: "+undo_file);
        }
    }
}

void update_hash_lists(const std::string db_dir)
{
    std::cout << "Updating hash lists ..." << std::endl;

    std::string bhdb_file(db_dir + "bhashes");
    std::string ohdb_file(db_dir + "ohashes");
    std::string bidb_file(db_dir + "bilinks");
    std::string oidb_file(db_dir + "ohlinks");
    bhdb_handle = fopen(bhdb_file.c_str(), "r+");
    ohdb_handle = fopen(ohdb_file.c_str(), "r+");
    bidb_handle = fopen(bidb_file.c_str(), "r+");
    oidb_handle = fopen(oidb_file.c_str(), "r+");
    char temp_odat[40];

    for (const auto& item: block_hash_map)
    {
        if (item.second->isOrphan) {
            memcpy(temp_odat, item.second->header.hashPrevBlock.data, 32);
            memcpy(&(temp_odat[32]), &(item.second->header.nHeight), 8);
            put_orph_hash(oblk_count, HexEncode(item.first));
            put_orph_link(oblk_count++, temp_odat);
        } else {
            uint64_t& blk_index(item.second->header.nHeight);
            put_block_hash(blk_index, HexEncode(item.first));
            put_block_link(blk_index, item.second->fileNumber, item.second->fileIndex);
        }
    }

    fclose(bhdb_handle);
    fclose(ohdb_handle);
    fclose(bidb_handle);
    fclose(oidb_handle);
}

void update_db_files(const std::string& db_dir)
{
    std::cout << "Updating db files ..." << std::endl;

    for (const auto& item: tx_addr_map)
    {
        std::string address(hash160tobase58(item.first));
        std::string sub_str(&(address[1]), 2);
        std::transform(sub_str.begin(), sub_str.end(), sub_str.begin(), ::tolower);
        std::string sub_dir(db_dir + "txs/" + sub_str);
        std::string adb_file(sub_dir + "/" + address);
        std::string ast_file(adb_file + "-stats");

        if (!DirExists(sub_dir)) {
            if (!CreateDir(sub_dir)) {
                throw std::runtime_error("Unable to create folder: "+sub_dir);
            }
        }

        std::ofstream adb_ofs(adb_file, std::ofstream::app | std::ios::binary);
        if (adb_ofs.is_open()) {
            adb_ofs << item.second->TxnListSS().rdbuf();
            adb_ofs.close();
        } else {
            throw std::runtime_error("Unable to create db file: "+adb_file);
        }

        std::string ast_str(ReadFileStr(ast_file));
        std::ofstream ast_ofs(ast_file, std::ofstream::trunc);
        if (ast_ofs.is_open()) {
            AddrStats& addr_stats(item.second->stats);
            if (!ast_str.empty()) {
                std::vector<std::string> astats(Tokenize(ast_str, ':'));
                addr_stats.inpSum += stoull(astats[0]);
                addr_stats.outSum += stoull(astats[1]);
                addr_stats.inpCnt += stoull(astats[2]);
                addr_stats.outCnt += stoull(astats[3]);
            }
            ast_ofs << addr_stats.inpSum << ":" << addr_stats.outSum
                    << ":" << addr_stats.inpCnt << ":" << addr_stats.outCnt;
            ast_ofs.close();
        } else {
            throw std::runtime_error("Unable to create db file: "+ast_file);
        }
    }

    std::stringstream ss;
    ss << inp_count << ":" << out_count << ":" << inp_total << ":" << out_total;
    std::string dat_str = DelCharInStr(ss.str(), '.');
    std::ofstream sdt_ofs(db_dir+"stat_dat", std::ofstream::trunc);
    if (sdt_ofs.is_open()) {
        sdt_ofs << dat_str;
        sdt_ofs.close();
    } else {
        throw std::runtime_error("Unable to create db file: "+db_dir+"stat_dat");
    }

    std::ofstream ldt_ofs(db_dir+"last_dat", std::ofstream::trunc);
    if (ldt_ofs.is_open()) {
        ldt_ofs << blk_count << ":" << txn_count << ":" << oblk_count;
        ldt_ofs.close();
    } else {
        throw std::runtime_error("Unable to create db file: "+db_dir+"last_dat");
    }

    std::ofstream bdt_ofs(db_dir+"block_dat", std::ios::trunc);
    if (bdt_ofs.is_open()) {
        bdt_ofs << bfile_num << ":" << bfile_index << ":" << HexEncode(last_block_hash);
        bdt_ofs.close();
    } else {
        throw std::runtime_error("Unable to create db file: "+db_dir+"block_dat");
    }
}

void save_db_files(const std::string& db_dir)
{
    std::cout << "Writing db files ..." << std::endl;

    for (const auto& item: tx_addr_map)
    {
        std::string address(hash160tobase58(item.first));
        std::string sub_str(&(address[1]), 2);
        std::transform(sub_str.begin(), sub_str.end(), sub_str.begin(), ::tolower);
        std::string sub_dir(db_dir + "txs/" + sub_str);
        std::string adb_file(sub_dir + "/" + address);
        std::string ast_file(adb_file + "-stats");

        if (!DirExists(sub_dir)) {
            if (!CreateDir(sub_dir)) {
                throw std::runtime_error("Unable to create folder: "+sub_dir);
            }
        }

        std::ofstream adb_ofs(adb_file, std::ofstream::trunc | std::ios::binary);
        if (adb_ofs.is_open()) {
            adb_ofs << item.second->TxnListSS().rdbuf();
            adb_ofs.close();
        } else {
            throw std::runtime_error("Unable to create db file: "+adb_file);
        }

        std::ofstream ast_ofs(ast_file, std::ofstream::trunc);
        if (ast_ofs.is_open()) {
            AddrStats& addr_stats(item.second->stats);
            ast_ofs << addr_stats.inpSum << ":" << addr_stats.outSum
                    << ":" << addr_stats.inpCnt << ":" << addr_stats.outCnt;
            ast_ofs.close();
        } else {
            throw std::runtime_error("Unable to create db file: "+ast_file);
        }
    }

    std::stringstream ss;
    ss << inp_count << ":" << out_count << ":" << inp_total << ":" << out_total;
    std::string dat_str = DelCharInStr(ss.str(), '.');
    std::ofstream sdt_ofs(db_dir+"stat_dat", std::ofstream::trunc);
    if (sdt_ofs.is_open()) {
        sdt_ofs << dat_str;
        sdt_ofs.close();
    } else {
        throw std::runtime_error("Unable to create db file: "+db_dir+"stat_dat");
    }

    std::ofstream ldt_ofs(db_dir+"last_dat", std::ofstream::trunc);
    if (ldt_ofs.is_open()) {
        ldt_ofs << blk_count << ":" << txn_count << ":" << oblk_count;
        ldt_ofs.close();
    } else {
        throw std::runtime_error("Unable to create db file: "+db_dir+"last_dat");
    }

    std::ofstream bdt_ofs(db_dir+"block_dat", std::ios::trunc);
    if (bdt_ofs.is_open()) {
        bdt_ofs << bfile_num << ":" << bfile_index << ":" << HexEncode(last_block_hash);
        bdt_ofs.close();
    } else {
        throw std::runtime_error("Unable to create db file: "+db_dir+"block_dat");
    }
}

void create_db_dirs(const std::string db_dir)
{
    std::string txnsDir = db_dir + "txs/";
    std::string undoDir = db_dir + "undo/";
    std::string bhFile = db_dir + "bhashes";
    std::string ohFile = db_dir + "ohashes";
    std::string blFile = db_dir + "bilinks";
    std::string olFile = db_dir + "ohlinks";

    if (!DirExists(db_dir)) {
        if (!CreateDir(db_dir)) {
            throw std::runtime_error("Unable to create folder: "+db_dir);
        }
    }

    if (!DirExists(txnsDir)) {
        if (!CreateDir(txnsDir)) {
            throw std::runtime_error("Unable to create folder: "+txnsDir);
        }
    }

    if (!DirExists(undoDir)) {
        if (!CreateDir(undoDir)) {
            throw std::runtime_error("Unable to create folder: "+undoDir);
        }
    }

    if (!FileExists(bhFile)) {
        if (!CreateFile(bhFile)) {
            throw std::runtime_error("Unable to create file: "+bhFile);
        }
    }

    if (!FileExists(ohFile)) {
        if (!CreateFile(ohFile)) {
            throw std::runtime_error("Unable to create file: "+ohFile);
        }
    }

    if (!FileExists(blFile)) {
        if (!CreateFile(blFile)) {
            throw std::runtime_error("Unable to create file: "+blFile);
        }
    }

    if (!FileExists(olFile)) {
        if (!CreateFile(olFile)) {
            throw std::runtime_error("Unable to create file: "+olFile);
        }
    }
}

int main(int argc, char *argv[])
{
    std::cout << "Starting ..." << std::endl;

    std::string parser_mode;
    std::string block_folder;
    std::string db_folder = "./db/";

    if (argc > 2) {
        parser_mode.assign(argv[1]);
        block_folder.assign(argv[2]);
        TrimStrEnd(block_folder, "/\\");
    } else {
        std::cout << "Missing arguments!" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (argc > 3) db_folder.assign(argv[3]);

    if (parser_mode == "-firstrun") {

        if (FileExists(db_folder+"block_dat")) {
            std::cout << "Database files already exist!" << std::endl;
        } else {
            create_db_dirs(db_folder);
            last_block_hash = read_block_files(block_folder);
            std::vector<BlockData*> block_chain(build_chain_links());
            parse_blockchain(block_chain);
            update_hash_lists(db_folder);
            save_db_files(db_folder);
        }

    } else if (parser_mode == "-update") {

        std::string sdat_str = ReadFileStr(db_folder+"stat_dat");
        std::string ldat_str = ReadFileStr(db_folder+"last_dat");
        std::string bdat_str = ReadFileStr(db_folder+"block_dat");
        std::vector<std::string> stat_dat(Tokenize(sdat_str, ':'));
        std::vector<std::string> last_dat(Tokenize(ldat_str, ':'));
        std::vector<std::string> block_dat(Tokenize(bdat_str, ':'));

        if (stat_dat.size() != 4 || last_dat.size() < 3 || block_dat.size() != 3) {
            throw std::runtime_error("Corrupted data files detected!");
        }

        inp_count = stoull(stat_dat[0]);
        out_count = stoull(stat_dat[1]);
        inp_total = Integer(stat_dat[2].c_str());
        out_total = Integer(stat_dat[3].c_str());

        blk_count = stoull(last_dat[0]);
        txn_count = stoull(last_dat[1]);
        oblk_count = stoull(last_dat[2]);

        bfile_num = stoul(block_dat[0]);
        bfile_index = stoull(block_dat[1]);
        std::string lbh(HexDecode(block_dat[2]));

        last_block_hash = read_block_files(block_folder);

        if (last_block_hash.empty()) {
            std::cout << "No new blocks found." << std::endl;
        } else {

            std::vector<BlockData*> block_chain(build_block_links(lbh, db_folder));

            if (fork_detected) {
                fork_detected = false;
                lbh = last_block_hash;
                block_hash_map.clear();
                last_block_hash = read_block_files(block_folder);
                block_chain = build_block_links(lbh, db_folder);
                if (fork_detected) {
                    throw std::runtime_error("Failed to recover from fork!");
                }
            }

            parse_blocks(block_chain);
            save_undo_data(block_chain, db_folder);
            update_hash_lists(db_folder);
            update_db_files(db_folder);
        }

    } else if (parser_mode == "-richlist") {

        last_block_hash = read_block_files(block_folder);
        std::vector<BlockData*> block_chain(build_chain_links());
        parse_blockchain(block_chain);

        std::vector<std::pair<uint64_t, std::string>> rich_list;
        rich_list.reserve(block_chain.size());
        build_rich_list(rich_list);
        save_rich_list(db_folder, rich_list);

    } else {
        throw std::runtime_error("Invalid operation mode specified!");
    }

    std::cout << "Finished!";
    return EXIT_SUCCESS;
}
