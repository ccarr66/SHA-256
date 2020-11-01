#define DEBUG_MACHINE 

#ifdef DEBUG_MACHINE
    #include <iostream>
    #include <iomanip>
#endif

#include <algorithm>
#include <memory>
#include <climits>
#include <cstring>


class SHA256
{
public:
    using word_ty = uint32_t;
    using bitLen_ty = size_t;

    static constexpr bitLen_ty byteLen = CHAR_BIT;
    static constexpr bitLen_ty blockLen = 512;
    static constexpr size_t wordLenInByte = sizeof(word_ty);
    static constexpr bitLen_ty wordLen = byteLen * wordLenInByte;
    static constexpr size_t blockLenInWord = blockLen / wordLen;

    static constexpr bitLen_ty endMarkerLen = 64;
    static constexpr size_t endMarkerLenInWord = endMarkerLen / wordLen;

    using block_ty = word_ty[blockLenInWord];

    word_ty resultHashValues[8];

    static_assert(blockLen % wordLen == 0); 
    static_assert(endMarkerLen % wordLen == 0); 

    static constexpr bool isBigEndian()
    {
        const auto testVal = uint32_t{0x89ABCDEF};
        const auto mostSigByte  = uint8_t {(testVal & 0xff000000) >> 24};
        const auto leastSigByte  = uint8_t {testVal & 0xff};
        const auto byteRef = (const uint8_t&)testVal;

        if(byteRef == mostSigByte)
            return true;
        else if (byteRef == leastSigByte)
            return false;
        else
            throw; //this causes compilation to fail bc it's in constexpr context
    }
    
private:
    
    class blockCont
    {
    public:
        size_t len{0};
        std::unique_ptr<block_ty[]> blockArr;

        block_ty& operator[](size_t i) { return blockArr[i];}
        block_ty& last() {return blockArr[len - 1];}

        block_ty * begin() { return &(blockArr[0]);}; 
        block_ty const* begin() const { return &(blockArr[0]);}; 
        block_ty * end() { return &(blockArr[len]);}; 
        block_ty const* end() const { return &(blockArr[len]);}; 

        blockCont(size_t len) : len(len), blockArr(std::make_unique<block_ty[]>(len)) {}

#ifdef DEBUG_MACHINE
        void print(void) 
        {
            std::cout << "\n";
            for(const auto& block : *this) 
            {
                std::cout << "\n0x";
                for(const auto& word : block)
                    std::cout << std::setfill('0') << std::setw(wordLenInByte * 2) << std::hex << word;
            }
        }
        void printBits(void) 
        {
            std::cout << "\n";
            for(const auto& block : *this) 
            {
                std::cout << '\n';
                auto printWord = [](word_ty c) {
                    std::cout << ' ';
                    for(size_t i = 0; i < wordLen; i++) {
                        if(c & (1 << (wordLen - 1 - i)))
                            std::cout << "1";
                        else
                            std::cout << "0";
                    }
                };
                std::for_each(std::begin(block), std::end(block), printWord);
            }
        }
#else
        std::unique_ptr<char[]> printBlocksHex(void) 
        {
            const auto retStrLen = this->len * wordLenInByte + 1;
            auto retStr = std::make_unique<char[]>(retStrLen);
            auto retStrRef = retStr.get(); 
            for(const auto& block : *this) 
            {
                for(const auto& word : block)
                {
                    auto charPtrToWord = reinterpret_cast<const char*>(&word);
                    for(size_t byteIdx = 0; byteIdx < wordLenInByte; byteIdx++)
                        *retStrRef++ = *(charPtrToWord + byteIdx);
                }
            }
            retStrRef[retStrLen - 1] = '\0';
            return retStr;
        }
        
        std::unique_ptr<char[]> printBits(void) 
        {
            const auto retStrLen = this->len * wordLenInByte * byteLen + 1;
            auto retStr = std::make_unique<char[]>(retStrLen);
            auto retStrRef = retStr.get(); 

            auto wordToBits = [](word_ty c, char* &retStrPos) {
                    for(size_t i = 0; i < wordLen; i++) {
                        if(c & (1 << (wordLen - 1 - i)))
                            *retStrPos++ = '1';
                        else
                            *retStrPos++ = '0';
                    }
                };

            for(const auto& block : *this) 
                for(const auto& word : block)
                    wordToBits(word, retStrRef);

            retStrRef[retStrLen - 1] = '\0';

            return retStr;
        }
#endif
    };

    constexpr word_ty rotL(word_ty x, bitLen_ty n) 
    {
        return (x << n) | (x >> (wordLen - n));
    }

    constexpr word_ty rotR(word_ty x, bitLen_ty n) 
    {
        return (x >> n) | (x << (wordLen - n));
    }

    constexpr word_ty shR(word_ty x, bitLen_ty n) 
    {
        return (x >> n);
    }

    constexpr word_ty CH(word_ty x, word_ty y, word_ty z)
    {
        return (x & y) ^ (~x & z);
    }

    constexpr word_ty MAJ(word_ty x, word_ty y, word_ty z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    constexpr word_ty BSIG0(word_ty x)
    {
        return rotR(x, 2) ^ rotR(x, 13) ^ rotR(x, 22);
    }

    constexpr word_ty BSIG1(word_ty x)
    {
        return rotR(x, 6) ^ rotR(x, 11) ^ rotR(x, 25);
    }

    constexpr word_ty SSIG0(word_ty x)
    {
        return rotR(x, 7) ^ rotR(x, 18) ^ shR(x, 3);
    }

    constexpr word_ty SSIG1(word_ty x)
    {
        return rotR(x, 17) ^ rotR(x, 19) ^ shR(x, 10);
    }

    static constexpr word_ty K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static constexpr word_ty initialHash[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    void copyDataToBlocks(const char* data, size_t dataLen, blockCont& blocks)
    {
        auto blockIdx = size_t{0};
        auto wordIdx = size_t{0};
        auto byteInWordIdx = size_t{0};

        auto setByteInWord = [&](char c) -> word_ty 
        {
            auto shiftAmt = size_t{0};
            if constexpr(isBigEndian()) 
                shiftAmt = CHAR_BIT * byteInWordIdx;
            else
                shiftAmt = CHAR_BIT * (wordLenInByte - 1 - byteInWordIdx);

            return word_ty{ static_cast<word_ty>(c) << shiftAmt};
        };

        std::for_each(
            data, 
            data + dataLen, 
            [&](char c) {
                blocks[blockIdx][wordIdx] |= setByteInWord(c);

                byteInWordIdx = (byteInWordIdx + 1) % wordLenInByte;
                if(byteInWordIdx == 0) 
                {
                    wordIdx = (wordIdx + 1) % blockLenInWord; 
                    if(wordIdx == blockLenInWord)  
                        blockIdx++;
                }
            }

        ); 
    }

    void setEndMarker(blockCont& blocks, bitLen_ty dataBitLen)
    {
        constexpr auto maskWord = uint64_t{ (1ul << wordLen) - 1 }; //results in 64'h0000000100000000 => 64'h00000000ffffffff

        auto& lastBlock = blocks.last();
        auto& endMarkerHighWord = lastBlock[blockLenInWord - endMarkerLenInWord + 0];
        auto& endMarkerLowWord = lastBlock[blockLenInWord - endMarkerLenInWord + 1];

        constexpr auto assignEndMarkerRaw = [](const bitLen_ty& dataBitLen) -> uint64_t{
            if constexpr (isBigEndian()) 
            {
                return uint64_t{    ((dataBitLen >> 56) & 0x00000000000000FF) 
                                |   ((dataBitLen >> 40) & 0x000000000000FF00) 
                                |   ((dataBitLen >> 24) & 0x0000000000FF0000) 
                                |   ((dataBitLen >>  8) & 0x00000000FF000000)    
                                |   ((dataBitLen <<  8) & 0x000000FF00000000) 
                                |   ((dataBitLen << 24) & 0x0000FF0000000000) 
                                |   ((dataBitLen << 40) & 0x00FF000000000000) 
                                |   ((dataBitLen << 56) & 0xFF00000000000000)};
            }
            else
                return uint64_t{ dataBitLen };
        };
        const auto endMarkerRaw = assignEndMarkerRaw(dataBitLen);
        
        endMarkerLowWord = endMarkerRaw & maskWord;
        endMarkerHighWord = (endMarkerRaw >> wordLen) & maskWord;
        return;
    }

    void setMessageEndBit(blockCont& blocks, bitLen_ty dataBitLen)
    {
        const auto lastBlockIdx = size_t{dataBitLen / blockLen};
        const auto lastWordIdx = size_t{(dataBitLen % blockLen) / wordLen};
        const auto lastBitIdx = size_t{dataBitLen % wordLen};
        auto endBitMask = word_ty{0};
        if constexpr(isBigEndian())
            endBitMask = static_cast<word_ty>(0x00000001 << lastBitIdx);
        else
            endBitMask = static_cast<word_ty>(0x80000000 >> lastBitIdx);
        
        blocks[lastBlockIdx][lastWordIdx] |= endBitMask;       
    }

    struct workingVariables { 
        word_ty a,b,c,d,e,f,g,h;
        workingVariables(const word_ty initVal[8]) : 
            a(initVal[0]),b(initVal[1]),c(initVal[2]),d(initVal[3]),
            e(initVal[4]),f(initVal[5]),g(initVal[6]),h(initVal[7])
        {}
    };

    void prepareMessageSchedule(const block_ty& block, word_ty* messageSchedule) 
    {
        for(size_t i = 0; i < 64; i++)
        {
            auto newWord = word_ty{0};
            if(i < 16)
                newWord = block[i];
            else
                newWord = SSIG1(messageSchedule[i - 2]) + messageSchedule[i - 7] + SSIG0(messageSchedule[i - 15]) + messageSchedule[i - 16];
                
            messageSchedule[i] = newWord;
        }
    }

    void processWorkingVars(workingVariables& wv, word_ty wt, word_ty K)
    {
            auto T1 = wv.h + BSIG1(wv.e) + CH(wv.e, wv.f, wv.g) + K + wt;
            auto T2 = BSIG0(wv.a) + MAJ(wv.a,wv.b,wv.c);
            wv.h = wv.g;
            wv.g = wv.f;
            wv.f = wv.e;
            wv.e = wv.d + T1;
            wv.d = wv.c;
            wv.c = wv.b;
            wv.b = wv.a;
            wv.a = T1 + T2;
    }

    void performHash(const blockCont& blocks)
    {
        std::copy(std::begin(initialHash), std::end(initialHash), std::begin(resultHashValues));

        auto hashBlock = [&](const block_ty& block) -> void {
            word_ty messageSchedule[64];
            prepareMessageSchedule(block, messageSchedule);

            workingVariables currVar(resultHashValues);
            auto i = size_t{0};
            for(const auto& w : messageSchedule)
                processWorkingVars(currVar, w, K[i++]);

            resultHashValues[0] += currVar.a;
            resultHashValues[1] += currVar.b;
            resultHashValues[2] += currVar.c;
            resultHashValues[3] += currVar.d;
            resultHashValues[4] += currVar.e;
            resultHashValues[5] += currVar.f;
            resultHashValues[6] += currVar.g;
            resultHashValues[7] += currVar.h;
            
        };
        
        std::for_each(blocks.begin(), blocks.end(), hashBlock);
    }

public:
    //requires strData to point to an char array with len elements
    SHA256(const char* data, size_t dataLen)
    {
        constexpr auto maxLastBlockLen    = bitLen_ty {blockLen - endMarkerLen};
        static_assert(maxLastBlockLen < blockLen);
        
        const auto dataBitLen = bitLen_ty{dataLen * CHAR_BIT};
        const auto lastBlockLen = (dataBitLen + 1) % blockLen;

        constexpr auto endMarkerLen   = bitLen_ty {64};
        auto numZeros = bitLen_ty {0};
        if(lastBlockLen > maxLastBlockLen)
            numZeros = blockLen - (lastBlockLen - maxLastBlockLen);
        else 
            numZeros = maxLastBlockLen - lastBlockLen;

        const auto totalLen = bitLen_ty {dataBitLen + 1 + numZeros + endMarkerLen};
        const auto numBlocks = size_t {totalLen / blockLen};
        
        auto blocks = blockCont(numBlocks);
        copyDataToBlocks(data, dataLen, blocks);
        setEndMarker(blocks, dataBitLen);
        setMessageEndBit(blocks, dataBitLen);
        performHash(blocks);
    }
};