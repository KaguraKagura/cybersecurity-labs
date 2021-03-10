/* Secret-Key Encryption Lab
 * 
 * Find out the key to a symmetric key crypto (AES), when plaintext, ciphertext, initial vector are provided, 
 * and the key belongs to a dictionary of words supplied.
 * Also get a feeling of how to use the openssl library cryptos.
 * */



#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <array>
#include <fstream>


const int AES_128_BLOCK_SIZE = 128 / 8;

bool test_a_key(const std::vector<unsigned char> &plain, const std::vector<unsigned char> &cipher,
                const std::vector<unsigned char> key, std::vector<unsigned char> iv);

void pad_a_key(std::vector<unsigned char> &key);

std::vector<unsigned char> hex_string_to_byte(const std::string &hex);


int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cout << "Enter plaintext, ciphertext, iv, and path of dictionary\n";
        return -1;
    }
    std::ifstream keys(argv[4]);
    if (!keys.is_open()) {
        std::cout << "Bad path!\n";
        return -1;
    }
    std::string plain(argv[1]), cipher(argv[2]), iv(argv[3]);
    std::vector<unsigned char> p(plain.cbegin(), plain.cend());
    std::vector<unsigned char> c = hex_string_to_byte(cipher);
    std::vector<unsigned char> i = hex_string_to_byte(iv);
    if (p.size() > 100) {
        std::cout << "At most 100-byte plaintext!\n";
        return -1;
    }
    if (i.size() != AES_128_BLOCK_SIZE) {
        std::cout << "Bad iv!\n";
        return -1;
    }
    // Test every key in keys file
    std::string key;
    while (keys >> key) {
        std::vector<unsigned char> k(key.begin(), key.end());
        pad_a_key(k);
        if (test_a_key(p, c, k, i)) {
            std::cout << "The key is \"" << key << "\"!\n";
            return 0;
        }
        keys >> std::hex;
    }
    std::cout << "Did not find the key!\n";
    return 0;
}

// use aes-128-cbc to encrypt a plaintext and compare with provided cipher
bool test_a_key(const std::vector<unsigned char> &plain, const std::vector<unsigned char> &cipher,
                const std::vector<unsigned char> key, std::vector<unsigned char> iv) {
    std::array<unsigned char, 150> out;
    int outlen, tmplen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), &key[0], &iv[0]);
    if (!EVP_EncryptUpdate(ctx, out.begin(), &outlen, &plain[0], plain.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher error");
    }
    if (!EVP_CipherFinal(ctx, out.begin() + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher error");
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return std::equal(out.cbegin(), out.cbegin() + outlen, cipher.cbegin());
}

// pad a key with '#'
void pad_a_key(std::vector<unsigned char> &key) {
    int pad_length = AES_128_BLOCK_SIZE - AES_128_BLOCK_SIZE % key.size();
    for (auto i = 0; i != pad_length; ++i) {
        key.push_back('#');
    }
}

// change a hex string into a bytes vector
std::vector<unsigned char> hex_string_to_byte(const std::string &hex) {
    std::vector<unsigned char> bytes;
    for (auto i = hex.cbegin(); i != hex.cend(); i += 2) {
        char sub_string[2];
        std::copy(i, i + 2, std::begin(sub_string));
        auto byte = static_cast<unsigned char>(strtoul(sub_string, NULL, 16));
        bytes.push_back(byte);
    }
    return bytes;
}
