%module(directors = "1") oqspython
%{
#define SWIG_FILE_WITH_INIT
#define SWIG_PYTHON_STRICT_BYTE_CHAR
#include "oqs/oqs.h"
#include <string>
%}

%include<stdint.i>
%include "oqs/oqs.h"
%include "std_string.i"
%include "std_vector.i"
%include "cpointer.i"

%pointer_class(size_t, size_t_p);

%feature("director");

%inline %{
class CustomException : public std::exception {
public:
    CustomException(const char* msg) : message_(msg) {}
    const char* what() const noexcept override { return message_.c_str(); }
private:
    std::string message_;
};
%}


%exception {
  try { $action }
  catch (CustomException &e) {
    PyErr_SetString(PyExc_RuntimeError, e.what());
    SWIG_fail;
    }
}
// -------------------------------------------------------------------
// OQS_randombytes

%inline %{
    std::string OQS_randombytes(size_t bytes_to_read){
        std::string random_string;
        random_string.resize(bytes_to_read);
        OQS_randombytes((uint8_t*)random_string.data(), bytes_to_read);
        return random_string;
    }
%}

// -------------------------------------------------------------------
// OQS_randombytes_switch_algorithm
// Generally no need to create typemap
OQS_STATUS OQS_randombytes_switch_algorithm(const char *algorithm);
// -------------------------------------------------------------------
// OQS_SIG_alg_identifier
// Generally no need to create typemap
const char *OQS_SIG_alg_identifier(size_t i);
// -------------------------------------------------------------------
// OQS_SIG_alg_count
// Generally no need to create typemap
int OQS_SIG_alg_count(void);
// -------------------------------------------------------------------
// OQS_SIG_alg_identifier
// Generally no need to create typemap
int OQS_SIG_alg_is_enabled(const char *method_name);
// -------------------------------------------------------------------
// OQS_SIGNATURE
%inline %{
    class OQS_SIGNATURE
    {
    public:
        OQS_SIG *sig_struct;
        std::string method_name;
        std::string alg_version;
        uint8_t claimed_nist_level;
        bool euf_cma;
        size_t length_public_key;
        size_t length_private_key;
        size_t length_signature;

        OQS_SIGNATURE(char *signature_name)
        {
            sig_struct = OQS_SIG_new(signature_name);
            if (sig_struct == NULL) {
                std::string error_message = "OQS_SIG_new failed, probably unknown or incorrect signature name: ";
                error_message += signature_name;
                throw CustomException(error_message.c_str());
            }
            method_name = std::string(sig_struct->method_name);
            alg_version = std::string(sig_struct->alg_version);
            claimed_nist_level = sig_struct->claimed_nist_level;
            euf_cma = sig_struct->euf_cma;
            length_public_key = sig_struct->length_public_key;
            length_private_key = sig_struct->length_secret_key;
            length_signature = sig_struct->length_signature;
        }

        ~OQS_SIGNATURE()
        {
            if (sig_struct != NULL)
            {
                OQS_SIG_free(sig_struct);
                sig_struct = NULL;
            }
        }

        OQS_STATUS keypair(char *public_key, char *private_key)
        {
            return sig_struct->keypair((uint8_t*)public_key, (uint8_t*)private_key);
        }

        OQS_STATUS sign(char *signature, size_t &signature_len, const char *message, const size_t message_len, const char *private_key)
        {
            return sig_struct->sign((uint8_t*)signature, &signature_len, (uint8_t*)message, message_len, (uint8_t*)private_key);
        }

        OQS_STATUS verify(const char *message, const size_t message_len, const char *signature, const size_t signature_len, const char *public_key)
        {
            return sig_struct->verify((uint8_t*)message, message_len, (uint8_t*)signature, signature_len, (uint8_t*)public_key);
        }
    };
%}

// -------------------------------------------------------------------
// OQS_KEM_alg_identifier
// Generally no need to create typemap
const char *OQS_KEM_alg_identifier(size_t i);
// -------------------------------------------------------------------
// OQS_KEM_alg_count
// Generally no need to create typemap
int OQS_KEM_alg_count(void);
// -------------------------------------------------------------------
// OQS_KEM_alg_identifier
// Generally no need to create typemap
int OQS_KEM_alg_is_enabled(const char *method_name);
// -------------------------------------------------------------------
// OQS_KEYENCAPSULATION
%inline %{
    class OQS_KEYENCAPSULATION
    {
    public:
        OQS_KEM *kem_struct;
        std::string method_name;
        std::string alg_version;
        uint8_t claimed_nist_level;
        bool ind_cca;
        size_t length_public_key;
        size_t length_private_key;
        size_t length_ciphertext;
        size_t length_shared_secret;

        OQS_KEYENCAPSULATION(char *kem_name)
        {
            kem_struct = OQS_KEM_new(kem_name);
            if (kem_struct == NULL) {
                std::string error_message = "OQS_KEM_new failed, probably unknown or incorrect kem name: ";
                error_message += kem_name;
                throw CustomException(error_message.c_str());
            }
            method_name = std::string(kem_struct->method_name);
            alg_version = std::string(kem_struct->alg_version);
            claimed_nist_level = kem_struct->claimed_nist_level;
            ind_cca = kem_struct->ind_cca;
            length_public_key = kem_struct->length_public_key;
            length_private_key = kem_struct->length_secret_key;
            length_ciphertext = kem_struct->length_ciphertext;
            length_shared_secret = kem_struct->length_shared_secret;
        }

        ~OQS_KEYENCAPSULATION()
        {
            if (kem_struct != NULL)
            {
                OQS_KEM_free(kem_struct);
                kem_struct = NULL;
            }
        }

        OQS_STATUS keypair(char *public_key, char *private_key)
        {
            return kem_struct->keypair((uint8_t*)public_key, (uint8_t*)private_key);
        }

        OQS_STATUS encapsulate(char *ciphertext, char *shared_secret, const char *public_key)
        {
            return kem_struct->encaps((uint8_t*)ciphertext, (uint8_t*)shared_secret, (uint8_t*)public_key);
        }

        OQS_STATUS decapsulate(char *shared_secret, const char *ciphertext, const char *private_key)
        {
            return kem_struct->decaps((uint8_t*)shared_secret, (uint8_t*)ciphertext, (uint8_t*)private_key);
        }
    };
%}
// -------------------------------------------------------------------
// enums and constants
enum OQS_STATUS
{
    /** Used to indicate that some undefined error occurred. */
    OQS_ERROR = -1,
    /** Used to indicate successful return from function. */
    OQS_SUCCESS = 0,
    /** Used to indicate failures in external libraries (e.g., OpenSSL). */
    OQS_EXTERNAL_LIB_ERROR_OPENSSL = 50,
};

#define OQS_RAND_alg_system "system"
#define OQS_RAND_alg_nist_kat "NIST-KAT"
#define OQS_RAND_alg_openssl "OpenSSL"
#define OQS_SIG_alg_dilithium_2 "Dilithium2"
#define OQS_SIG_alg_dilithium_3 "Dilithium3"
#define OQS_SIG_alg_dilithium_5 "Dilithium5"
#define OQS_SIG_alg_dilithium_2_aes "Dilithium2-AES"
#define OQS_SIG_alg_dilithium_3_aes "Dilithium3-AES"
#define OQS_SIG_alg_dilithium_5_aes "Dilithium5-AES"
#define OQS_SIG_alg_falcon_512 "Falcon-512"
#define OQS_SIG_alg_falcon_1024 "Falcon-1024"
#define OQS_SIG_alg_sphincs_haraka_128f_robust "SPHINCS+-Haraka-128f-robust"
#define OQS_SIG_alg_sphincs_haraka_128f_simple "SPHINCS+-Haraka-128f-simple"
#define OQS_SIG_alg_sphincs_haraka_128s_robust "SPHINCS+-Haraka-128s-robust"
#define OQS_SIG_alg_sphincs_haraka_128s_simple "SPHINCS+-Haraka-128s-simple"
#define OQS_SIG_alg_sphincs_haraka_192f_robust "SPHINCS+-Haraka-192f-robust"
#define OQS_SIG_alg_sphincs_haraka_192f_simple "SPHINCS+-Haraka-192f-simple"
#define OQS_SIG_alg_sphincs_haraka_192s_robust "SPHINCS+-Haraka-192s-robust"
#define OQS_SIG_alg_sphincs_haraka_192s_simple "SPHINCS+-Haraka-192s-simple"
#define OQS_SIG_alg_sphincs_haraka_256f_robust "SPHINCS+-Haraka-256f-robust"
#define OQS_SIG_alg_sphincs_haraka_256f_simple "SPHINCS+-Haraka-256f-simple"
#define OQS_SIG_alg_sphincs_haraka_256s_robust "SPHINCS+-Haraka-256s-robust"
#define OQS_SIG_alg_sphincs_haraka_256s_simple "SPHINCS+-Haraka-256s-simple"
#define OQS_SIG_alg_sphincs_sha256_128f_robust "SPHINCS+-SHA256-128f-robust"
#define OQS_SIG_alg_sphincs_sha256_128f_simple "SPHINCS+-SHA256-128f-simple"
#define OQS_SIG_alg_sphincs_sha256_128s_robust "SPHINCS+-SHA256-128s-robust"
#define OQS_SIG_alg_sphincs_sha256_128s_simple "SPHINCS+-SHA256-128s-simple"
#define OQS_SIG_alg_sphincs_sha256_192f_robust "SPHINCS+-SHA256-192f-robust"
#define OQS_SIG_alg_sphincs_sha256_192f_simple "SPHINCS+-SHA256-192f-simple"
#define OQS_SIG_alg_sphincs_sha256_192s_robust "SPHINCS+-SHA256-192s-robust"
#define OQS_SIG_alg_sphincs_sha256_192s_simple "SPHINCS+-SHA256-192s-simple"
#define OQS_SIG_alg_sphincs_sha256_256f_robust "SPHINCS+-SHA256-256f-robust"
#define OQS_SIG_alg_sphincs_sha256_256f_simple "SPHINCS+-SHA256-256f-simple"
#define OQS_SIG_alg_sphincs_sha256_256s_robust "SPHINCS+-SHA256-256s-robust"
#define OQS_SIG_alg_sphincs_sha256_256s_simple "SPHINCS+-SHA256-256s-simple"
#define OQS_SIG_alg_sphincs_shake256_128f_robust "SPHINCS+-SHAKE256-128f-robust"
#define OQS_SIG_alg_sphincs_shake256_128f_simple "SPHINCS+-SHAKE256-128f-simple"
#define OQS_SIG_alg_sphincs_shake256_128s_robust "SPHINCS+-SHAKE256-128s-robust"
#define OQS_SIG_alg_sphincs_shake256_128s_simple "SPHINCS+-SHAKE256-128s-simple"
#define OQS_SIG_alg_sphincs_shake256_192f_robust "SPHINCS+-SHAKE256-192f-robust"
#define OQS_SIG_alg_sphincs_shake256_192f_simple "SPHINCS+-SHAKE256-192f-simple"
#define OQS_SIG_alg_sphincs_shake256_192s_robust "SPHINCS+-SHAKE256-192s-robust"
#define OQS_SIG_alg_sphincs_shake256_192s_simple "SPHINCS+-SHAKE256-192s-simple"
#define OQS_SIG_alg_sphincs_shake256_256f_robust "SPHINCS+-SHAKE256-256f-robust"
#define OQS_SIG_alg_sphincs_shake256_256f_simple "SPHINCS+-SHAKE256-256f-simple"
#define OQS_SIG_alg_sphincs_shake256_256s_robust "SPHINCS+-SHAKE256-256s-robust"
#define OQS_SIG_alg_sphincs_shake256_256s_simple "SPHINCS+-SHAKE256-256s-simple"
#define OQS_SIG_algs_length 44
#define OQS_KEM_alg_bike_l1 "BIKE-L1"
#define OQS_KEM_alg_bike_l3 "BIKE-L3"
#define OQS_KEM_alg_bike_l5 "BIKE-L5"
#define OQS_KEM_alg_classic_mceliece_348864 "Classic-McEliece-348864"
#define OQS_KEM_alg_classic_mceliece_348864f "Classic-McEliece-348864f"
#define OQS_KEM_alg_classic_mceliece_460896 "Classic-McEliece-460896"
#define OQS_KEM_alg_classic_mceliece_460896f "Classic-McEliece-460896f"
#define OQS_KEM_alg_classic_mceliece_6688128 "Classic-McEliece-6688128"
#define OQS_KEM_alg_classic_mceliece_6688128f "Classic-McEliece-6688128f"
#define OQS_KEM_alg_classic_mceliece_6960119 "Classic-McEliece-6960119"
#define OQS_KEM_alg_classic_mceliece_6960119f "Classic-McEliece-6960119f"
#define OQS_KEM_alg_classic_mceliece_8192128 "Classic-McEliece-8192128"
#define OQS_KEM_alg_classic_mceliece_8192128f "Classic-McEliece-8192128f"
#define OQS_KEM_alg_hqc_128 "HQC-128"
#define OQS_KEM_alg_hqc_192 "HQC-192"
#define OQS_KEM_alg_hqc_256 "HQC-256"
#define OQS_KEM_alg_kyber_512 "Kyber512"
#define OQS_KEM_alg_kyber_768 "Kyber768"
#define OQS_KEM_alg_kyber_1024 "Kyber1024"
#define OQS_KEM_alg_kyber_512_90s "Kyber512-90s"
#define OQS_KEM_alg_kyber_768_90s "Kyber768-90s"
#define OQS_KEM_alg_kyber_1024_90s "Kyber1024-90s"
#define OQS_KEM_alg_ntruprime_sntrup761 "sntrup761"
#define OQS_KEM_alg_frodokem_640_aes "FrodoKEM-640-AES"
#define OQS_KEM_alg_frodokem_640_shake "FrodoKEM-640-SHAKE"
#define OQS_KEM_alg_frodokem_976_aes "FrodoKEM-976-AES"
#define OQS_KEM_alg_frodokem_976_shake "FrodoKEM-976-SHAKE"
#define OQS_KEM_alg_frodokem_1344_aes "FrodoKEM-1344-AES"
#define OQS_KEM_alg_frodokem_1344_shake "FrodoKEM-1344-SHAKE"
#define OQS_KEM_algs_length 29