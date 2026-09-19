// Feasibility test: run MPC4J's own TFHE RGSW + external product on OUR BFV
// parameters, instead of the plaintext-window-limited RGSW we wrote ourselves.
//
// Why this test exists: MPC4J ships mpc4j-native-fhe/tfhe (TFHEcipher + TFHERNS)
// and it is ALREADY compiled into our mpc4j-native-fhe.dll. Its external product
// decomposes the source ciphertext with an RNS/CRT decomposition (TFHERNS::CRTDecPoly)
// rather than through the plaintext modulus, so the gadget base is not capped at
// +-t/2 the way our own implementation is. If it works on our parameters, the RGSW
// layer can be lifted wholesale from MPC4J instead of us writing the RNS version.
//
// Conventions confirmed from MPC4J's own OnionPIR code:
//   * TFHEcipher::encrypt(plain, rgsw) expects `plain` in NTT form (OnionPIR passes
//     secret_key.data(), which is NTT form), and adds the gadget constants RAW to
//     components 0 and 1 (k = 0 -> component 0, k = 1 -> component 1).
//   * The external product output is in NTT form; the caller sets that flag.
//
// Usage: tfhe_feasibility_test <N>
#include "seal/seal.h"
#include "tfhe.h"   // MPC4J 的 TFHEcipher（编译时把 tfhe/ 目录平铺到了 -I 路径下）

#include <cstdlib>
#include <iostream>
#include <vector>

using namespace seal;
using namespace std;

static int failures = 0;

static void report(const string &name, bool ok, const string &detail) {
    cout << (ok ? "[PASS] " : "[FAIL] ") << name << "\n       " << detail << "\n";
    if (!ok) {
        failures++;
    }
}

int main(int argc, char **argv) {
    size_t N = argc > 1 ? static_cast<size_t>(atoi(argv[1])) : 2048;

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(N);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(N, sec_level_type::tc128));
    parms.set_plain_modulus(65537);
    SEALContext context(parms);

    auto &lvl = context.first_context_data()->parms();
    size_t lvlBits = 0;
    for (const auto &m : lvl.coeff_modulus()) {
        lvlBits += m.bit_count();
    }
    cout << "=== MPC4J TFHE on our parameters ===\n";
    cout << "N=" << N << "  declared primes=" << parms.coeff_modulus().size()
         << "  working-level primes=" << lvl.coeff_modulus().size()
         << "  working-level bits=" << lvlBits << "\n";
    cout << "targetP: digits=" << targetP::digits << "  Bgbit=" << targetP::Bgbit
         << "  Bg=2^" << targetP::Bgbit << "  l_=" << targetP::l_ << "\n\n";

    if (lvlBits > targetP::digits) {
        cout << "!! 工作模数位宽 " << lvlBits << " 超过 targetP::digits=" << targetP::digits
             << "（params.h 是编译期常量，需要按目标参数重编）\n";
        return 2;
    }

    KeyGenerator keygen(context);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;
    keygen.create_public_key(pk);
    Encryptor encryptor(context, sk);
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    // ---- 源密文：普通 BFV 加密 ----
    Plaintext msg(N);
    for (size_t i = 0; i < N; i++) {
        msg[i] = static_cast<uint64_t>((i % 100) + 1);
    }
    Ciphertext src;
    encryptor.encrypt_symmetric(msg, src);

    TFHEcipher tfhe(context, pk);

    // ---- RGSW(1)：常数的 NTT 形式 = 每个系数都是 1 ----
    Plaintext one(N);
    for (size_t i = 0; i < N; i++) {
        one[i] = 1;
    }
    RGSWCipher rgswOne;
    tfhe.encrypt(one, rgswOne);
    cout << "RGSW 密文个数 = " << rgswOne.size() << "（2*l_ = " << 2 * targetP::l_ << "）\n";

    // ---- RGSW(1) ⊗ src 应当等于 src ----
    Ciphertext dst;
    dst.resize(context, context.first_parms_id(), 2);
    tfhe.ExternalProduct(dst, src, rgswOne);
    Ciphertext dstCopy = dst;
    if (dstCopy.is_ntt_form()) {
        evaluator.transform_from_ntt_inplace(dstCopy);
    }
    Plaintext out;
    decryptor.decrypt(dstCopy, out);
    size_t wrong = 0;
    for (size_t i = 0; i < N; i++) {
        if (out[i] != msg[i]) {
            wrong++;
        }
    }
    report("RGSW(1) x src = src（MPC4J 的 RNS 版外部乘积）", wrong == 0,
        "错位 " + to_string(wrong) + "/" + to_string(N)
            + "；首个系数 got=" + to_string(out[0]) + " want=" + to_string(msg[0]));

    // ---- RGSW(0) ⊗ src 应当约为 0 ----
    Plaintext zero(N);
    RGSWCipher rgswZero;
    tfhe.encrypt(zero, rgswZero);
    Ciphertext dst0;
    dst0.resize(context, context.first_parms_id(), 2);
    tfhe.ExternalProduct(dst0, src, rgswZero);
    if (dst0.is_ntt_form()) {
        evaluator.transform_from_ntt_inplace(dst0);
    }
    Plaintext out0;
    decryptor.decrypt(dst0, out0);
    size_t nonzero = 0;
    for (size_t i = 0; i < N; i++) {
        if (out0[i] != 0) {
            nonzero++;
        }
    }
    report("RGSW(0) x src = 0", nonzero == 0, "非零系数 " + to_string(nonzero) + "/" + to_string(N));

    cout << "\n" << (failures == 0 ? "=== MPC4J 的 TFHE 在我们的参数上可用 ==="
                                   : "=== 有 " + to_string(failures) + " 项失败 ===") << "\n";
    return failures == 0 ? 0 : 1;
}
