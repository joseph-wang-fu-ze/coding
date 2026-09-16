// Print the real coefficient-modulus composition that SEAL 4.0.0 picks for each
// polynomial degree at 128-bit security, plus a validity check of the exact
// configuration the CAPE paper uses (N = 16384, t = 65537).
//
// This exists because ciphertext byte sizes cannot be turned into a prime count:
// SEAL's serialisation may compress, so the prime count has to be read from the
// library itself. Build with the static libseal-4.0.a produced by build_seal.ps1.

#include "seal/seal.h"

#include <iostream>
#include <vector>

using namespace seal;
using namespace std;

static void report(size_t n, sec_level_type level, const char *label) {
    try {
        vector<Modulus> cm = CoeffModulus::BFVDefault(n, level);
        size_t total = 0;
        for (const auto &m : cm) {
            total += m.bit_count();
        }
        cout << "N=" << n << "  sec=" << label << "  primes=" << cm.size() << "  total=" << total << " bits  [";
        for (size_t i = 0; i < cm.size(); i++) {
            cout << (i ? ", " : "") << cm[i].bit_count();
        }
        cout << "]\n";
    } catch (const exception &e) {
        cout << "N=" << n << "  sec=" << label << "  -> " << e.what() << "\n";
    }
}

int main() {
    cout << "=== SEAL 4.0.0 CoeffModulus::BFVDefault 实测 ===\n";
    const size_t degrees[] = {1024, 2048, 4096, 8192, 16384, 32768};
    for (size_t n : degrees) {
        report(n, sec_level_type::tc128, "tc128");
    }
    cout << "\n";

    // The paper's configuration: N = 16384, t = 65537, SEAL defaults at 128-bit security.
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(16384);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(16384, sec_level_type::tc128));
    parms.set_plain_modulus(65537);
    SEALContext context(parms);

    cout << "=== 论文参数校验（N=16384, t=65537）===\n";
    cout << "parameters_set        : " << (context.parameters_set() ? "true" : "false") << "\n";
    if (!context.parameters_set()) {
        cout << "error                 : " << context.parameter_error_message() << "\n";
        return 1;
    }
    auto &first = context.first_context_data()->parms();
    auto &last = context.last_context_data()->parms();
    size_t firstBits = 0, lastBits = 0;
    for (const auto &m : first.coeff_modulus()) {
        firstBits += m.bit_count();
    }
    for (const auto &m : last.coeff_modulus()) {
        lastBits += m.bit_count();
    }
    cout << "first level coeff mod : " << first.coeff_modulus().size() << " primes, " << firstBits << " bits\n";
    cout << "last  level coeff mod : " << last.coeff_modulus().size() << " primes, " << lastBits << " bits\n";
    cout << "plain modulus         : " << parms.plain_modulus().value() << " ("
         << parms.plain_modulus().bit_count() << " bits)\n";
    cout << "chain size            : " << context.first_context_data()->chain_index() + 1 << "\n";
    cout << "first level parms_id[0]: " << context.first_parms_id()[0] << "\n";
    return 0;
}
