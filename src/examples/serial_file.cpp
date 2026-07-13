/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

#include <computefhe/ComputeFHE.h>
#include <computefhe/Serialize.h>
#include <iostream>

using namespace computefhe;
using namespace std;

// Serialization type. SerType::JSON can also be preferred
#define SER_TYPE SerType::BINARY

int main() {
    // ----- CLIENT SIDE -----
    // Initialize in client mode
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true);
    auto secret_key = cfhe_base->GetLWEPrivateKey(); // for validation

    // Encrypt some data
    Evector<Eint8> arr = {10, 20, 30, 40};
    Eint8 index = 1;

    Serial::SerializeToFile(
        "ref_key.dat", cfhe_base->GetBinFHEContext().GetRefreshKey(), SER_TYPE);
    Serial::SerializeToFile(
        "ks_key.dat", cfhe_base->GetBinFHEContext().GetSwitchKey(), SER_TYPE);
    Serial::SerializeToFile("enc_arr.dat", arr, SER_TYPE);
    Serial::SerializeToFile("enc_index.dat", index, SER_TYPE);

    // Finalize client mode
    computefhe::Finalize();

    // ----- SERVER SIDE -----
    // Initialize in server mode
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, false);

    // Deserialize data
    RingGSWACCKey deserialized_ref_key;
    LWESwitchingKey deserialized_ks_key;
    Evector<Eint8> deserialized_arr;
    Eint8 deserialized_index;

    Serial::DeserializeFromFile("ref_key.dat", deserialized_ref_key, SER_TYPE);
    Serial::DeserializeFromFile("ks_key.dat", deserialized_ks_key, SER_TYPE);
    Serial::DeserializeFromFile("enc_arr.dat", deserialized_arr, SER_TYPE);
    Serial::DeserializeFromFile("enc_index.dat", deserialized_index, SER_TYPE);

    // Load keys
    cfhe_base->GetBinFHEContext().BTKeyLoad(
        {deserialized_ref_key, deserialized_ks_key});

    // Do something
    cout << "Processing..." << endl;
    deserialized_arr[deserialized_index]++;

    // Check results (needs secret key)
    cfhe_base->SetLWEPrivateKey(secret_key);
    for (auto &i : deserialized_arr) {
        cout << cfhe_base->DecryptInt(i.getData()) << endl;
    }

    // Finalize server mode
    computefhe::Finalize();

    return 0;
}
