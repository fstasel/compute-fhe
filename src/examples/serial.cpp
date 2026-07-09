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

int main() {
    // ----- CLIENT SIDE -----
    // Initialize in client mode
    computefhe::Init(CCPARAM_TOY, ALU_OPTIMIZED, true);
    auto secret_key = cfhe_base->GetLWEPrivateKey(); // for validation

    // Encrypt some data
    Evector<Eint8> arr = {10, 20, 30, 40};
    Eint8 index = 1;

    // Serialize data
    string ref_key = Serial::SerializeToString(
        cfhe_base->GetBinFHEContext().GetRefreshKey());
    string ks_key =
        Serial::SerializeToString(cfhe_base->GetBinFHEContext().GetSwitchKey());
    string enc_arr = Serial::SerializeToString(arr);
    string enc_index = Serial::SerializeToString(index);

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
    Serial::DeserializeFromString(deserialized_ref_key, ref_key);
    Serial::DeserializeFromString(deserialized_ks_key, ks_key);
    Serial::DeserializeFromString(deserialized_arr, enc_arr);
    Serial::DeserializeFromString(deserialized_index, enc_index);

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
