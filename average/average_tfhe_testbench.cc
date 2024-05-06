#include <stdint.h>

#include <iostream>

#include "tfhe/tfhe.h"
#include "transpiler/data/tfhe_data.h"
#include "xls/common/logging/logging.h"

#include "transpiler/examples/average/average_tfhe.h"

using namespace std;

const int main_minimum_lambda = 120;

int main(int argc, char** argv) {
  TFheGateBootstrappingParameterSet* params =
      new_default_gate_bootstrapping_parameters(main_minimum_lambda);
	  
  uint32_t seed[] = {314, 1592, 657};
  tfhe_random_generator_setSeed(seed, 3);
  TFheGateBootstrappingSecretKeySet* key =
      new_random_gate_bootstrapping_secret_keyset(params);
  const TFheGateBootstrappingCloudKeySet* cloud_key = &key->cloud;

  // The dummy inputs are. 
  int a = 20;
  int b = 30;

  cout << "Given dummy test inputs are " << a << " and " << b << ", Average of two numbers are: " << (a + b)/2 << endl;
  // Encrypting given data
  auto ciphertext_a = Tfhe<int>::Encrypt(a, key);
  auto ciphertext_b = Tfhe<int>::Encrypt(b, key);

  cout << "Done with encryption" << endl;

  cout << "Decryption check: " << endl;
  // Decrypting the results.
  cout << ciphertext_a.Decrypt(key);
  cout << "  ";
  cout << ciphertext_b.Decrypt(key);

  cout << "\n";

  cout << "The server side computation for the given inputs:" << endl;
  // Average of two numbers
  Tfhe<int> cipher_result(params);
  XLS_CHECK_OK(
      average(cipher_result, ciphertext_a, ciphertext_b, cloud_key));

  cout << "\t\t\t\t\tComputation done" << endl;

  cout << "After decryption a: " << ciphertext_a.Decrypt(key) << "\n";
  cout << "After decryption b: " << ciphertext_b.Decrypt(key) << "\n";
  cout << "Decrypted result is: " << cipher_result.Decrypt(key) << "\n";

  cout << "Done with decryption" << endl;
}
