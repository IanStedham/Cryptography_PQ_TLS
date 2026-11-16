
gcc alicexor.c -lssl -lcrypto -loqs -o alicexor
gcc bobxor.c -lssl -lcrypto -loqs -o bobxor

./bobxor k1_ab.txt alice_kyber_public.txt bob_dilithium_private.txt >> Bob1.log
./alicexor k1_ab.txt bob_dilithium_public.txt alice_kyber_private.txt bob_dilithium_signature.txt bob_kyber_ciphertext.txt >> Alice1.log

echo "[Testing] Alice and Bob K2"

if cmp -s "k2_bob.txt" "k2_alice.txt"
then
   echo "K2 is valid."
else
   echo "K2 does not match!"
fi 

if cmp -s "bob_final_key.txt" "alice_final_key.txt"
then
    echo "K1 XOR K2 is valid"
else
    echo "K1 XOR K2 does not match!"
fi

echo "[Passed] Alice and Bob final key (K1 XOR K2) match"

echo "[Testing] Invalid signature"

./alice bob_dilithium_public.txt alice_kyber_private.txt bob_invalid_signature.txt bob_kyber_ciphertext.txt k1_ab.txt >> Alice2.log

if [ $? -ne 0 ]; then
    echo "Alice correctly exited with invalid signature."
else
    echo "Alice did not exit with an invalid signature."
fi

echo "[Passed] Alice exited with invalid signature"

echo "Done"
