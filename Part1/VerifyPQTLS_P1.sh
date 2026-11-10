#!/bin/bash

set -e

gcc alice.c -o alice -loqs -lssl -lcrypto
gcc bob.c -o bob -loqs -lssl -lcrypto

for i in 1 2 3
do

   BOB_KYBER_PK="bob_kyber_public${i}.txt"
   ALICE_DILITHIUM_SK="alice_dilithium_private${i}.txt"
   ALICE_DILITHIUM_PK="alice_dilithium_public${i}.txt"
   BOB_KYBER_SK="bob_kyber_private${i}.txt"

   ALICE_CT_OUT="kyber_ciphertext.txt"
   ALICE_SIG_OUT="dilithium_signature.txt"
   ALICE_SS_OUT="alice_shared_secret.txt"
   BOB_SS_OUT="bob_shared_secret.txt"

   # alice  
   echo "[Alice test set $i]"
   ./alice "$BOB_KYBER_PK" "$ALICE_DILITHIUM_SK" >> alice.log
   if [ $? -ne 0 ]; then
   echo "ERROR: Alice failed for test set $i."
   continue 
   fi
   # validate ciphertext length 
   CT_SIZE=$(wc -c < "$ALICE_CT_OUT")
   EXPECTED_CT_HEX_SIZE=1536  # 768 bytes / 1536 hex chars 

   if [ "$CT_SIZE" -eq "$EXPECTED_CT_HEX_SIZE" ]; then
   echo "PASSED: Ciphertext size is correct ($CT_SIZE hex chars / 768 bytes)"
   else
   echo "FAILED: Ciphertext size is incorrect (got $CT_SIZE, expected $EXPECTED_CT_HEX_SIZE hex chars)"
   continue
   fi
   # validate signature length 
   SIG_SIZE=$(wc -c < "$ALICE_SIG_OUT")
   EXPECTED_SIG_HEX_SIZE=4840  # 2420 bytes / 4840 hex chars 
   
   if [ "$SIG_SIZE" -eq "$EXPECTED_SIG_HEX_SIZE" ]; then
   echo "PASSED: Signature size is correct ($SIG_SIZE hex chars / 2420 bytes)"
   else
   echo "FAILED: Signature size is incorrect (got $SIG_SIZE, expected $EXPECTED_SIG_HEX_SIZE hex chars)"
   continue
   fi
   # bob
   echo "[Bob test set $i]"
   ./bob "$ALICE_DILITHIUM_PK" "$BOB_KYBER_SK" >> bob.log

   if [ $? -ne 0 ]; then
   echo "ERROR: Bob failed for test set $i."
   else
   echo "PASSED: Signature was verified and ciphertext decrypted."
   fi
    
   if cmp -s "$ALICE_SS_OUT" "$BOB_SS_OUT"; then
   echo "PASSED: Alice's Shared Secret ($ALICE_SS_OUT) matches Bob's Shared Secret ($BOB_SS_OUT)."
   else
   echo "FAILED: Alice's Shared Secret ($ALICE_SS_OUT) does NOT match Bob's Shared Secret ($BOB_SS_OUT)."
   fi

   if [ "$i" -eq 3 ]; then 
   echo "[Bob invalid signature test]"
   cp "$ALICE_SIG_OUT" "${ALICE_SIG_OUT}.backup"
   FIRST_SIG_BYTE=$(head -c 2 "$ALICE_SIG_OUT")
   MODIFIED_SIG_BYTE=$(printf "%02X" $((0x$FIRST_SIG_BYTE ^ 0xFF)))
   tail -c +3 "$ALICE_SIG_OUT" > temp_sig.txt
   echo -n "$MODIFIED_SIG_BYTE" > "$ALICE_SIG_OUT"
   cat temp_sig.txt >> "$ALICE_SIG_OUT"
   rm temp_sig.txt
   echo "Modified first byte of signature: $FIRST_SIG_BYTE -> $MODIFIED_SIG_BYTE"
           
   if ./bob "$ALICE_DILITHIUM_PK" "$BOB_KYBER_SK" >> bob.log 2>/dev/null; then
   echo "FAILED: Bob should have failed with modified signature but succeeded"
   else
   echo "PASSED: Bob correctly detected modified signature and exited"
   fi

   mv "${ALICE_SIG_OUT}.backup" "$ALICE_SIG_OUT"
fi
done
echo "Test complete"
