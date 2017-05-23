package com.example.mkucijan.myapplication;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;


public class AES_ECB extends AppCompatActivity {

    static final String TAG = "SymmetricAlgorithmAES";



    public void break_all_rules_but_iv() {
        String alg="AES";
        byte[] key = {(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0};
        byte[] salt = {(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0};
        byte[] seed = {(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0};
        int klen=100;

        String theTestText = "Plaintext";
        TextView tvorig = (TextView)findViewById(R.id.tvorig);
        tvorig.setText("\n[ORIGINAL]:\n" + theTestText + "\n");

        SecretKeySpec sks = null;

        try {
            sks = new SecretKeySpec(key , alg);
        } catch (Exception e) {
            Log.e(TAG, "AES secret key spec error");
        }

        byte[] encodedBytes = null;
        try {
            Cipher c = Cipher.getInstance(alg);
            c.init(Cipher.ENCRYPT_MODE, sks);
            encodedBytes = c.doFinal(theTestText.getBytes());
        } catch (Exception e) {
            Log.e(TAG, "AES encryption error");
        }
        TextView tvencoded = (TextView)findViewById(R.id.tvencoded);
        tvencoded.setText("[ENCODED]:\n" +
                Base64.encodeToString(encodedBytes, Base64.DEFAULT) + "\n");

        byte[] decodedBytes = null;
        try {
            Cipher c = Cipher.getInstance(alg);
            c.init(Cipher.DECRYPT_MODE, sks);
            decodedBytes = c.doFinal(encodedBytes);
        } catch (Exception e) {
            Log.e(TAG, "AES decryption error");
        }
        TextView tvdecoded = (TextView)findViewById(R.id.tvdecoded);
        tvdecoded.setText("[DECODED]:\n" + new String(decodedBytes) + "\n");


        char[] password = {(char)0x0,(char)0x0,(char)0x0,(char)0x0,(char)0x0,(char)0x0,(char)0x0,(char)0x0};
        KeySpec spec = new PBEKeySpec(password,salt,klen,536);

        try {
            SecureRandom sr =new SecureRandom(seed);
        } catch (Exception e) {
            Log.e(TAG,"secure random error");
        }

    }



    @Override
    public void onCreate(Bundle savedInstanceState) {
        Intent intent = getIntent();
        super.onCreate(savedInstanceState);
        setContentView(R.layout.aes_ecb);

        break_all_rules_but_iv();
    }
}
