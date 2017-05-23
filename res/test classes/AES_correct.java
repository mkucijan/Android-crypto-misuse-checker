package com.example.mkucijan.myapplication;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_correct extends AppCompatActivity {

    static final String TAG = "SymmetricAlgorithmAES";

    public byte[] generate_random_key(int size) {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(size, sr);
            return (kg.generateKey()).getEncoded();
        } catch (Exception e) {
            Log.e(TAG,"Generate key error");
            return null;
        }
    }


    public void break_no_rules() {
        String alg="AES/CBC/PKCS5Padding";
        byte[] key = generate_random_key(128);
        byte[] iv =generate_random_key(128);
        byte[] salt=generate_random_key(64);
        byte[] seed=generate_random_key(64);
        int klen=10000;

        String theTestText = "Plaintext";
        TextView tvorig = (TextView)findViewById(R.id.tvorig);
        tvorig.setText("\n[ORIGINAL]:\n" + theTestText + "\n");

        SecretKeySpec sks = null;
        IvParameterSpec ips = null;

        try {
            sks = new SecretKeySpec(key , alg);
            ips = new IvParameterSpec(iv);
        } catch (Exception e) {
            Log.e(TAG, "AES secret key spec error");
        }

        byte[] encodedBytes = null;
        try {
            Cipher c = Cipher.getInstance(alg);
            c.init(Cipher.ENCRYPT_MODE, sks,ips);
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
            c.init(Cipher.DECRYPT_MODE, sks,ips);
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
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_aes_correct);

        break_no_rules();
    }
}
