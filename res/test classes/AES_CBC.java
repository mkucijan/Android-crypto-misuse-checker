package com.example.mkucijan.myapplication;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_CBC extends AppCompatActivity {

    static final String TAG = "SymmetricAlgorithmAES";

    public void break_non_random_iv_and_key() {
        String alg="AES/CBC/PKCS5Padding";
        byte[] key = {(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0};
        byte[] iv = {(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0,(byte)0x0};
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

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_aes__cbc);

        break_non_random_iv_and_key();
    }
}
