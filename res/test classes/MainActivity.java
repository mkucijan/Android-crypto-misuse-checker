package com.example.mkucijan.myapplication;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    public void say(String msg1,String msg2) {
        TextView textView = (TextView) findViewById(R.id.textView);
        textView.setText(msg1+msg2);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String a="Hello";
        String b=" world!";
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        say(a, b);

    }

    public void buttonClickFunction(View v)
    {
        Intent intent = new Intent(getApplicationContext(), AES_ECB.class);
        startActivity(intent);
    }

    public void buttonClickFunction2(View v)
    {
        Intent intent = new Intent(getApplicationContext(), AES_CBC.class);
        startActivity(intent);
    }

    public void buttonClickFunction3(View v)
    {
        Intent intent = new Intent(getApplicationContext(), AES_correct.class);
        startActivity(intent);
    }
}
