package com.example.genericapp;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {
    // Placeholder values only - not real credentials.
    private static final String API_BASE = "https://api.example.com/v1/";
    private static final String UPLOAD_URL = "https://uploads.example.com/generic-app/";
    private static final String GOOGLE_API_KEY = "AIzaSy00000000000000000000000000000000A";
    private static final String AWS_SECRET = "0000000000000000000000000000000000000000";
    private static final String FIREBASE_DB = "https://generic-app-0000.firebaseio.com";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        android.util.Log.d("generic-app", API_BASE + UPLOAD_URL + FIREBASE_DB);
        android.util.Log.d("generic-app", GOOGLE_API_KEY + AWS_SECRET);
    }
}
