package com.example.personal_ai_assistant

import android.os.Build
import android.os.Bundle
import android.window.SplashScreenView
import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugins.GeneratedPluginRegistrant

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        GeneratedPluginRegistrant.registerWith(flutterEngine)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Keep splash screen visible longer on Android 12+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Set splash screen to stay on until Flutter tells it to close
            splashScreen.setOnExitAnimationListener { splashScreenView ->
                // Remove splash screen immediately when Flutter is ready
                splashScreenView.remove()
            }
        }
        super.onCreate(savedInstanceState)
    }
}
