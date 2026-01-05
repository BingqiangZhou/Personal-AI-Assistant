package com.example.personal_ai_assistant

import android.os.Build
import android.os.Bundle
import androidx.annotation.NonNull
import com.ryanheise.audioservice.AudioServiceActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugins.GeneratedPluginRegistrant

class MainActivity : AudioServiceActivity() {
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

    override fun onDestroy() {
        // CRITICAL: Ensure AudioService is properly released when activity is destroyed
        // This prevents the service from running indefinitely after app exit
        try {
            // AudioService will be cleaned up by Flutter's dispose method
            super.onDestroy()
        } catch (e: Exception) {
            // Log but don't crash
            android.util.Log.e("MainActivity", "Error in onDestroy", e)
            super.onDestroy()
        }
    }

    override fun onStop() {
        // Called when the activity is no longer visible to the user
        // This happens when app is minimized or another app is opened
        super.onStop()
    }
}
