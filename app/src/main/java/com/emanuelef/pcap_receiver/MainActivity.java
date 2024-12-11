package com.emanuelef.pcap_receiver;
import android.app.ActivityManager;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;

import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Observable;
import java.util.Observer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
public class MainActivity extends AppCompatActivity implements Observer {
    static final String PCAPDROID_PACKAGE = "com.emanuelef.remote_capture";
    static final String CAPTURE_CTRL_ACTIVITY = "com.emanuelef.remote_capture.activities.CaptureCtrl";
    static final String CAPTURE_STATUS_ACTION = "com.emanuelef.remote_capture.CaptureStatus";
    static final String TAG = "PCAP Receiver";

    Button mStart;
    CaptureThread mCapThread;
    TextView mLog;
    EditText serverUrlInput;
    boolean mCaptureRunning = false;
    private Handler handler;
    private Runnable captureRunnable;
    private final ActivityResultLauncher<Intent> captureStartLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::handleCaptureStartResult);
    private final ActivityResultLauncher<Intent> captureStopLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::handleCaptureStopResult);
    private final ActivityResultLauncher<Intent> captureStatusLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::handleCaptureStatusResult);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mLog = findViewById(R.id.pkts_log);
        mStart = findViewById(R.id.start_btn);

        Button copyButton = findViewById(R.id.copy_btn);
        copyButton.setOnClickListener(v -> {
            String sessionText = mLog.getText().toString();
            if (!sessionText.isEmpty()) {
                android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                android.content.ClipData clip = android.content.ClipData.newPlainText("Session Text", sessionText);
                clipboard.setPrimaryClip(clip);
                Toast.makeText(MainActivity.this, "Session copied to clipboard", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, "No session text to copy", Toast.LENGTH_SHORT).show();
            }
        });

        mStart.setOnClickListener(v -> {
            if (!mCaptureRunning) {
                startCapture();
            } else {
                stopCapture();
            }
        });

        if ((savedInstanceState != null) && savedInstanceState.containsKey("capture_running")) {
            setCaptureRunning(savedInstanceState.getBoolean("capture_running"));
        } else {
            queryCaptureStatus();
        }

        MyBroadcastReceiver.CaptureObservable.getInstance().addObserver(this);

        handler = new Handler(Looper.getMainLooper());

        captureRunnable = new Runnable() {
            @Override
            public void run() {
                if (!mCaptureRunning) {
                    startCapture(); // Start the capture
                    Log.d(TAG, "Capture started by interval");
                }
                handler.postDelayed(this, 30000);
            }
        };

        handler.post(captureRunnable);

    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        handler.removeCallbacks(captureRunnable); // Remove any scheduled captures to prevent memory leaks
        MyBroadcastReceiver.CaptureObservable.getInstance().deleteObserver(this);
        stopCaptureThread();
    }
    @Override
    public void update(Observable o, Object arg) {
        boolean capture_running = (boolean) arg;
        Log.d(TAG, "capture_running: " + capture_running);
        setCaptureRunning(capture_running);
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle bundle) {
        bundle.putBoolean("capture_running", mCaptureRunning);
        super.onSaveInstanceState(bundle);
    }

    void onPacketReceived(EthernetPacket pkt) {
        if (pkt.getPayload() instanceof IpV4Packet) {
            IpV4Packet ipV4Packet = (IpV4Packet) pkt.getPayload();
            byte[] payloadData = ipV4Packet.getPayload().getRawData();
            String payloadText = new String(payloadData, StandardCharsets.UTF_8);
            Log.d("Packet Payload", "Raw Payload Text:\n" + payloadText);

            Pattern pattern = Pattern.compile("GZ00[A-Za-z0-9]+GZ00");
            Matcher matcher = pattern.matcher(payloadText);

            if (matcher.find()) {
                String extractedText = matcher.group();
                Log.d("Packet Payload", "Matched Text: " + extractedText);

                runOnUiThread(() -> mLog.setText(extractedText));


            }
        } else {
            Log.w(TAG, "Received non-IPv4 packet");
        }
    }





    void queryCaptureStatus() {
        Log.d(TAG, "Querying PCAPdroid");

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY);
        intent.putExtra("action", "get_status");

        try {
            captureStatusLauncher.launch(intent);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, "PCAPdroid package not found: " + PCAPDROID_PACKAGE, Toast.LENGTH_LONG).show();
        }
    }

    void startCapture() {
        Log.d(TAG, "Starting PCAPdroid");

        // Start the PCAPdroid capture
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY);
        intent.putExtra("action", "start");
        intent.putExtra("broadcast_receiver", "com.emanuelef.pcap_receiver.MyBroadcastReceiver");
        intent.putExtra("pcap_dump_mode", "udp_exporter");
        intent.putExtra("collector_ip_address", "127.0.0.1");
        intent.putExtra("collector_port", "5123");
        intent.putExtra("pcapdroid_trailer", "true");
        intent.putExtra("full_payload", true);
        intent.putExtra("app_filter", "id.dana");

        captureStartLauncher.launch(intent);
    }


    void stopCapture() {
        Log.d(TAG, "Stopping PCAPdroid");

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY);
        intent.putExtra("action", "stop");

        captureStopLauncher.launch(intent);
    }

    void setCaptureRunning(boolean running) {
        mCaptureRunning = running;
        mStart.setText(running ? "Stop Capture" : "Start Capture");

        if(mCaptureRunning && (mCapThread == null)) {
            mCapThread = new CaptureThread(this);
            mCapThread.start();
        } else if(!mCaptureRunning)
            stopCaptureThread();
    }

    void stopCaptureThread() {
        if(mCapThread == null)
            return;

        mCapThread.stopCapture();
        mCapThread.interrupt();
        mCapThread = null;
    }

    void handleCaptureStartResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid start result: " + result);

        if (result.getResultCode() == RESULT_OK) {
            Toast.makeText(this, "Capture started!", Toast.LENGTH_SHORT).show();
            setCaptureRunning(true);
            mLog.setText("");

            Intent launchIntent = getPackageManager().getLaunchIntentForPackage("id.dana");
            if (launchIntent != null) {
                startActivity(launchIntent);
                Log.d(TAG, "Successfully opened id.dana app.");
                Toast.makeText(this, "Opening id.dana app...", Toast.LENGTH_SHORT).show();
            } else {
                Log.e(TAG, "Could not find the id.dana app to open.");
                Toast.makeText(this, "Could not open id.dana app.", Toast.LENGTH_SHORT).show();
            }
        } else {
            Toast.makeText(this, "Capture failed to start", Toast.LENGTH_SHORT).show();
        }
    }




    private void handleAppStatus(String status) {
        if ("aktif".equalsIgnoreCase(status)) {
            Toast.makeText(this, "App is active", Toast.LENGTH_SHORT).show();
        } else if ("tidak aktif".equalsIgnoreCase(status)) {
            showErrorAndClose("Sudah expired pak hehe.");
        } else {
            showErrorAndClose("Unexpected status received: " + status);
        }
    }

    private void showErrorAndClose(String message) {
        new androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("App Status")
                .setMessage(message)
                .setCancelable(false)
                .setPositiveButton("OK", (dialog, which) -> closeApp())
                .show();
    }

    private void closeApp() {
        finish();
        System.exit(0);
    }
    void handleCaptureStopResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid stop result: " + result);

        if(result.getResultCode() == RESULT_OK) {
            Toast.makeText(this, "Capture stopped!", Toast.LENGTH_SHORT).show();
            setCaptureRunning(false);
        } else
            Toast.makeText(this, "Could not stop capture", Toast.LENGTH_SHORT).show();

        Intent intent = result.getData();
        if((intent != null) && (intent.hasExtra("bytes_sent")))
            logStats(intent);
    }

    void handleCaptureStatusResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid status result: " + result);

        if((result.getResultCode() == RESULT_OK) && (result.getData() != null)) {
            Intent intent = result.getData();
            boolean running = intent.getBooleanExtra("running", false);
            int verCode = intent.getIntExtra("version_code", 0);
            String verName = intent.getStringExtra("version_name");

            if(verName == null)
                verName = "<1.4.6";

            Log.d(TAG, "PCAPdroid " + verName + "(" + verCode + "): running=" + running);
            setCaptureRunning(running);
        }
    }

    void logStats(Intent intent) {
        String stats = "*** Stats ***" +
                "\nBytes sent: " +
                intent.getLongExtra("bytes_sent", 0) +
                "\nBytes received: " +
                intent.getLongExtra("bytes_rcvd", 0) +
                "\nPackets sent: " +
                intent.getIntExtra("pkts_sent", 0) +
                "\nPackets received: " +
                intent.getIntExtra("pkts_rcvd", 0) +
                "\nPackets dropped: " +
                intent.getIntExtra("pkts_dropped", 0) +
                "\nPCAP dump size: " +
                intent.getLongExtra("bytes_dumped", 0);

        Log.i("stats", stats);
    }
}