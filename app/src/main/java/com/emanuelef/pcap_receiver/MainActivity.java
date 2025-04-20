package com.emanuelef.pcap_receiver;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.textfield.TextInputEditText;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Observable;
import java.util.Observer;

public class MainActivity extends AppCompatActivity implements Observer {
    static final String PCAPDROID_PACKAGE = "com.emanuelef.remote_capture";
    static final String CAPTURE_CTRL_ACTIVITY = "com.emanuelef.remote_capture.activities.CaptureCtrl";
    static final String CAPTURE_STATUS_ACTION = "com.emanuelef.remote_capture.CaptureStatus";
    static final String TAG = "PCAP Receiver";

    private static final int MAX_LOG_BUFFER_SIZE = 20000;
    private static final int UPDATE_INTERVAL_MS = 500;

    Button mStart;
    Button mCopyBtn;
    CaptureThread mCapThread;
    TextView mLog;
    TextInputEditText mTargetAppInput;
    boolean mCaptureRunning = false;
    private Handler handler;
    private Runnable captureRunnable;
    private StringBuilder logBuilder = new StringBuilder();

    private StringBuilder pendingLogs = new StringBuilder();
    private long lastUpdateTime = 0;

    private Handler logUpdateHandler;
    private Runnable logUpdateRunnable;

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
        mCopyBtn = findViewById(R.id.copy_btn);
        mTargetAppInput = findViewById(R.id.target_app_input);

        logUpdateHandler = new Handler(Looper.getMainLooper());
        logUpdateRunnable = new Runnable() {
            @Override
            public void run() {
                updateLogView();
                logUpdateHandler.postDelayed(this, UPDATE_INTERVAL_MS);
            }
        };

        mCopyBtn.setOnClickListener(v -> {
            String sessionText = mLog.getText().toString();
            if (!sessionText.isEmpty()) {
                android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                android.content.ClipData clip = android.content.ClipData.newPlainText("Session Text", sessionText);
                clipboard.setPrimaryClip(clip);
                Toast.makeText(MainActivity.this, "Logs copied to clipboard", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, "No logs to copy", Toast.LENGTH_SHORT).show();
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
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (handler != null) {
            handler.removeCallbacks(captureRunnable);
        }
        if (logUpdateHandler != null) {
            logUpdateHandler.removeCallbacks(logUpdateRunnable);
        }
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

            if (payloadText.trim().length() > 0) {
                SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
                String timestamp = sdf.format(new Date());

                String sourceIP = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
                String destIP = ipV4Packet.getHeader().getDstAddr().getHostAddress();

                String logEntry = String.format("[%s] %s → %s\n%s\n\n",
                        timestamp, sourceIP, destIP, payloadText);

                synchronized (pendingLogs) {
                    pendingLogs.append(logEntry);
                }

                long currentTime = System.currentTimeMillis();
                if (currentTime - lastUpdateTime > UPDATE_INTERVAL_MS) {
                    updateLogView();
                    lastUpdateTime = currentTime;
                }
            }
        } else {
            Log.w(TAG, "Received non-IPv4 packet");
        }
    }

    private void updateLogView() {

        if (pendingLogs.length() > 0) {
            runOnUiThread(() -> {
                synchronized (pendingLogs) {

                    logBuilder.append(pendingLogs.toString());

                    pendingLogs.setLength(0);

                    if (logBuilder.length() > MAX_LOG_BUFFER_SIZE) {
                        int cutIndex = logBuilder.length() - MAX_LOG_BUFFER_SIZE;

                        int nextLineBreak = logBuilder.indexOf("\n", cutIndex);
                        if (nextLineBreak > 0) {
                            cutIndex = nextLineBreak + 1;
                        }
                        logBuilder.delete(0, cutIndex);
                    }

                    int scrollY = mLog.getScrollY();
                    int scrollX = mLog.getScrollX();

                    mLog.setText(logBuilder.toString());

                    boolean wasAtBottom = false;
                    try {
                        if (mLog.getLayout() != null) {
                            int visibleLines = mLog.getHeight() / mLog.getLineHeight();
                            int lastVisibleLine = scrollY / mLog.getLineHeight() + visibleLines;
                            wasAtBottom = lastVisibleLine >= mLog.getLineCount() - 3;
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "Error calculating scroll position", e);
                        wasAtBottom = true;
                    }

                    if (wasAtBottom) {

                        mLog.post(() -> {
                            try {
                                if (mLog.getLayout() != null) {
                                    final int scrollAmount = mLog.getLayout().getLineTop(mLog.getLineCount()) - mLog.getHeight();
                                    if (scrollAmount > 0) {
                                        mLog.scrollTo(0, scrollAmount);
                                    }
                                }
                            } catch (Exception e) {
                                Log.e(TAG, "Error scrolling to bottom", e);
                            }
                        });
                    } else {

                        mLog.post(() -> mLog.scrollTo(scrollX, scrollY));
                    }
                }
            });
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

        String targetAppPackage = mTargetAppInput.getText().toString().trim();
        if (targetAppPackage.isEmpty()) {
            Toast.makeText(this, "Please enter a target app package name", Toast.LENGTH_SHORT).show();
            return;
        }

        logBuilder = new StringBuilder();
        pendingLogs = new StringBuilder();
        mLog.setText("");
        lastUpdateTime = 0;

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY);
        intent.putExtra("action", "start");
        intent.putExtra("broadcast_receiver", "com.emanuelef.pcap_receiver.MyBroadcastReceiver");
        intent.putExtra("pcap_dump_mode", "udp_exporter");
        intent.putExtra("collector_ip_address", "127.0.0.1");
        intent.putExtra("collector_port", "5123");
        intent.putExtra("pcapdroid_trailer", "true");
        intent.putExtra("full_payload", true);
        intent.putExtra("app_filter", targetAppPackage);

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
        mTargetAppInput.setEnabled(!running);

        if (mCaptureRunning && (mCapThread == null)) {
            mCapThread = new CaptureThread(this);
            mCapThread.start();

            logUpdateHandler.post(logUpdateRunnable);
        } else if (!mCaptureRunning) {

            logUpdateHandler.removeCallbacks(logUpdateRunnable);

            updateLogView();

            stopCaptureThread();
        }
    }

    void stopCaptureThread() {
        if (mCapThread == null)
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

            String targetAppPackage = mTargetAppInput.getText().toString().trim();

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
            String timestamp = sdf.format(new Date());
            synchronized (pendingLogs) {
                pendingLogs.append("=== CAPTURE STARTED AT " + timestamp + " ===\n");
                pendingLogs.append("Target App: " + targetAppPackage + "\n\n");
            }
            updateLogView();

            Intent launchIntent = getPackageManager().getLaunchIntentForPackage(targetAppPackage);
            if (launchIntent != null) {
                startActivity(launchIntent);
                Log.d(TAG, "Successfully opened " + targetAppPackage + " app.");
                Toast.makeText(this, "Opening " + targetAppPackage + " app...", Toast.LENGTH_SHORT).show();
            } else {
                Log.e(TAG, "Could not find the " + targetAppPackage + " app to open.");
                Toast.makeText(this, "Could not open " + targetAppPackage + " app.", Toast.LENGTH_SHORT).show();
            }
        } else {
            Toast.makeText(this, "Capture failed to start", Toast.LENGTH_SHORT).show();
        }
    }

    void handleCaptureStopResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid stop result: " + result);

        if (result.getResultCode() == RESULT_OK) {
            Toast.makeText(this, "Capture stopped!", Toast.LENGTH_SHORT).show();
            setCaptureRunning(false);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
            String timestamp = sdf.format(new Date());
            synchronized (pendingLogs) {
                pendingLogs.append("=== CAPTURE STOPPED AT " + timestamp + " ===\n");
            }
            updateLogView();

            Intent intent = result.getData();
            if ((intent != null) && (intent.hasExtra("bytes_sent"))) {
                String stats = logStats(intent);
                synchronized (pendingLogs) {
                    pendingLogs.append(stats);
                }
                updateLogView();
            }
        } else {
            Toast.makeText(this, "Could not stop capture", Toast.LENGTH_SHORT).show();
        }
    }

    void handleCaptureStatusResult(final ActivityResult result) {
        Log.d(TAG, "PCAPdroid status result: " + result);

        if ((result.getResultCode() == RESULT_OK) && (result.getData() != null)) {
            Intent intent = result.getData();
            boolean running = intent.getBooleanExtra("running", false);
            int verCode = intent.getIntExtra("version_code", 0);
            String verName = intent.getStringExtra("version_name");

            if (verName == null)
                verName = "<1.4.6";

            Log.d(TAG, "PCAPdroid " + verName + "(" + verCode + "): running=" + running);
            setCaptureRunning(running);
        }
    }

    String logStats(Intent intent) {
        String stats = "*** CAPTURE STATISTICS ***" +
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
                intent.getLongExtra("bytes_dumped", 0) +
                "\n\n";

        Log.i("stats", stats);
        return stats;
    }
}