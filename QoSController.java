package com.qosvisualizer.engine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

public class QoSController {

    public enum ThrottleState {
        FULL_SPEED,
        THROTTLED
    }

    private ThrottleState currentState = ThrottleState.THROTTLED;
    private String lastStateChangeTime = "INITIAL";
    private boolean BLOCK_MODE = true;  // NEW FLAG

    // Default thresholds in KB/s
    private double limitX_Throttle = 150.0;
    private double limitY_Release = 75.0; // Default to 50%
    private double lastHighKbps = 0;
    private volatile boolean isInitialized = false;
    private final boolean restrictChrome;

    // --- Structured Low Priority Targets ---
    private static class QoSTarget {
        String name;
        String appPath;
        int port;
        String protocol;
        int precedence;
        boolean isHighPriority;

        QoSTarget(String name, String appPath, int port, String protocol, int precedence, boolean isHighPriority) {
            this.name = name;
            this.appPath = appPath;
            this.port = port;
            this.protocol = protocol;
            this.precedence = precedence;
            this.isHighPriority = isHighPriority;
        }
    }

    private final QoSTarget[] qosTargets = {
        // TIER 1: HIGH PRIORITY (Precedence 255 = UNTOUCHABLE)
        new QoSTarget("HighPri_Teams", "ms-teams.exe", 0, "", 255, true),
        new QoSTarget("HighPri_Zoom", "Zoom.exe", 0, "", 255, true),
        new QoSTarget("HighPri_WhatsApp", "WhatsApp.exe", 0, "", 255, true),
        new QoSTarget("HighPri_WhatsApp2", "WhatsAppDesktop.exe", 0, "", 255, true),
        
        // TIER 2: LOW PRIORITY - APP LEVEL (Precedence 40 = STRICT)
        new QoSTarget("LowPri_Chrome", "chrome.exe", 0, "", 40, false),
        new QoSTarget("LowPri_Edge", "msedge.exe", 0, "", 40, false),
        new QoSTarget("LowPri_Store", "WinStore.App.exe", 0, "", 40, false),
        new QoSTarget("LowPri_Update1", "MoUsoCoreWorker.exe", 0, "", 40, false),
        
        // TIER 3: PORT BACKUP (Precedence 30 = FINAL CATCH)
        new QoSTarget("LowPri_Web443_TCP", "", 443, "TCP", 30, false),
        new QoSTarget("LowPri_Web443_UDP", "", 443, "UDP", 30, false),
        new QoSTarget("LowPri_Web80", "", 80, "TCP", 30, false)
    };
    // ----------------------------------------
    private int lowTrafficConsecutiveCount = 0;
    private int highTrafficConsecutiveCount = 0;
    private int samplesSinceStart = 0; // Grace period counter
    private long currentBlockDurationSeconds = 0; 
    private static final int RELEASE_STABILITY_THRESHOLD = 5; // 5 seconds of stability required
    private static final int THROTTLE_STABILITY_THRESHOLD = 2; // 2 seconds of high traffic required

    private final Consumer<String> eventLogger;
    private final Consumer<Boolean> throttleStateListener;
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    public QoSController(Consumer<String> eventLogger, Consumer<Boolean> throttleStateListener, boolean restrictChrome) {
        this.eventLogger = eventLogger;
        this.throttleStateListener = throttleStateListener;
        this.restrictChrome = restrictChrome;
        
        // Start initialization in a background thread to prevent UI "stucking" (freezing)
        Thread initThread = new Thread(this::initPolicy, "QoS-Init-Thread");
        initThread.setDaemon(true);
        initThread.start();
    }
    private void initPolicy() {
        String timestamp = LocalTime.now().format(timeFormatter);
        this.lastStateChangeTime = timestamp;
        logEvent("[" + timestamp + "] - Initializing Tiered Precedence QoS...");

        StringBuilder script = new StringBuilder();
        script.append("$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'); ");
        script.append("if (-not $isAdmin) { throw 'Access is denied. Administrator privileges required.' } ");
        
        // HARD RESET: Forcefully remove ALL existing policies and firewall rules to ensure a clean slate
        script.append("Get-NetQosPolicy -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue; ");
        script.append("Get-NetFirewallRule | ?{$_.DisplayName -like 'NetViz_*' -or $_.DisplayName -like 'Temp_Block_*'} | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue; ");
        
        // Initial leak rate calculation for starting state
        double initialLeakRate = Math.min(100.0, limitX_Throttle * (1.0 / 3.0));
        long initialBps = (long)(initialLeakRate * 8 * 1024);
        
        for (QoSTarget target : qosTargets) {
            // Skip Chrome policy if restrictChrome is false
            if (!restrictChrome && "LowPri_Chrome".equals(target.name)) {
                continue;
            }

            String rate = target.isHighPriority ? "([uint64]1GB)" : "([uint64]" + initialBps + ")"; 
            String protocolPart = target.protocol.isEmpty() ? "" : " -IPProtocolMatchCondition " + target.protocol;
            
            if (target.port > 0) {
                script.append(String.format("New-NetQosPolicy -Name '%s_Dst' -IPDstPortMatchCondition %d%s -ThrottleRateActionBitsPerSecond %s -NetworkProfile All -Precedence %d -Confirm:$false -ErrorAction Stop; ", 
                    target.name, target.port, protocolPart, rate, target.precedence));
                script.append(String.format("New-NetQosPolicy -Name '%s_Src' -IPSrcPortMatchCondition %d%s -ThrottleRateActionBitsPerSecond %s -NetworkProfile All -Precedence %d -Confirm:$false -ErrorAction Stop; ", 
                    target.name, target.port, protocolPart, rate, target.precedence));
            } else if (!target.appPath.isEmpty()) {
                script.append(String.format("New-NetQosPolicy -Name '%s' -AppPathNameMatchCondition '%s'%s -ThrottleRateActionBitsPerSecond %s -NetworkProfile All -Precedence %d -Confirm:$false -ErrorAction Stop; ", 
                    target.name, target.appPath, protocolPart, rate, target.precedence));
            } else if (!target.protocol.isEmpty()) {
                script.append(String.format("New-NetQosPolicy -Name '%s' -IPProtocolMatchCondition '%s' -ThrottleRateActionBitsPerSecond %s -NetworkProfile All -Precedence %d -Confirm:$false -ErrorAction Stop; ", 
                    target.name, target.protocol, rate, target.precedence));
            }
        }
        script.append("Write-Host 'POLICIES_READY'");

        this.isInitialized = executePowerShellCommand(script.toString(), "Tiered QoS Policies Initialized", "Policy Initialization Failed!");
        
        if (this.isInitialized) {
            applyState(currentState);
        }
    }

    private void logEvent(String message) {
        if (this.eventLogger != null) {
            this.eventLogger.accept(message);
        }
    }

    public void processHighPriorityTraffic(double highKbps) {
        this.lastHighKbps = highKbps;
        ThrottleState nextState = currentState;
        samplesSinceStart++;

        if (highKbps > limitX_Throttle) {
            // Check for stability before throttling - only allow after a 3-second grace period
            if (samplesSinceStart > 3) {
                highTrafficConsecutiveCount++;
                if (highTrafficConsecutiveCount >= THROTTLE_STABILITY_THRESHOLD) {
                    nextState = ThrottleState.THROTTLED;
                }
            }
            lowTrafficConsecutiveCount = 0; // Reset release counter
        } else if (highKbps < limitY_Release) {
            // Check for stability before release
            lowTrafficConsecutiveCount++;
            highTrafficConsecutiveCount = 0; // Reset throttle counter
            if (lowTrafficConsecutiveCount >= RELEASE_STABILITY_THRESHOLD) {
                nextState = ThrottleState.FULL_SPEED;
            }
        } else {
            // Inside the "Cage": we stay in the current state, but reset the stable counters
            // as the signal is currently within the active/jitter zone
            lowTrafficConsecutiveCount = 0;
            highTrafficConsecutiveCount = 0;
        }

        // Increment block duration if currently throttled
        if (currentState == ThrottleState.THROTTLED) {
            currentBlockDurationSeconds++;
        } else {
            currentBlockDurationSeconds = 0; // Reset when not throttled
        }

        if (nextState != currentState) {
            applyState(nextState);
            currentState = nextState;
        }
    }

    public void updateThresholds(double triggerLimit, double releaseLimit) {
        this.limitX_Throttle = triggerLimit;
        this.limitY_Release = releaseLimit;
        
        // Immediate check for state transition using the last known traffic measurement.
        processHighPriorityTraffic(lastHighKbps);
    }

    private void applyState(ThrottleState state) {
        String timestamp = LocalTime.now().format(timeFormatter);
        this.lastStateChangeTime = timestamp;

        if (!isInitialized) {
            if (throttleStateListener != null) {
                throttleStateListener.accept(state == ThrottleState.THROTTLED);
            }
            return;
        }

        switch (state) {
            case THROTTLED:
                new Thread(this::blockEverything, "QoS-Block-Thread").start();
                break;
            case FULL_SPEED:
                new Thread(this::restoreEverything, "QoS-Restore-Thread").start();
                break;
        }

        if (throttleStateListener != null) {
            throttleStateListener.accept(state == ThrottleState.THROTTLED);
        }
    }

    private void blockEverything() {
        String timestamp = LocalTime.now().format(timeFormatter);
        String appsToBlock = "'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'";
        if (restrictChrome) {
            appsToBlock += ", 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'";
        }

        String blockCmd = 
            "$apps = @(" + appsToBlock + "); " +
            "foreach ($app in $apps) { if (Test-Path $app) { $name = Split-Path $app -Leaf; New-NetFirewallRule -DisplayName ('Temp_Block_' + $name) -Direction Outbound -Program $app -Action Block -ErrorAction SilentlyContinue } }; " +
            "New-NetFirewallRule -DisplayName 'Temp_Block_Store' -Direction Outbound -PackageFamilyName 'Microsoft.WindowsStore_8wekyb3d8bbwe' -Action Block -ErrorAction SilentlyContinue; " +
            "$services = @('wuauserv', 'gupdate', 'gupdatem', 'MicrosoftEdgeElevationService', 'BITS'); " +
            "foreach ($svc in $services) { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue; Set-Service -Name $svc -StartupType Disabled }; " +
            "Write-Host '>>> PACKETS BLOCKED <<<'";
            
        String logMsg = "[" + timestamp + "] - \u2622\uFE0F BLOCK EVERYTHING: Edge/Store blocked, Update services stopped.";
        if (restrictChrome) {
            logMsg = "[" + timestamp + "] - \u2622\uFE0F BLOCK EVERYTHING: Chrome/Edge/Store blocked, Update services stopped.";
        }
            
        executePowerShellCommand(blockCmd, logMsg, "[" + timestamp + "] - BLOCK EVERYTHING FAILED");
    }

    private void restoreEverything() {
        String timestamp = LocalTime.now().format(timeFormatter);
        String restoreCmd = 
            "Remove-NetFirewallRule -DisplayName 'Temp_Block_*' -ErrorAction SilentlyContinue; " +
            "$services = @('wuauserv', 'gupdate', 'gupdatem', 'MicrosoftEdgeElevationService', 'BITS'); " +
            "foreach ($svc in $services) { Set-Service -Name $svc -StartupType Automatic; Start-Service -Name $svc -ErrorAction SilentlyContinue }; " +
            "Write-Host '>>> RESTORED <<<'";
            
        executePowerShellCommand(restoreCmd, 
            "[" + timestamp + "] - 🔓 RESTORE EVERYTHING: Firewall rules removed, services restarted.", 
            "[" + timestamp + "] - RESTORE EVERYTHING FAILED");
    }

    private boolean executePowerShellCommand(String command, String successMsg, String errorMsg) {
        StringBuilder fullOutput = new StringBuilder();
        String lastErrorLine = null;
        try {
            System.out.println("[QoSController] Executing PowerShell: " + command);
            ProcessBuilder processBuilder = new ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    command
            );
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[PowerShell Output] " + line);
                    fullOutput.append(line).append("\n");
                    
                    // Catch more lines of the error to understand the "Parameter" failure
                    if (line.contains(" : ") || line.toLowerCase().contains("error") || line.toLowerCase().contains("denied") || line.contains("FullyQualifiedErrorId")) {
                        lastErrorLine = line.trim();
                    }
                }
            }
            
            int exitCode = process.waitFor();
            
            if (exitCode != 0) {
                System.err.println("[QoSController] Command failed with exit code: " + exitCode);
                
                // CRITICAL: Log the FULL output to the Dashboard so the user can see exactly why it failed
                String fullLog = fullOutput.toString().trim();
                String detail = !fullLog.isEmpty() ? fullLog : "Unknown Error - check Admin permissions";
                
                // If it's too long, take the first 500 chars to avoid UI issues
                if (detail.length() > 500) detail = detail.substring(0, 500) + "...";
                
                logEvent(errorMsg + " -> " + detail);
                return false;
            } else {
                // Individual policy failure check
                String outputStr = fullOutput.toString();
                if (outputStr.contains("ERROR_IN_POLICY")) {
                    logEvent(errorMsg + " (Partial Failure) -> " + outputStr.trim());
                    return false;
                }
                logEvent(successMsg);
                return true;
            }

        } catch (IOException | InterruptedException e) {
            System.err.println("[QoSController] Failed to execute PowerShell command: " + command);
            logEvent(errorMsg + " -> System error: " + e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    public void stop() {
        String timestamp = LocalTime.now().format(timeFormatter);
        logEvent("[" + timestamp + "] - Stopping QoS and restoring normal speed...");
        
        new Thread(() -> {
            // 1. Restore Firewall and Services
            restoreEverything();
            
            // 2. Remove QoS Policies (the most thorough way to restore normal speed)
            String cleanupQos = "Get-NetQosPolicy -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue;";
            executePowerShellCommand(cleanupQos, "QoS Policies cleared", "QoS Cleanup Failed");
        }, "QoS-Stop-Thread").start();
        
        currentState = ThrottleState.FULL_SPEED;
    }

    public void shutdown() {
        stop();
    }

    public ThrottleState getCurrentState() {
        return currentState;
    }

    public String getLastStateChangeTime() {
        return lastStateChangeTime;
    }

    public int getStabilityCount() {
        return lowTrafficConsecutiveCount;
    }

    public int getStabilityThreshold() {
        return RELEASE_STABILITY_THRESHOLD;
    }

    public long getCurrentBlockDurationSeconds() {
        return currentBlockDurationSeconds;
    }

    public int getThrottleStabilityCount() {
        return highTrafficConsecutiveCount;
    }

    public int getThrottleStabilityThreshold() {
        return THROTTLE_STABILITY_THRESHOLD;
    }
}

