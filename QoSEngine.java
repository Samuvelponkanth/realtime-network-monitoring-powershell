package com.qosvisualizer.engine;

import com.qosvisualizer.model.PacketData;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public class QoSEngine {
    private final Consumer<PacketData> uiCallback;
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private final Map<String, FlowStats> flowCache = new ConcurrentHashMap<>();

    private static class FlowStats {
        long lastWindowStart = System.currentTimeMillis();
        int packetCount = 0;
        int windowCount = 0;
        boolean isBursty = false;
        boolean isFastTracked = false;
        boolean isConfirmed = false;
        long lastPacketTime = System.currentTimeMillis();
        String currentStatus = "NORMAL";
        String currentSubType = "OTHER";

        synchronized void addPacket(int size, boolean isCallSignature, boolean isHeavyLoad) {
            long now = System.currentTimeMillis();
            packetCount++;

            // 1. Fast-Track / Buffer-Track Logic (Immediate Response)
            if (isHeavyLoad) {
                currentStatus = "BUFFERING";
                currentSubType = "UDP-LARGE (HEAVY)";
            } else if (isCallSignature && !isConfirmed) {
                isFastTracked = true;
                currentStatus = "LIVE-VOIP (ACTIVE)";
                currentSubType = "UDP-VOIP (SIGNATURE)";
            }

            // Detect Burst: If we see a huge number of packets in a very short time
            if (packetCount > 50 && (now - lastWindowStart) < 100) {
                isBursty = true;
            }

            // Window Evaluation: every 500ms
            if (now - lastWindowStart > 500) {
                windowCount++;
                
                if (packetCount > 30 && !isBursty) {
                    isConfirmed = true;
                    currentStatus = "LIVE-VOIP";
                    currentSubType = "UDP-STREAM (CONFIRMED)";
                } else if (isBursty || packetCount > 50) {
                    currentStatus = "BUFFERING";
                    currentSubType = "UDP-BUFFER (LOW)";
                    isFastTracked = false;
                } else {
                    // Dual-Layer Verification: If steady rhythm isn't maintained after 1 second, demote
                    if (isFastTracked && windowCount >= 2 && !isConfirmed) {
                        currentStatus = "NORMAL";
                        currentSubType = "UDP-STABLE (DEMOTED)";
                        isFastTracked = false;
                    } else if (!isFastTracked) {
                        currentStatus = "NORMAL";
                        currentSubType = "UDP-STABLE";
                    }
                }
                
                // Reset for next window
                packetCount = 0;
                lastWindowStart = now;
                isBursty = false;
            }
            lastPacketTime = now;
        }
    }

    public QoSEngine(Consumer<PacketData> uiCallback) {
        this.uiCallback = uiCallback;
    }

    public void processPacket(Packet packet, int size) {
        if (packet == null) return;

        String protocolName = "OTHER";
        String subType = "OTHER";
        String priority = "LOW"; 
        String destIp = "UNKNOWN";
        String status = "NORMAL";

        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            destIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();
            Packet payload = ipV4Packet.getPayload();
            if (payload != null) {
                if (payload instanceof UdpPacket) {
                    UdpPacket udpPacket = (UdpPacket) payload;
                    int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                    int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                    
                    // Instant Signature Recognition: Expanded for Video Call Support and Gaming (Full Ephemeral Range)
                    boolean isCallSignature = (size >= 40 && size <= 1500) && 
                                             (srcPort == 3478 || dstPort == 3478 || 
                                              srcPort == 443 || dstPort == 443 ||
                                              (dstPort >= 1024 && dstPort <= 65535) || 
                                              (srcPort >= 1024 && srcPort <= 65535));
                    
                    // Heavy load is now anything large that ISN'T matching a VoIP signature
                    boolean isHeavyLoad = (size > 1400) && !isCallSignature;
                    boolean isWebUdp = (srcPort == 443 || dstPort == 443 || srcPort == 80 || dstPort == 80 || srcPort == 3478 || dstPort == 3478);
                    
                    String flowKey = destIp + ":" + (dstPort == 443 || dstPort == 80 ? srcPort : dstPort);
                    FlowStats stats = flowCache.computeIfAbsent(flowKey, k -> new FlowStats());
                    stats.addPacket(size, isCallSignature, isHeavyLoad);

                    protocolName = "UDP";
                    subType = stats.currentSubType;
                    status = stats.currentStatus;

                    // Priority Assignment
                    if (status.contains("LIVE-VOIP")) {
                        priority = "HIGH";
                        protocolName = isWebUdp ? "UDP-VOIP (WHATSAPP)" : "UDP-STREAM (HIGH)";
                    } else if (status.equals("BUFFERING")) {
                        priority = "LOW";
                        protocolName = isWebUdp ? "UDP-WEB (BUFFER)" : "UDP-LARGE";
                    } else {
                        priority = "LOW";
                        protocolName = isWebUdp ? "UDP-WEB" : "UDP";
                    }

                } else if (payload instanceof TcpPacket) {
                    protocolName = size > 1300 ? "TCP-WEB" : "TCP";
                    subType = "TCP-PLAIN";
                    priority = "LOW";
                }
            }
        }

        // Cleanup old flows (Lazy cleanup)
        if (flowCache.size() > 100) {
            flowCache.entrySet().removeIf(entry -> System.currentTimeMillis() - entry.getValue().lastPacketTime > 5000);
        }

        String timestamp = LocalTime.now().format(timeFormatter);
        PacketData data = new PacketData(timestamp, protocolName, subType, size, priority, destIp);
        data.setStatus(status);
        uiCallback.accept(data);
    }
}
