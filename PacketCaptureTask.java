package com.qosvisualizer.engine;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

public class PacketCaptureTask implements Runnable {
    private final PcapNetworkInterface networkInterface;
    private final QoSEngine qosEngine;
    private PcapHandle handle;
    private volatile boolean running = true;

    public PacketCaptureTask(PcapNetworkInterface networkInterface, QoSEngine qosEngine) {
        this.networkInterface = networkInterface;
        this.qosEngine = qosEngine;
    }

    @Override
    public void run() {
        try {
            int snapLen = 65536;
            int timeout = 50; // ms
            handle = networkInterface.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
            
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    if (!running) return;
                    qosEngine.processPacket(packet, packet.length());
                }
            };

            while (running) {
                try {
                    handle.dispatch(10, listener);
                } catch (Exception e) {
                    if (!running) break;
                }
            }
        } catch (Exception e) {
            System.err.println("Error capturing packets: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }

    public void stop() {
        running = false;
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (Exception e) {
                // Ignore
            }
        }
    }
}
