
package com.qosvisualizer.model;

public class PacketData {
    private final String time;
    private final String protocol;
    private final String subType;
    private final int size;
    private final String priority;
    private final String destIp;
    private String status;

    public PacketData(String time, String protocol, String subType, int size, String priority, String destIp) {
        this.time = time;
        this.protocol = protocol;
        this.subType = subType;
        this.size = size;
        this.priority = priority;
        this.destIp = destIp;
        this.status = "NORMAL";
    }

    public String getTime() {
        return time;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getSubType() {
        return subType;
    }

    public int getSize() {
        return size;
    }

    public String getPriority() {
        return priority;
    }

    public String getDestIp() {
        return destIp;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
