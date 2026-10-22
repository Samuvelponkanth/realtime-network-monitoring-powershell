package com.qosvisualizer;

import com.qosvisualizer.engine.PacketCaptureTask;
import com.qosvisualizer.engine.QoSController;
import com.qosvisualizer.engine.QoSEngine;
import com.qosvisualizer.model.PacketData;
import javafx.application.Platform;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Line;
import javafx.scene.shape.Rectangle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class DashboardUI extends BorderPane {

    private ComboBox<PcapNetworkInterface> interfaceSelector;
    private Button startButton;
    private Button stopButton;
    private ToggleButton restrictChromeBtn;

    private LineChart<String, Number> chartHigh;
    private LineChart<String, Number> chartLow;

    private XYChart.Series<String, Number> seriesHigh;
    private XYChart.Series<String, Number> seriesLow;

    private TableView<PacketData> packetTable;
    private ObservableList<PacketData> tableData;
    private ListView<String> eventLog;

    private Thread captureThread;
    private PacketCaptureTask captureTask;
    private QoSController qosController;

    private Slider thresholdSlider;
    private Label thresholdLabel;
    private Slider releaseSlider;
    private Label releaseLabel;
    private VBox leakRateBox;
    private Label leakRateLabel;
    private final DoubleProperty currentThreshold = new SimpleDoubleProperty(150.0);
    private final DoubleProperty currentReleaseThreshold = new SimpleDoubleProperty(75.0);

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private volatile long currentHighBytes = 0;
    private volatile long currentLowBytes = 0;

    private long totalHighBytesTotal = 0;
    private long totalProtectedBytes = 0;
    private long totalLowBytesTotal = 0;
    private long totalDelayedBytes = 0;

    private Label highUsedLabel;
    private Label highProtectedLabel;
    private Label highProtectedTitleLabel; 
    private Label lowUsedLabel;
    private Label lowDelayedLabel;
    private Label timeLabelHigh;
    private Label timeLabelLow;

    private Timer chartUpdateTimer;
    private final int MAX_DATA_POINTS = 60;
    private long lastTableUpdateTime = 0;
    private double[] highKbpsHistory = new double[3]; // 3-second moving average for signal smoothing
    private int highKbpsIndex = 0;
    private int historyCount = 0;

    public DashboardUI() {
        setupTopPanel();
        setupCenterPanel();
        setupBottomPanel();
        getStyleClass().add("dashboard-pane");
    }

    private void setupTopPanel() {
        HBox topBox = new HBox(15);
        topBox.setPadding(new Insets(15));
        topBox.getStyleClass().add("top-box");

        Label label = new Label("Select Interface:");
        label.getStyleClass().add("title-label");

        interfaceSelector = new ComboBox<>();
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            interfaceSelector.setItems(FXCollections.observableArrayList(allDevs));
        } catch (Exception e) {
            System.err.println("Error finding interfaces: " + e.getMessage());
        }

        interfaceSelector.setCellFactory(lv -> new ListCell<PcapNetworkInterface>() {
            @Override
            protected void updateItem(PcapNetworkInterface item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? "" : (item.getDescription() != null ? item.getDescription() : item.getName()));
            }
        });
        interfaceSelector.setButtonCell(new ListCell<PcapNetworkInterface>() {
            @Override
            protected void updateItem(PcapNetworkInterface item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? "" : (item.getDescription() != null ? item.getDescription() : item.getName()));
            }
        });

        startButton = new Button("Start Capture");
        startButton.getStyleClass().add("start-button");
        startButton.setOnAction(e -> startCapture());

        stopButton = new Button("Stop Capture");
        stopButton.getStyleClass().add("stop-button");
        stopButton.setDisable(true);
        stopButton.setOnAction(e -> stopCapture());

        restrictChromeBtn = new ToggleButton("Restrict Chrome");
        restrictChromeBtn.getStyleClass().add("restrict-chrome-btn");

        VBox thresholdBox = new VBox(2);
        thresholdLabel = new Label("Trigger: 150 KB/s");
        thresholdLabel.getStyleClass().add("threshold-label");
        thresholdSlider = new Slider(10, 1000, 150);
        thresholdSlider.setPrefWidth(200);
        thresholdSlider.setShowTickMarks(true);
        thresholdSlider.setShowTickLabels(true);

        leakRateBox = new VBox(2);
        leakRateBox.getStyleClass().add("leak-rate-box");
        Label leakTitle = new Label("Low-Priority Access");
        leakTitle.getStyleClass().add("title-label");
        leakTitle.setStyle("-fx-font-size: 10px;");
        leakRateLabel = new Label("ALLOWED");
        leakRateLabel.getStyleClass().add("leak-rate-label");
        leakRateBox.getChildren().addAll(leakTitle, leakRateLabel);

        thresholdSlider.valueProperty().addListener((obs, oldVal, newVal) -> {
            double val = newVal.doubleValue();
            thresholdLabel.setText(String.format("Trigger: %.0f KB/s", val));
            currentThreshold.set(val);

            if (qosController != null) {
                qosController.updateThresholds(val, currentReleaseThreshold.get());
            }
        });
        thresholdBox.getStyleClass().add("threshold-box");
        thresholdBox.getChildren().addAll(thresholdLabel, thresholdSlider);

        VBox releaseBox = new VBox(2);
        releaseLabel = new Label("Release: 75 KB/s");
        releaseLabel.getStyleClass().add("release-label");
        releaseSlider = new Slider(5, 500, 75);
        releaseSlider.setPrefWidth(200);
        releaseSlider.setShowTickMarks(true);
        releaseSlider.setShowTickLabels(true);
        releaseSlider.maxProperty().bind(thresholdSlider.valueProperty().divide(2.0));
        
        releaseSlider.valueProperty().addListener((obs, oldVal, newVal) -> {
            double val = newVal.doubleValue();
            releaseLabel.setText(String.format("Release: %.0f KB/s", val));
            currentReleaseThreshold.set(val);
            if (qosController != null) {
                qosController.updateThresholds(currentThreshold.get(), val);
            }
        });
        releaseBox.getStyleClass().add("release-box");
        releaseBox.getChildren().addAll(releaseLabel, releaseSlider);

        topBox.getChildren().addAll(label, interfaceSelector, restrictChromeBtn, startButton, stopButton, thresholdBox, releaseBox, leakRateBox);
        setTop(topBox);
    }


    private LineChart<String, Number> createChart(String title, String styleClass, DoubleProperty thresholdProp, DoubleProperty releaseProp) {
        CategoryAxis xAxis = new CategoryAxis();
        xAxis.setLabel("Time");
        xAxis.setAnimated(false);
        NumberAxis yAxis = new NumberAxis();
        yAxis.setLabel("KB/s");
        yAxis.setAnimated(false);
        
        if (thresholdProp != null) {
            yAxis.setAutoRanging(false);
            yAxis.setLowerBound(0);
            yAxis.setUpperBound(1200); // Fixed range for consistent scale
            yAxis.setTickUnit(100);
        } else {
            yAxis.setForceZeroInRange(true);
        }
        LineChart<String, Number> chart = new LineChart<String, Number>(xAxis, yAxis) {
            private final Line triggerLine = new Line();
            private final Line releaseLine = new Line();
            private final Rectangle cageZone = new Rectangle();

            {
                if (thresholdProp != null) {
                    triggerLine.setStroke(Color.RED);
                    triggerLine.setStrokeWidth(2);
                    triggerLine.getStrokeDashArray().addAll(10.0, 5.0);
                    
                    releaseLine.setStroke(Color.web("#1E90FF")); // Blue
                    releaseLine.setStrokeWidth(2);
                    releaseLine.getStrokeDashArray().addAll(10.0, 5.0);
                    
                    cageZone.setFill(Color.web("#1E90FF", 0.1)); // Very faint blue background
                    
                    getPlotChildren().addAll(0, List.of(cageZone));
                    getPlotChildren().addAll(triggerLine, releaseLine);
                    
                    thresholdProp.addListener((obs, oldVal, newVal) -> requestLayout());
                    releaseProp.addListener((obs, oldVal, newVal) -> requestLayout());
                }
            }

            @Override
            protected void layoutPlotChildren() {
                super.layoutPlotChildren();
                if (thresholdProp != null && releaseProp != null) {
                    double triggerVal = thresholdProp.get();
                    double releaseVal = releaseProp.get();
                    
                    double yTrigger = getYAxis().getDisplayPosition(triggerVal);
                    double yRelease = getYAxis().getDisplayPosition(releaseVal);
                    
                    double chartWidth = getBoundsInLocal().getWidth();
                    
                    // Update Trigger Line
                    triggerLine.setStartX(0);
                    triggerLine.setEndX(chartWidth);
                    triggerLine.setStartY(yTrigger);
                    triggerLine.setEndY(yTrigger);
                    triggerLine.toFront();
                    
                    // Update Release Line
                    releaseLine.setStartX(0);
                    releaseLine.setEndX(chartWidth);
                    releaseLine.setStartY(yRelease);
                    releaseLine.setEndY(yRelease);
                    releaseLine.toFront();
                    
                    // Update Cage Zone (Area between the two lines)
                    // Note: yTrigger is typically < yRelease because large values are at the top (small pixels)
                    double top = Math.min(yTrigger, yRelease);
                    double height = Math.abs(yRelease - yTrigger);
                    
                    cageZone.setX(0);
                    cageZone.setY(top);
                    cageZone.setWidth(chartWidth);
                    cageZone.setHeight(height);
                }
            }
        };
        chart.setTitle(title);
        chart.setAnimated(false);
        chart.getStyleClass().addAll("traffic-chart", styleClass);
        chart.setCreateSymbols(false);
        return chart;
    }

    private void setupCenterPanel() {
        chartHigh = createChart("High Priority (UDP)", "chart-high", currentThreshold, currentReleaseThreshold);
        chartLow = createChart("Low Priority (TCP/QUIC)", "chart-low", null, null);

        // Compact charts to allow more space for the table below
        chartHigh.setMinHeight(280);
        chartHigh.setPrefHeight(280);
        chartLow.setMinHeight(280);
        chartLow.setPrefHeight(280);

        // Set manual axis labels to place stats beside "Time"
        chartHigh.getXAxis().setLabel(null);
        chartLow.getXAxis().setLabel(null);

        seriesHigh = new XYChart.Series<>();
        seriesHigh.setName("High");
        chartHigh.getData().add(seriesHigh);

        seriesLow = new XYChart.Series<>();
        seriesLow.setName("Low");
        chartLow.getData().add(seriesLow);

        // High Priority Stats
        highUsedLabel = new Label("0.00 KB");
        highProtectedLabel = new Label("---");
        timeLabelHigh = new Label("00:00:00.000");
        timeLabelHigh.getStyleClass().add("axis-title-small");

        HBox highStatsBox = createStatBoxDynamic("CAGE TIMER:", highProtectedLabel, "stat-high-alt");
        highProtectedTitleLabel = (Label) highStatsBox.getChildren().get(0);

        HBox highStatsRow = new HBox(15,
                createStatBoxCompact("USED:", highUsedLabel, "stat-high"),
                timeLabelHigh,
                highStatsBox
        );
        highStatsRow.setAlignment(javafx.geometry.Pos.CENTER);
        VBox highContainer = new VBox(0, chartHigh, highStatsRow);

        // Low Priority Stats
        lowUsedLabel = new Label("0.00 KB");
        lowDelayedLabel = new Label("0.00 KB");
        timeLabelLow = new Label("00:00:00.000");
        timeLabelLow.getStyleClass().add("axis-title-small");

        HBox lowStatsRow = new HBox(15,
                createStatBoxCompact("USED:", lowUsedLabel, "stat-low"),
                timeLabelLow,
                createStatBoxCompact("BLOCKED FOR:", lowDelayedLabel, "stat-low-alt")
        );
        lowStatsRow.setAlignment(javafx.geometry.Pos.CENTER);
        VBox lowContainer = new VBox(0, chartLow, lowStatsRow);

        HBox chartsBox = new HBox(20, highContainer, lowContainer);
        HBox.setHgrow(highContainer, Priority.ALWAYS);
        HBox.setHgrow(lowContainer, Priority.ALWAYS);
        chartsBox.setPadding(new Insets(5, 10, 5, 10));

        setCenter(chartsBox);
    }

    private HBox createStatBoxCompact(String title, Label valueLabel, String styleClass) {
        HBox box = new HBox(5);
        box.getStyleClass().addAll("stat-box-compact", styleClass);
        Label titleLabel = new Label(title);
        titleLabel.getStyleClass().add("stat-title-compact");
        valueLabel.getStyleClass().add("stat-value-compact");
        box.getChildren().addAll(titleLabel, valueLabel);
        box.setAlignment(javafx.geometry.Pos.CENTER);
        return box;
    }

    private HBox createStatBoxDynamic(String title, Label valueLabel, String styleClass) {
        HBox box = new HBox(5);
        box.getStyleClass().addAll("stat-box-compact", styleClass);
        Label titleLabel = new Label(title);
        titleLabel.getStyleClass().add("stat-title-compact");
        valueLabel.getStyleClass().add("stat-value-compact");
        box.getChildren().addAll(titleLabel, valueLabel);
        box.setAlignment(javafx.geometry.Pos.CENTER);
        return box;
    }

    private void setupBottomPanel() {
        packetTable = new TableView<>();
        packetTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        tableData = FXCollections.observableArrayList();
        packetTable.setItems(tableData);
        packetTable.getStyleClass().add("packet-table");
        packetTable.setPrefHeight(250);

        TableColumn<PacketData, String> timeCol = new TableColumn<>("Time");
        timeCol.setCellValueFactory(new PropertyValueFactory<>("time"));
        timeCol.setPrefWidth(150);
        timeCol.setMinWidth(120);
        timeCol.setMaxWidth(1200); // Allow some growth

        TableColumn<PacketData, String> protoCol = new TableColumn<>("Protocol");
        protoCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));

        TableColumn<PacketData, Integer> sizeCol = new TableColumn<>("Size (Bytes)");
        sizeCol.setCellValueFactory(new PropertyValueFactory<>("size"));

        TableColumn<PacketData, String> priorityCol = new TableColumn<>("Priority");
        priorityCol.setCellValueFactory(new PropertyValueFactory<>("priority"));

        TableColumn<PacketData, String> destIpCol = new TableColumn<>("Destination IP");
        destIpCol.setCellValueFactory(new PropertyValueFactory<>("destIp"));

        TableColumn<PacketData, String> controlCol = new TableColumn<>("Control Status");
        controlCol.setCellValueFactory(new PropertyValueFactory<>("status"));

        packetTable.getColumns().addAll(timeCol, protoCol, sizeCol, destIpCol, priorityCol, controlCol);
        priorityCol.setCellFactory(column -> new TableCell<PacketData, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (item == null || empty) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    if (item.equals("HIGH")) {
                        setStyle("-fx-text-fill: #FF4444; -fx-font-weight: bold;");
                    } else if (item.equals("LOW")) {
                        setStyle("-fx-text-fill: #00C851; -fx-font-weight: bold;");
                    }
                }
            }
        });

        controlCol.setCellFactory(column -> new TableCell<PacketData, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (item == null || empty) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    if (item.contains("CONTROLLED")) {
                        setStyle("-fx-text-fill: #FF8800; -fx-font-weight: bold;");
                    } else {
                        setStyle("-fx-text-fill: #33B5E5;");
                    }
                }
            }
        });


        eventLog = new ListView<>();
        eventLog.getStyleClass().add("event-log");
        eventLog.setPrefWidth(350); // Reduced width to give more space to the packet table

        HBox bottomHBox = new HBox(10, packetTable, eventLog);
        HBox.setHgrow(packetTable, Priority.ALWAYS);

        VBox bottomBox = new VBox();
        bottomBox.setPadding(new Insets(10));
        bottomBox.getChildren().add(bottomHBox);
        setBottom(bottomBox);
    }

    private void logSystemEvent(String message) {
        Platform.runLater(() -> {
            eventLog.getItems().add(0, message);
            if (eventLog.getItems().size() > 500) {
                eventLog.getItems().remove(500, eventLog.getItems().size());
            }
        });
    }

    private void startCapture() {
        PcapNetworkInterface selectedInterface = interfaceSelector.getValue();
        if (selectedInterface == null) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Please select an interface first!");
            alert.show();
            return;
        }

        startButton.setDisable(true);
        interfaceSelector.setDisable(true);
        restrictChromeBtn.setDisable(true);
        thresholdSlider.setDisable(true);
        releaseSlider.setDisable(true);
        stopButton.setDisable(false);

        seriesHigh.getData().clear();
        seriesLow.getData().clear();
        tableData.clear();
        eventLog.getItems().clear();
        updateLeakRateStatus(false);

        totalHighBytesTotal = 0;
        totalProtectedBytes = 0;
        totalLowBytesTotal = 0;
        totalDelayedBytes = 0;
        updateStats();

        boolean restrictChrome = restrictChromeBtn.isSelected();
        qosController = new QoSController(this::logSystemEvent, this::updateLeakRateStatus, restrictChrome);
        qosController.updateThresholds(currentThreshold.get(), currentReleaseThreshold.get());
        QoSEngine qosEngine = new QoSEngine(this::handleNewPacket);

        captureTask = new PacketCaptureTask(selectedInterface, qosEngine);
        captureThread = new Thread(captureTask);
        captureThread.setDaemon(true);
        captureThread.start();
        
        logSystemEvent(">>> CAPTURE STARTED ON [" + (selectedInterface.getDescription() != null ? selectedInterface.getDescription() : selectedInterface.getName()) + "]");

        startChartTimer();
    }

    private void stopCapture() {
        if (captureTask != null) {
            captureTask.stop();
        }
        if (captureThread != null) {
            captureThread.interrupt();
        }
        if (chartUpdateTimer != null) {
            chartUpdateTimer.cancel();
        }

        startButton.setDisable(false);
        interfaceSelector.setDisable(false);
        restrictChromeBtn.setDisable(false);
        thresholdSlider.setDisable(false);
        releaseSlider.setDisable(false);
        stopButton.setDisable(true);

        if (qosController != null) {
            qosController.stop();
        }
    }

    private void handleNewPacket(PacketData data) {
        // Dynamic Slider Response: increment from the very first packet of a fast-track call
        if (data.getStatus().startsWith("LIVE-VOIP") || "HIGH".equals(data.getPriority())) {
            currentHighBytes += data.getSize();
            totalHighBytesTotal += data.getSize();
            totalProtectedBytes += data.getSize();
        } else {
            currentLowBytes += data.getSize();
            totalLowBytesTotal += data.getSize();
            if (qosController != null && qosController.getCurrentState() == QoSController.ThrottleState.THROTTLED) {
                totalDelayedBytes += data.getSize();
                if ("NORMAL".equals(data.getStatus())) {
                    data.setStatus("CONTROLLED (THROTTLED)");
                }
            }
        }

        long now = System.currentTimeMillis();
        if (now - lastTableUpdateTime > 500) { // Increased from 100ms to 500ms for UI stability
            lastTableUpdateTime = now;
            Platform.runLater(() -> {
                tableData.add(0, data);
                if (tableData.size() > 20) {
                    tableData.remove(20, tableData.size());
                }
            });
        }
    }


    private void startChartTimer() {
        chartUpdateTimer = new Timer(true);
        chartUpdateTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                String timestamp = LocalTime.now().format(timeFormatter);
                double instantHighKbps = currentHighBytes / 1024.0;
                double instantLowKbps = currentLowBytes / 1024.0;

                // Signal Smoothing Logic (Moving Average)
                highKbpsHistory[highKbpsIndex % 3] = instantHighKbps;
                highKbpsIndex++;
                if (historyCount < 3) historyCount++;

                double smoothedHighKbps = 0;
                for (int i = 0; i < historyCount; i++) {
                    smoothedHighKbps += highKbpsHistory[i];
                }
                smoothedHighKbps /= historyCount;

                if (qosController != null) {
                    qosController.processHighPriorityTraffic(instantHighKbps);
                }

                currentHighBytes = 0;
                currentLowBytes = 0;

                final double highValToChart = smoothedHighKbps;
                final double lowValToChart = instantLowKbps;

                Platform.runLater(() -> {
                    timeLabelHigh.setText(timestamp);
                    timeLabelLow.setText(timestamp);
                    seriesHigh.getData().add(new XYChart.Data<>(timestamp, highValToChart));
                    seriesLow.getData().add(new XYChart.Data<>(timestamp, lowValToChart));

                    if (seriesHigh.getData().size() > MAX_DATA_POINTS) {
                        seriesHigh.getData().remove(0);
                    }
                    if (seriesLow.getData().size() > MAX_DATA_POINTS) {
                        seriesLow.getData().remove(0);
                    }
                    updateStats();
                });
            }
        }, 1000, 1000);
    }

    private void updateStats() {
        highUsedLabel.setText(formatBytes(totalHighBytesTotal));
        lowUsedLabel.setText(formatBytes(totalLowBytesTotal));
        
        if (qosController != null) {
            int stability = qosController.getStabilityCount();
            int relThreshold = qosController.getStabilityThreshold();
            int throttleCount = qosController.getThrottleStabilityCount();
            int thrThreshold = qosController.getThrottleStabilityThreshold();
            long blockedSeconds = qosController.getCurrentBlockDurationSeconds();
            
            // Dynamic Cage Timer Logic
            if (qosController.getCurrentState() == QoSController.ThrottleState.FULL_SPEED) {
                if (throttleCount > 0) {
                    highProtectedTitleLabel.setText("BLOCKING IN:");
                    highProtectedLabel.setText(String.format("%ds", thrThreshold - throttleCount));
                    highProtectedLabel.setStyle("-fx-text-fill: #FF4444; -fx-font-weight: bold;"); // Red for blocking
                } else {
                    highProtectedTitleLabel.setText("CAGE TIMER:");
                    highProtectedLabel.setText("---");
                    highProtectedLabel.setStyle("-fx-text-fill: white;");
                }
            } else if (qosController.getCurrentState() == QoSController.ThrottleState.THROTTLED) {
                if (stability > 0) {
                    highProtectedTitleLabel.setText("RELEASE IN:");
                    highProtectedLabel.setText(String.format("%ds", relThreshold - stability));
                    highProtectedLabel.setStyle("-fx-text-fill: #1E90FF; -fx-font-weight: bold;"); // Blue for release
                } else {
                    highProtectedTitleLabel.setText("STATUS:");
                    highProtectedLabel.setText("BLOCKED");
                    highProtectedLabel.setStyle("-fx-text-fill: #FF4444; -fx-font-weight: bold;"); // Red for active block
                }
            }
            
            if (blockedSeconds > 0) {
                lowDelayedLabel.setText(String.format("%ds", blockedSeconds));
            } else {
                lowDelayedLabel.setText("---");
            }
        }
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024 * 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else {
            return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
        }
    }

    private void updateLeakRateStatus(boolean throttled) {
        Platform.runLater(() -> {
            if (throttled) {
                if (!leakRateBox.getStyleClass().contains("throttled")) {
                    leakRateBox.getStyleClass().add("throttled");
                }
                leakRateLabel.setText("BLOCKED");
                leakRateLabel.setStyle("-fx-text-fill: #FF4444; -fx-font-weight: bold;");
            } else {
                leakRateBox.getStyleClass().remove("throttled");
                leakRateLabel.setText("ALLOWED");
                leakRateLabel.setStyle("-fx-text-fill: #00C851; -fx-font-weight: bold;");
            }
        });
    }

    public void cleanup() {
        stopCapture();
        if (qosController != null) {
            qosController.shutdown();
        }
    }
}
