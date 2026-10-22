package com.qosvisualizer;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    private DashboardUI dashboardUI;

    @Override
    public void start(Stage primaryStage) {
        dashboardUI = new DashboardUI();
        
        Scene scene = new Scene(dashboardUI, 1000, 700);
        String css = getClass().getResource("/style.css").toExternalForm();
        scene.getStylesheets().add(css);
        
        primaryStage.setTitle("Real-Time Network QoS Visualizer");
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(800);
        primaryStage.setMinHeight(600);
        primaryStage.setOnCloseRequest(e -> {
            dashboardUI.cleanup();
            System.exit(0);
        });
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
