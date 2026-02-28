#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QFrame>

class EDRBridge;

class FullScanPanel : public QWidget {
    Q_OBJECT

public:
    explicit FullScanPanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void startScan();
    void onProgressChanged(int percent);
    void onCurrentFileChanged(const QString& filePath);
    void onThreatDetected(const QString& filePath, const QString& threatName);
    void onScanFinished(int totalFiles, int threatsFound);
    void onEstimatedTimeChanged(const QString& timeRemaining);

private:
    void setupUI();
    void setIdleState();
    void setScanningState();

    EDRBridge* bridge_;

    QLabel* titleLabel_;
    QLabel* statusLabel_;
    QLabel* currentFileLabel_;
    QLabel* threatsCountLabel_;
    QLabel* estimatedTimeLabel_;
    QProgressBar* progressBar_;
    QPushButton* startBtn_;
    QPushButton* pauseBtn_;
    QPushButton* resumeBtn_;
    QPushButton* cancelBtn_;
    QTextEdit* directoryLog_;

    bool isPaused_{false};
    int threatsFound_{0};
};
