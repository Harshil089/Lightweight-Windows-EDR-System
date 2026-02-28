#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFrame>

class EDRBridge;

class RealTimeProtectionPanel : public QWidget {
    Q_OBJECT

public:
    explicit RealTimeProtectionPanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void refreshStatus();

private slots:
    void onToggleClicked();

private:
    void setupUI();
    void updateUI(bool active);
    QFrame* createMonitorRow(const QString& icon, const QString& name, QLabel*& statusLabel);

    EDRBridge* bridge_;

    QPushButton* toggleBtn_;
    QLabel* statusLabel_;
    QLabel* statusDescLabel_;

    // Monitor status labels
    QLabel* processMonitorStatus_;
    QLabel* registryMonitorStatus_;
    QLabel* fileSystemStatus_;
    QLabel* networkMonitorStatus_;
};
