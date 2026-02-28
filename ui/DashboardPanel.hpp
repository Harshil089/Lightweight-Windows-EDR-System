#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QTimer>

class EDRBridge;

class DashboardPanel : public QWidget {
    Q_OBJECT

public:
    explicit DashboardPanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void refreshStatus();

signals:
    void quickScanRequested();

private:
    void setupUI();
    QFrame* createStatusCard(const QString& title, const QString& value,
                             const QString& iconText, const QString& color);

    EDRBridge* bridge_;

    // Status cards
    QLabel* protectionStatusLabel_;
    QLabel* protectionStatusIcon_;
    QLabel* lastScanLabel_;
    QLabel* threatsLabel_;
    QLabel* healthLabel_;
    QFrame* healthIndicator_;

    // Quick scan button
    QPushButton* quickScanBtn_;

    // Status card frames (for dynamic styling)
    QFrame* protectionCard_;
    QFrame* lastScanCard_;
    QFrame* threatsCard_;
    QFrame* healthCard_;

    QTimer* refreshTimer_;

    // Backend connection indicator (Phase 4)
    QFrame* connectionIndicator_;
    QLabel* connectionLabel_;
};
