#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QListWidget>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <memory>

class EDRBridge;
class DashboardPanel;
class QuickScanPanel;
class FullScanPanel;
class RealTimeProtectionPanel;
class SettingsPanel;
class QuarantinePanel;
class LogsPanel;
class AboutPanel;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(EDRBridge* bridge, QWidget* parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onNavigationChanged(int index);
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void showThreatNotification(const QString& threatName, const QString& filePath);

private:
    void setupUI();
    void setupSidebar();
    void setupContentArea();
    void setupSystemTray();
    void applyStylesheet();

    EDRBridge* bridge_;

    // Layout
    QWidget* centralWidget_;
    QHBoxLayout* mainLayout_;

    // Sidebar
    QWidget* sidebarWidget_;
    QVBoxLayout* sidebarLayout_;
    QListWidget* navList_;
    QLabel* logoLabel_;

    // Content
    QStackedWidget* contentStack_;

    // Panels
    DashboardPanel* dashboardPanel_;
    QuickScanPanel* quickScanPanel_;
    FullScanPanel* fullScanPanel_;
    RealTimeProtectionPanel* rtpPanel_;
    SettingsPanel* settingsPanel_;
    QuarantinePanel* quarantinePanel_;
    LogsPanel* logsPanel_;
    AboutPanel* aboutPanel_;

    // System tray
    QSystemTrayIcon* trayIcon_;
    QMenu* trayMenu_;
};
