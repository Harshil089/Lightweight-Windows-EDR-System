#include "MainWindow.hpp"
#include "EDRBridge.hpp"
#include "DashboardPanel.hpp"
#include "QuickScanPanel.hpp"
#include "FullScanPanel.hpp"
#include "RealTimeProtectionPanel.hpp"
#include "SettingsPanel.hpp"
#include "QuarantinePanel.hpp"
#include "LogsPanel.hpp"
#include "AboutPanel.hpp"
#include <QCloseEvent>
#include <QApplication>
#include <QFont>
#include <QIcon>
#include <QFile>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>

MainWindow::MainWindow(EDRBridge* bridge, QWidget* parent)
    : QMainWindow(parent), bridge_(bridge)
{
    setWindowTitle("CortexEDR - Endpoint Detection & Response");
    setMinimumSize(1100, 700);
    resize(1280, 800);

    setupUI();
    setupSystemTray();
    applyStylesheet();

    // Connect threat notifications
    connect(bridge_, &EDRBridge::threatNotification,
            this, &MainWindow::showThreatNotification);
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUI()
{
    centralWidget_ = new QWidget(this);
    setCentralWidget(centralWidget_);

    mainLayout_ = new QHBoxLayout(centralWidget_);
    mainLayout_->setContentsMargins(0, 0, 0, 0);
    mainLayout_->setSpacing(0);

    setupSidebar();
    setupContentArea();

    mainLayout_->addWidget(sidebarWidget_);
    mainLayout_->addWidget(contentStack_, 1);
}

void MainWindow::setupSidebar()
{
    sidebarWidget_ = new QWidget();
    sidebarWidget_->setObjectName("sidebar");
    sidebarWidget_->setFixedWidth(240);

    sidebarLayout_ = new QVBoxLayout(sidebarWidget_);
    sidebarLayout_->setContentsMargins(0, 0, 0, 0);
    sidebarLayout_->setSpacing(0);

    // Logo/Title area
    QWidget* logoArea = new QWidget();
    logoArea->setObjectName("logoArea");
    logoArea->setFixedHeight(80);
    QVBoxLayout* logoLayout = new QVBoxLayout(logoArea);
    logoLayout->setContentsMargins(20, 15, 20, 15);

    logoLabel_ = new QLabel("CortexEDR");
    logoLabel_->setObjectName("logoLabel");
    QFont logoFont("Segoe UI", 18, QFont::Bold);
    logoLabel_->setFont(logoFont);

    QLabel* subtitleLabel = new QLabel("Endpoint Protection");
    subtitleLabel->setObjectName("subtitleLabel");
    QFont subFont("Segoe UI", 9);
    subtitleLabel->setFont(subFont);

    logoLayout->addWidget(logoLabel_);
    logoLayout->addWidget(subtitleLabel);

    // Navigation list
    navList_ = new QListWidget();
    navList_->setObjectName("navList");
    navList_->setFrameShape(QFrame::NoFrame);
    navList_->setIconSize(QSize(20, 20));

    struct NavItem {
        QString icon;
        QString text;
    };

    NavItem items[] = {
        {"\xF0\x9F\x9B\xA1", "  Dashboard"},
        {"\xF0\x9F\x94\x8D", "  Quick Scan"},
        {"\xF0\x9F\x93\x82", "  Full System Scan"},
        {"\xF0\x9F\xA7\xA0", "  Real-Time Protection"},
        {"\xE2\x9A\x99",     "  Settings"},
        {"\xF0\x9F\x97\x91", "  Quarantine"},
        {"\xF0\x9F\x93\x8A", "  Logs"},
        {"\xE2\x9D\x93",     "  About"}
    };

    for (const auto& item : items) {
        QListWidgetItem* listItem = new QListWidgetItem(item.icon + item.text);
        listItem->setSizeHint(QSize(240, 48));
        QFont itemFont("Segoe UI", 11);
        listItem->setFont(itemFont);
        navList_->addItem(listItem);
    }

    navList_->setCurrentRow(0);
    connect(navList_, &QListWidget::currentRowChanged,
            this, &MainWindow::onNavigationChanged);

    // Version label at bottom
    QLabel* versionLabel = new QLabel("v1.0.0");
    versionLabel->setObjectName("versionLabel");
    versionLabel->setAlignment(Qt::AlignCenter);
    QFont vFont("Segoe UI", 8);
    versionLabel->setFont(vFont);

    sidebarLayout_->addWidget(logoArea);
    sidebarLayout_->addWidget(navList_, 1);
    sidebarLayout_->addWidget(versionLabel);
    sidebarLayout_->addSpacing(10);
}

void MainWindow::setupContentArea()
{
    contentStack_ = new QStackedWidget();
    contentStack_->setObjectName("contentStack");

    dashboardPanel_ = new DashboardPanel(bridge_);
    quickScanPanel_ = new QuickScanPanel(bridge_);
    fullScanPanel_ = new FullScanPanel(bridge_);
    rtpPanel_ = new RealTimeProtectionPanel(bridge_);
    settingsPanel_ = new SettingsPanel(bridge_);
    quarantinePanel_ = new QuarantinePanel(bridge_);
    logsPanel_ = new LogsPanel(bridge_);
    aboutPanel_ = new AboutPanel();

    contentStack_->addWidget(dashboardPanel_);    // 0
    contentStack_->addWidget(quickScanPanel_);     // 1
    contentStack_->addWidget(fullScanPanel_);      // 2
    contentStack_->addWidget(rtpPanel_);           // 3
    contentStack_->addWidget(settingsPanel_);      // 4
    contentStack_->addWidget(quarantinePanel_);    // 5
    contentStack_->addWidget(logsPanel_);          // 6
    contentStack_->addWidget(aboutPanel_);         // 7

    // Connect dashboard quick scan to navigation
    connect(dashboardPanel_, &DashboardPanel::quickScanRequested, this, [this]() {
        navList_->setCurrentRow(1);
        quickScanPanel_->startScan();
    });

    // Connect scan signals to panels
    connect(bridge_, &EDRBridge::scanProgressChanged, quickScanPanel_, &QuickScanPanel::onProgressChanged);
    connect(bridge_, &EDRBridge::scanCurrentFileChanged, quickScanPanel_, &QuickScanPanel::onCurrentFileChanged);
    connect(bridge_, &EDRBridge::scanThreatDetected, quickScanPanel_, &QuickScanPanel::onThreatDetected);
    connect(bridge_, &EDRBridge::scanFinished, quickScanPanel_, &QuickScanPanel::onScanFinished);

    connect(bridge_, &EDRBridge::scanProgressChanged, fullScanPanel_, &FullScanPanel::onProgressChanged);
    connect(bridge_, &EDRBridge::scanCurrentFileChanged, fullScanPanel_, &FullScanPanel::onCurrentFileChanged);
    connect(bridge_, &EDRBridge::scanThreatDetected, fullScanPanel_, &FullScanPanel::onThreatDetected);
    connect(bridge_, &EDRBridge::scanFinished, fullScanPanel_, &FullScanPanel::onScanFinished);
    connect(bridge_, &EDRBridge::scanEstimatedTimeChanged, fullScanPanel_, &FullScanPanel::onEstimatedTimeChanged);
}

void MainWindow::onNavigationChanged(int index)
{
    contentStack_->setCurrentIndex(index);

    // Refresh data when navigating to certain panels
    switch (index) {
        case 0: dashboardPanel_->refreshStatus(); break;
        case 3: rtpPanel_->refreshStatus(); break;
        case 5: quarantinePanel_->refreshTable(); break;
        case 6: logsPanel_->refreshLogs(); break;
        default: break;
    }
}

// ─── System Tray ─────────────────────────────────────────────────────────────

void MainWindow::setupSystemTray()
{
    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setToolTip("CortexEDR - Endpoint Protection");

    // Create a simple icon programmatically
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setBrush(QColor("#00BCD4"));
    painter.setPen(Qt::NoPen);
    painter.drawEllipse(2, 2, 28, 28);
    painter.setPen(QPen(Qt::white, 2));
    painter.drawText(pixmap.rect(), Qt::AlignCenter, "C");
    painter.end();

    trayIcon_->setIcon(QIcon(pixmap));

    trayMenu_ = new QMenu(this);
    trayMenu_->addAction("Show CortexEDR", this, [this]() {
        show();
        raise();
        activateWindow();
    });
    trayMenu_->addSeparator();
    trayMenu_->addAction("Quick Scan", this, [this]() {
        show();
        navList_->setCurrentRow(1);
        quickScanPanel_->startScan();
    });
    trayMenu_->addSeparator();
    trayMenu_->addAction("Exit", qApp, &QApplication::quit);

    trayIcon_->setContextMenu(trayMenu_);
    trayIcon_->show();

    connect(trayIcon_, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayActivated);
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        if (isVisible()) {
            hide();
        } else {
            show();
            raise();
            activateWindow();
        }
    }
}

void MainWindow::showThreatNotification(const QString& threatName, const QString& filePath)
{
    if (trayIcon_ && trayIcon_->isVisible()) {
        trayIcon_->showMessage(
            "Threat Detected",
            QString("%1\n%2").arg(threatName, filePath),
            QSystemTrayIcon::Warning,
            5000
        );
    }
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    // Minimize to tray instead of closing
    if (trayIcon_ && trayIcon_->isVisible()) {
        hide();
        trayIcon_->showMessage(
            "CortexEDR",
            "Application minimized to system tray. Double-click to restore.",
            QSystemTrayIcon::Information,
            2000
        );
        event->ignore();
    } else {
        event->accept();
    }
}

// ─── Stylesheet ──────────────────────────────────────────────────────────────

void MainWindow::applyStylesheet()
{
    QString style = R"(
    /* ═══════════════════════════════════════════════════════════
       CortexEDR Dark Theme - Cybersecurity Color Palette
       Primary: #0D1117 (deep dark)
       Secondary: #161B22 (card dark)
       Accent: #00BCD4 (teal)
       Accent2: #2196F3 (blue)
       Success: #4CAF50 (green)
       Warning: #FF9800 (orange)
       Danger: #F44336 (red)
       Text: #E6EDF3 (light gray)
       TextDim: #8B949E (muted)
       Border: #30363D (subtle border)
       ═══════════════════════════════════════════════════════════ */

    * {
        font-family: "Segoe UI", sans-serif;
    }

    QMainWindow {
        background-color: #0D1117;
    }

    /* ─── Sidebar ──────────────────────────────────────────── */

    #sidebar {
        background-color: #0D1117;
        border-right: 1px solid #30363D;
    }

    #logoArea {
        background-color: #0D1117;
        border-bottom: 1px solid #30363D;
    }

    #logoLabel {
        color: #00BCD4;
        font-size: 20px;
        font-weight: bold;
    }

    #subtitleLabel {
        color: #8B949E;
        font-size: 10px;
    }

    #versionLabel {
        color: #484F58;
        font-size: 9px;
        padding: 8px;
    }

    #navList {
        background-color: transparent;
        border: none;
        padding: 8px;
    }

    #navList::item {
        color: #8B949E;
        padding: 12px 16px;
        border-radius: 8px;
        margin: 2px 4px;
    }

    #navList::item:hover {
        background-color: #161B22;
        color: #E6EDF3;
    }

    #navList::item:selected {
        background-color: rgba(0, 188, 212, 0.15);
        color: #00BCD4;
        border-left: 3px solid #00BCD4;
    }

    /* ─── Content Area ─────────────────────────────────────── */

    #contentStack {
        background-color: #0D1117;
    }

    /* ─── Common Card Style ────────────────────────────────── */

    .card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 12px;
        padding: 20px;
    }

    QFrame[class="card"] {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 12px;
    }

    /* ─── Labels ───────────────────────────────────────────── */

    QLabel {
        color: #E6EDF3;
    }

    QLabel[class="title"] {
        font-size: 24px;
        font-weight: bold;
        color: #E6EDF3;
    }

    QLabel[class="subtitle"] {
        font-size: 14px;
        color: #8B949E;
    }

    QLabel[class="sectionTitle"] {
        font-size: 16px;
        font-weight: 600;
        color: #E6EDF3;
    }

    QLabel[class="cardValue"] {
        font-size: 28px;
        font-weight: bold;
    }

    QLabel[class="cardLabel"] {
        font-size: 12px;
        color: #8B949E;
    }

    QLabel[class="dimText"] {
        color: #8B949E;
        font-size: 12px;
    }

    /* ─── Buttons ──────────────────────────────────────────── */

    QPushButton {
        background-color: #21262D;
        color: #E6EDF3;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 10px 24px;
        font-size: 13px;
        font-weight: 500;
    }

    QPushButton:hover {
        background-color: #30363D;
        border-color: #484F58;
    }

    QPushButton:pressed {
        background-color: #0D1117;
    }

    QPushButton:disabled {
        background-color: #161B22;
        color: #484F58;
        border-color: #21262D;
    }

    QPushButton[class="primary"] {
        background-color: #00BCD4;
        color: #FFFFFF;
        border: none;
        font-weight: 600;
    }

    QPushButton[class="primary"]:hover {
        background-color: #00ACC1;
    }

    QPushButton[class="primary"]:pressed {
        background-color: #0097A7;
    }

    QPushButton[class="danger"] {
        background-color: #F44336;
        color: #FFFFFF;
        border: none;
    }

    QPushButton[class="danger"]:hover {
        background-color: #E53935;
    }

    QPushButton[class="success"] {
        background-color: #4CAF50;
        color: #FFFFFF;
        border: none;
    }

    QPushButton[class="success"]:hover {
        background-color: #43A047;
    }

    QPushButton[class="warning"] {
        background-color: #FF9800;
        color: #FFFFFF;
        border: none;
    }

    QPushButton#toggleOn {
        background-color: #4CAF50;
        color: white;
        border: none;
        border-radius: 20px;
        padding: 12px 40px;
        font-size: 15px;
        font-weight: bold;
    }

    QPushButton#toggleOn:hover {
        background-color: #43A047;
    }

    QPushButton#toggleOff {
        background-color: #F44336;
        color: white;
        border: none;
        border-radius: 20px;
        padding: 12px 40px;
        font-size: 15px;
        font-weight: bold;
    }

    QPushButton#toggleOff:hover {
        background-color: #E53935;
    }

    /* ─── Progress Bar ─────────────────────────────────────── */

    QProgressBar {
        background-color: #21262D;
        border: 1px solid #30363D;
        border-radius: 6px;
        text-align: center;
        color: #E6EDF3;
        font-size: 12px;
        min-height: 24px;
    }

    QProgressBar::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 #00BCD4, stop:1 #2196F3);
        border-radius: 5px;
    }

    /* ─── Tables ───────────────────────────────────────────── */

    QTableWidget {
        background-color: #0D1117;
        alternate-background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 8px;
        gridline-color: #21262D;
        color: #E6EDF3;
        selection-background-color: rgba(0, 188, 212, 0.2);
        selection-color: #E6EDF3;
    }

    QTableWidget::item {
        padding: 8px;
    }

    QHeaderView::section {
        background-color: #161B22;
        color: #8B949E;
        border: none;
        border-bottom: 1px solid #30363D;
        padding: 10px 8px;
        font-weight: 600;
        font-size: 12px;
    }

    /* ─── Text Edit / Log Viewer ───────────────────────────── */

    QTextEdit {
        background-color: #0D1117;
        color: #8B949E;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 8px;
        font-family: "Cascadia Code", "Consolas", monospace;
        font-size: 11px;
    }

    /* ─── ComboBox ─────────────────────────────────────────── */

    QComboBox {
        background-color: #21262D;
        color: #E6EDF3;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 8px 12px;
        font-size: 12px;
        min-width: 150px;
    }

    QComboBox:hover {
        border-color: #484F58;
    }

    QComboBox::drop-down {
        border: none;
        width: 24px;
    }

    QComboBox QAbstractItemView {
        background-color: #21262D;
        color: #E6EDF3;
        border: 1px solid #30363D;
        selection-background-color: rgba(0, 188, 212, 0.2);
    }

    /* ─── Slider ───────────────────────────────────────────── */

    QSlider::groove:horizontal {
        background: #21262D;
        height: 6px;
        border-radius: 3px;
    }

    QSlider::handle:horizontal {
        background: #00BCD4;
        width: 18px;
        height: 18px;
        margin: -6px 0;
        border-radius: 9px;
    }

    QSlider::handle:horizontal:hover {
        background: #26C6DA;
    }

    QSlider::sub-page:horizontal {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 #00BCD4, stop:1 #2196F3);
        border-radius: 3px;
    }

    /* ─── CheckBox ─────────────────────────────────────────── */

    QCheckBox {
        color: #E6EDF3;
        font-size: 13px;
        spacing: 8px;
    }

    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 4px;
        border: 2px solid #30363D;
        background-color: #21262D;
    }

    QCheckBox::indicator:checked {
        background-color: #00BCD4;
        border-color: #00BCD4;
    }

    QCheckBox::indicator:hover {
        border-color: #00BCD4;
    }

    /* ─── List Widget (Exclusions) ─────────────────────────── */

    QListWidget {
        background-color: #0D1117;
        border: 1px solid #30363D;
        border-radius: 8px;
        color: #E6EDF3;
        padding: 4px;
    }

    QListWidget::item {
        padding: 8px;
        border-radius: 4px;
    }

    QListWidget::item:selected {
        background-color: rgba(0, 188, 212, 0.15);
    }

    /* ─── Scrollbars ───────────────────────────────────────── */

    QScrollBar:vertical {
        background: #0D1117;
        width: 8px;
        border-radius: 4px;
    }

    QScrollBar::handle:vertical {
        background: #30363D;
        border-radius: 4px;
        min-height: 30px;
    }

    QScrollBar::handle:vertical:hover {
        background: #484F58;
    }

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0;
    }

    QScrollBar:horizontal {
        background: #0D1117;
        height: 8px;
        border-radius: 4px;
    }

    QScrollBar::handle:horizontal {
        background: #30363D;
        border-radius: 4px;
        min-width: 30px;
    }

    QScrollBar::handle:horizontal:hover {
        background: #484F58;
    }

    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0;
    }

    /* ─── Tooltips ─────────────────────────────────────────── */

    QToolTip {
        background-color: #21262D;
        color: #E6EDF3;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 12px;
    }

    /* ─── Message Box ──────────────────────────────────────── */

    QMessageBox {
        background-color: #161B22;
    }

    QMessageBox QLabel {
        color: #E6EDF3;
    }

    QMessageBox QPushButton {
        min-width: 80px;
    }

    /* ─── Menu (Tray) ──────────────────────────────────────── */

    QMenu {
        background-color: #21262D;
        color: #E6EDF3;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 4px;
    }

    QMenu::item {
        padding: 8px 24px;
        border-radius: 4px;
    }

    QMenu::item:selected {
        background-color: rgba(0, 188, 212, 0.2);
    }

    QMenu::separator {
        height: 1px;
        background-color: #30363D;
        margin: 4px 8px;
    }
    )";

    setStyleSheet(style);
}
