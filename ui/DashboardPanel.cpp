#include "DashboardPanel.hpp"
#include "EDRBridge.hpp"
#include <QPainter>

DashboardPanel::DashboardPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();

    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &DashboardPanel::refreshStatus);
    refreshTimer_->start(3000);

    refreshStatus();
}

void DashboardPanel::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(32, 28, 32, 28);
    layout->setSpacing(24);

    // Title
    QLabel* title = new QLabel("Dashboard");
    title->setProperty("class", "title");
    QFont titleFont("Segoe UI", 24, QFont::Bold);
    title->setFont(titleFont);

    QLabel* subtitle = new QLabel("Overview of your system protection status");
    subtitle->setProperty("class", "subtitle");
    QFont subFont("Segoe UI", 12);
    subtitle->setFont(subFont);

    layout->addWidget(title);
    layout->addWidget(subtitle);
    layout->addSpacing(8);

    // Status cards grid
    QGridLayout* cardGrid = new QGridLayout();
    cardGrid->setSpacing(16);

    // Protection Status Card
    protectionCard_ = new QFrame();
    protectionCard_->setObjectName("protectionCard");
    protectionCard_->setStyleSheet(
        "QFrame#protectionCard { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; padding: 20px; }");
    protectionCard_->setMinimumHeight(140);

    QVBoxLayout* pcLayout = new QVBoxLayout(protectionCard_);
    pcLayout->setContentsMargins(24, 20, 24, 20);

    QLabel* pcIcon = new QLabel();
    pcIcon->setStyleSheet("font-size: 32px;");
    pcIcon->setText("\xF0\x9F\x9B\xA1");

    QLabel* pcTitle = new QLabel("Protection Status");
    pcTitle->setProperty("class", "cardLabel");
    QFont cardLabelFont("Segoe UI", 11);
    pcTitle->setFont(cardLabelFont);

    protectionStatusLabel_ = new QLabel("Inactive");
    protectionStatusLabel_->setProperty("class", "cardValue");
    QFont cardValFont("Segoe UI", 22, QFont::Bold);
    protectionStatusLabel_->setFont(cardValFont);

    pcLayout->addWidget(pcIcon);
    pcLayout->addWidget(pcTitle);
    pcLayout->addWidget(protectionStatusLabel_);

    // Last Scan Card
    lastScanCard_ = new QFrame();
    lastScanCard_->setObjectName("lastScanCard");
    lastScanCard_->setStyleSheet(
        "QFrame#lastScanCard { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; padding: 20px; }");
    lastScanCard_->setMinimumHeight(140);

    QVBoxLayout* lsLayout = new QVBoxLayout(lastScanCard_);
    lsLayout->setContentsMargins(24, 20, 24, 20);

    QLabel* lsIcon = new QLabel("\xF0\x9F\x95\x90");
    lsIcon->setStyleSheet("font-size: 32px;");

    QLabel* lsTitle = new QLabel("Last Scan");
    lsTitle->setProperty("class", "cardLabel");
    lsTitle->setFont(cardLabelFont);

    lastScanLabel_ = new QLabel("Never");
    lastScanLabel_->setProperty("class", "cardValue");
    QFont lastScanFont("Segoe UI", 16, QFont::Bold);
    lastScanLabel_->setFont(lastScanFont);

    lsLayout->addWidget(lsIcon);
    lsLayout->addWidget(lsTitle);
    lsLayout->addWidget(lastScanLabel_);

    // Threats Detected Card
    threatsCard_ = new QFrame();
    threatsCard_->setObjectName("threatsCard");
    threatsCard_->setStyleSheet(
        "QFrame#threatsCard { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; padding: 20px; }");
    threatsCard_->setMinimumHeight(140);

    QVBoxLayout* tdLayout = new QVBoxLayout(threatsCard_);
    tdLayout->setContentsMargins(24, 20, 24, 20);

    QLabel* tdIcon = new QLabel("\xE2\x9A\xA0");
    tdIcon->setStyleSheet("font-size: 32px;");

    QLabel* tdTitle = new QLabel("Threats Detected");
    tdTitle->setProperty("class", "cardLabel");
    tdTitle->setFont(cardLabelFont);

    threatsLabel_ = new QLabel("0");
    threatsLabel_->setProperty("class", "cardValue");
    threatsLabel_->setFont(cardValFont);
    threatsLabel_->setStyleSheet("color: #4CAF50;");

    tdLayout->addWidget(tdIcon);
    tdLayout->addWidget(tdTitle);
    tdLayout->addWidget(threatsLabel_);

    // System Health Card
    healthCard_ = new QFrame();
    healthCard_->setObjectName("healthCard");
    healthCard_->setStyleSheet(
        "QFrame#healthCard { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; padding: 20px; }");
    healthCard_->setMinimumHeight(140);

    QVBoxLayout* shLayout = new QVBoxLayout(healthCard_);
    shLayout->setContentsMargins(24, 20, 24, 20);

    QLabel* shIcon = new QLabel("\xF0\x9F\x92\x9A");
    shIcon->setStyleSheet("font-size: 32px;");

    QLabel* shTitle = new QLabel("System Health");
    shTitle->setProperty("class", "cardLabel");
    shTitle->setFont(cardLabelFont);

    healthLabel_ = new QLabel("Unknown");
    healthLabel_->setProperty("class", "cardValue");
    QFont healthFont("Segoe UI", 18, QFont::Bold);
    healthLabel_->setFont(healthFont);

    healthIndicator_ = new QFrame();
    healthIndicator_->setFixedSize(12, 12);
    healthIndicator_->setStyleSheet("background-color: #8B949E; border-radius: 6px;");

    QHBoxLayout* healthRow = new QHBoxLayout();
    healthRow->addWidget(healthIndicator_);
    healthRow->addWidget(healthLabel_);
    healthRow->addStretch();

    shLayout->addWidget(shIcon);
    shLayout->addWidget(shTitle);
    shLayout->addLayout(healthRow);

    cardGrid->addWidget(protectionCard_, 0, 0);
    cardGrid->addWidget(lastScanCard_, 0, 1);
    cardGrid->addWidget(threatsCard_, 1, 0);
    cardGrid->addWidget(healthCard_, 1, 1);

    layout->addLayout(cardGrid);

    // Quick Scan Button
    QHBoxLayout* actionLayout = new QHBoxLayout();

    quickScanBtn_ = new QPushButton("  Run Quick Scan  ");
    quickScanBtn_->setProperty("class", "primary");
    quickScanBtn_->setMinimumHeight(50);
    quickScanBtn_->setCursor(Qt::PointingHandCursor);
    QFont btnFont("Segoe UI", 14, QFont::Bold);
    quickScanBtn_->setFont(btnFont);
    quickScanBtn_->setMinimumWidth(280);

    connect(quickScanBtn_, &QPushButton::clicked, this, [this]() {
        emit quickScanRequested();
    });

    actionLayout->addStretch();
    actionLayout->addWidget(quickScanBtn_);
    actionLayout->addStretch();

    layout->addSpacing(8);
    layout->addLayout(actionLayout);
    layout->addStretch();
}

void DashboardPanel::refreshStatus()
{
    // Protection status
    bool active = bridge_->isProtectionActive();
    protectionStatusLabel_->setText(active ? "Active" : "Inactive");
    protectionStatusLabel_->setStyleSheet(active ? "color: #4CAF50;" : "color: #F44336;");
    protectionCard_->setStyleSheet(
        active
        ? "QFrame#protectionCard { background-color: #161B22; border: 1px solid #4CAF50; border-radius: 12px; }"
        : "QFrame#protectionCard { background-color: #161B22; border: 1px solid #F44336; border-radius: 12px; }"
    );

    // Last scan
    QDateTime lastScan = bridge_->lastScanTime();
    if (lastScan.isValid()) {
        lastScanLabel_->setText(lastScan.toString("MMM d, hh:mm"));
    } else {
        lastScanLabel_->setText("Never");
    }

    // Threats
    int threats = bridge_->totalThreats();
    threatsLabel_->setText(QString::number(threats));
    if (threats > 0) {
        threatsLabel_->setStyleSheet("color: #F44336;");
        threatsCard_->setStyleSheet(
            "QFrame#threatsCard { background-color: #161B22; border: 1px solid #F44336; border-radius: 12px; }");
    } else {
        threatsLabel_->setStyleSheet("color: #4CAF50;");
        threatsCard_->setStyleSheet(
            "QFrame#threatsCard { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; }");
    }

    // System health
    QString health = bridge_->systemHealthStatus();
    if (health == "Green") {
        healthLabel_->setText("Healthy");
        healthLabel_->setStyleSheet("color: #4CAF50;");
        healthIndicator_->setStyleSheet("background-color: #4CAF50; border-radius: 6px;");
    } else if (health == "Yellow") {
        healthLabel_->setText("At Risk");
        healthLabel_->setStyleSheet("color: #FF9800;");
        healthIndicator_->setStyleSheet("background-color: #FF9800; border-radius: 6px;");
    } else {
        healthLabel_->setText("Unprotected");
        healthLabel_->setStyleSheet("color: #F44336;");
        healthIndicator_->setStyleSheet("background-color: #F44336; border-radius: 6px;");
    }
}
