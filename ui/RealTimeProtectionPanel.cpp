#include "RealTimeProtectionPanel.hpp"
#include "EDRBridge.hpp"

RealTimeProtectionPanel::RealTimeProtectionPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
    refreshStatus();
}

void RealTimeProtectionPanel::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(32, 28, 32, 28);
    layout->setSpacing(24);

    // Title
    QLabel* title = new QLabel("Real-Time Protection");
    title->setProperty("class", "title");
    QFont titleFont("Segoe UI", 24, QFont::Bold);
    title->setFont(titleFont);

    QLabel* desc = new QLabel("Monitor your system in real-time for threats and suspicious activity");
    desc->setProperty("class", "subtitle");
    desc->setWordWrap(true);

    layout->addWidget(title);
    layout->addWidget(desc);
    layout->addSpacing(16);

    // Toggle card
    QFrame* toggleCard = new QFrame();
    toggleCard->setObjectName("toggleCard");
    toggleCard->setStyleSheet(
        "QFrame#toggleCard { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; }");
    toggleCard->setMinimumHeight(160);

    QVBoxLayout* toggleLayout = new QVBoxLayout(toggleCard);
    toggleLayout->setContentsMargins(32, 28, 32, 28);
    toggleLayout->setSpacing(12);
    toggleLayout->setAlignment(Qt::AlignCenter);

    statusLabel_ = new QLabel("Protection Disabled");
    QFont statFont("Segoe UI", 20, QFont::Bold);
    statusLabel_->setFont(statFont);
    statusLabel_->setAlignment(Qt::AlignCenter);
    statusLabel_->setStyleSheet("color: #F44336;");

    statusDescLabel_ = new QLabel("Your device may be vulnerable to threats");
    statusDescLabel_->setProperty("class", "subtitle");
    statusDescLabel_->setAlignment(Qt::AlignCenter);

    toggleBtn_ = new QPushButton("Enable Protection");
    toggleBtn_->setObjectName("toggleOff");
    toggleBtn_->setMinimumHeight(48);
    toggleBtn_->setMinimumWidth(220);
    toggleBtn_->setCursor(Qt::PointingHandCursor);
    QFont toggleFont("Segoe UI", 14, QFont::Bold);
    toggleBtn_->setFont(toggleFont);

    connect(toggleBtn_, &QPushButton::clicked, this, &RealTimeProtectionPanel::onToggleClicked);

    toggleLayout->addWidget(statusLabel_);
    toggleLayout->addWidget(statusDescLabel_);
    toggleLayout->addSpacing(8);
    toggleLayout->addWidget(toggleBtn_, 0, Qt::AlignCenter);

    layout->addWidget(toggleCard);

    // Monitored processes section
    QLabel* monitorTitle = new QLabel("Monitoring Status");
    monitorTitle->setProperty("class", "sectionTitle");
    QFont secFont("Segoe UI", 16, QFont::DemiBold);
    monitorTitle->setFont(secFont);

    layout->addWidget(monitorTitle);

    // Monitor rows
    QFrame* monitorCard = new QFrame();
    monitorCard->setObjectName("monitorCard");
    monitorCard->setStyleSheet(
        "QFrame#monitorCard { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; }");

    QVBoxLayout* monitorLayout = new QVBoxLayout(monitorCard);
    monitorLayout->setContentsMargins(24, 16, 24, 16);
    monitorLayout->setSpacing(0);

    monitorLayout->addWidget(createMonitorRow("\xF0\x9F\x94\x84", "Process Monitor (ETW)", processMonitorStatus_));

    QFrame* sep1 = new QFrame();
    sep1->setFrameShape(QFrame::HLine);
    sep1->setStyleSheet("background-color: #21262D; max-height: 1px;");
    monitorLayout->addWidget(sep1);

    monitorLayout->addWidget(createMonitorRow("\xF0\x9F\x93\x9D", "Registry Monitor", registryMonitorStatus_));

    QFrame* sep2 = new QFrame();
    sep2->setFrameShape(QFrame::HLine);
    sep2->setStyleSheet("background-color: #21262D; max-height: 1px;");
    monitorLayout->addWidget(sep2);

    monitorLayout->addWidget(createMonitorRow("\xF0\x9F\x93\x81", "File System Hook", fileSystemStatus_));

    QFrame* sep3 = new QFrame();
    sep3->setFrameShape(QFrame::HLine);
    sep3->setStyleSheet("background-color: #21262D; max-height: 1px;");
    monitorLayout->addWidget(sep3);

    monitorLayout->addWidget(createMonitorRow("\xF0\x9F\x8C\x90", "Network Monitor", networkMonitorStatus_));

    layout->addWidget(monitorCard);
    layout->addStretch();
}

QFrame* RealTimeProtectionPanel::createMonitorRow(const QString& icon, const QString& name, QLabel*& statusLabel)
{
    QFrame* row = new QFrame();
    QHBoxLayout* rowLayout = new QHBoxLayout(row);
    rowLayout->setContentsMargins(8, 12, 8, 12);

    QLabel* iconLabel = new QLabel(icon);
    iconLabel->setStyleSheet("font-size: 20px;");
    iconLabel->setFixedWidth(32);

    QLabel* nameLabel = new QLabel(name);
    QFont nameFont("Segoe UI", 13);
    nameLabel->setFont(nameFont);

    statusLabel = new QLabel("Inactive");
    QFont statusFont("Segoe UI", 12, QFont::DemiBold);
    statusLabel->setFont(statusFont);
    statusLabel->setStyleSheet("color: #8B949E;");
    statusLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    rowLayout->addWidget(iconLabel);
    rowLayout->addWidget(nameLabel, 1);
    rowLayout->addWidget(statusLabel);

    return row;
}

void RealTimeProtectionPanel::onToggleClicked()
{
    if (bridge_->isProtectionActive()) {
        bridge_->disableRealTimeProtection();
    } else {
        bridge_->enableRealTimeProtection();
    }
    refreshStatus();
}

void RealTimeProtectionPanel::refreshStatus()
{
    bool active = bridge_->isProtectionActive();
    updateUI(active);
}

void RealTimeProtectionPanel::updateUI(bool active)
{
    if (active) {
        statusLabel_->setText("Protection Active");
        statusLabel_->setStyleSheet("color: #4CAF50;");
        statusDescLabel_->setText("Your device is being monitored for threats in real-time");
        toggleBtn_->setText("Disable Protection");
        toggleBtn_->setObjectName("toggleOn");
        toggleBtn_->setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; border: none; "
            "border-radius: 20px; padding: 12px 40px; font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background-color: #43A047; }");

        processMonitorStatus_->setText("Active");
        processMonitorStatus_->setStyleSheet("color: #4CAF50; font-weight: bold;");
        registryMonitorStatus_->setText("Active");
        registryMonitorStatus_->setStyleSheet("color: #4CAF50; font-weight: bold;");
        fileSystemStatus_->setText("Active");
        fileSystemStatus_->setStyleSheet("color: #4CAF50; font-weight: bold;");
        networkMonitorStatus_->setText("Active");
        networkMonitorStatus_->setStyleSheet("color: #4CAF50; font-weight: bold;");
    } else {
        statusLabel_->setText("Protection Disabled");
        statusLabel_->setStyleSheet("color: #F44336;");
        statusDescLabel_->setText("Your device may be vulnerable to threats");
        toggleBtn_->setText("Enable Protection");
        toggleBtn_->setObjectName("toggleOff");
        toggleBtn_->setStyleSheet(
            "QPushButton { background-color: #F44336; color: white; border: none; "
            "border-radius: 20px; padding: 12px 40px; font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background-color: #E53935; }");

        processMonitorStatus_->setText("Inactive");
        processMonitorStatus_->setStyleSheet("color: #8B949E;");
        registryMonitorStatus_->setText("Inactive");
        registryMonitorStatus_->setStyleSheet("color: #8B949E;");
        fileSystemStatus_->setText("Inactive");
        fileSystemStatus_->setStyleSheet("color: #8B949E;");
        networkMonitorStatus_->setText("Inactive");
        networkMonitorStatus_->setStyleSheet("color: #8B949E;");
    }
}
