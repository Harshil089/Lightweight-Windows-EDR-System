#include "AboutPanel.hpp"

AboutPanel::AboutPanel(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

void AboutPanel::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(32, 28, 32, 28);
    layout->setSpacing(16);

    // Title
    QLabel* title = new QLabel("About CortexEDR");
    title->setProperty("class", "title");
    QFont titleFont("Segoe UI", 24, QFont::Bold);
    title->setFont(titleFont);

    layout->addWidget(title);
    layout->addSpacing(24);

    // Logo area
    QLabel* logoLabel = new QLabel("CortexEDR");
    QFont logoFont("Segoe UI", 36, QFont::Bold);
    logoLabel->setFont(logoFont);
    logoLabel->setStyleSheet("color: #00BCD4;");
    logoLabel->setAlignment(Qt::AlignCenter);

    QLabel* tagline = new QLabel("Endpoint Detection & Response");
    QFont tagFont("Segoe UI", 14);
    tagline->setFont(tagFont);
    tagline->setStyleSheet("color: #8B949E;");
    tagline->setAlignment(Qt::AlignCenter);

    layout->addWidget(logoLabel);
    layout->addWidget(tagline);
    layout->addSpacing(24);

    // Info card
    QFrame* infoCard = new QFrame();
    infoCard->setStyleSheet(
        "QFrame { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; }");

    QVBoxLayout* infoLayout = new QVBoxLayout(infoCard);
    infoLayout->setContentsMargins(32, 24, 32, 24);
    infoLayout->setSpacing(16);

    auto addInfoRow = [&](const QString& label, const QString& value) {
        QHBoxLayout* row = new QHBoxLayout();
        QLabel* labelWidget = new QLabel(label);
        QFont lFont("Segoe UI", 12);
        labelWidget->setFont(lFont);
        labelWidget->setStyleSheet("color: #8B949E;");
        labelWidget->setFixedWidth(180);

        QLabel* valueWidget = new QLabel(value);
        QFont vFont("Segoe UI", 12, QFont::DemiBold);
        valueWidget->setFont(vFont);
        valueWidget->setStyleSheet("color: #E6EDF3;");

        row->addWidget(labelWidget);
        row->addWidget(valueWidget, 1);
        infoLayout->addLayout(row);
    };

    addInfoRow("Version:", "1.0.0");
    addInfoRow("Engine:", "CortexEDR Detection Engine");
    addInfoRow("Architecture:", "x64 (Windows 10/11)");
    addInfoRow("Build:", "C++20 / Qt 6 / MSVC 2022");
    addInfoRow("License:", "Educational / Portfolio Project");

    // Separator
    QFrame* separator = new QFrame();
    separator->setFrameShape(QFrame::HLine);
    separator->setStyleSheet("background-color: #30363D; max-height: 1px;");
    infoLayout->addWidget(separator);

    addInfoRow("Process Monitor:", "ETW-based (Kernel Provider)");
    addInfoRow("File Monitor:", "ReadDirectoryChangesW");
    addInfoRow("Network Monitor:", "IP Helper API (TCP/UDP)");
    addInfoRow("Registry Monitor:", "RegNotifyChangeKeyValue");
    addInfoRow("Risk Engine:", "Weighted Scoring + Rules + Behavior");
    addInfoRow("Incident Manager:", "State Machine + JSON Persistence");

    layout->addWidget(infoCard);

    // Footer
    QLabel* footer = new QLabel(
        "Built with modern C++ practices: RAII, smart pointers, thread safety,\n"
        "event-driven architecture, and clean MVC separation.");
    footer->setProperty("class", "dimText");
    footer->setAlignment(Qt::AlignCenter);
    footer->setWordWrap(true);

    layout->addSpacing(16);
    layout->addWidget(footer);
    layout->addStretch();
}
