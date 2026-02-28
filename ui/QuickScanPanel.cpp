#include "QuickScanPanel.hpp"
#include "EDRBridge.hpp"

QuickScanPanel::QuickScanPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
    setIdleState();
}

void QuickScanPanel::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(32, 28, 32, 28);
    layout->setSpacing(16);

    // Title
    titleLabel_ = new QLabel("Quick Scan");
    titleLabel_->setProperty("class", "title");
    QFont titleFont("Segoe UI", 24, QFont::Bold);
    titleLabel_->setFont(titleFont);

    QLabel* desc = new QLabel("Scan common threat locations: user profile, downloads, and temp folders");
    desc->setProperty("class", "subtitle");
    desc->setWordWrap(true);

    layout->addWidget(titleLabel_);
    layout->addWidget(desc);
    layout->addSpacing(16);

    // Status section
    QFrame* statusFrame = new QFrame();
    statusFrame->setObjectName("scanStatusFrame");
    statusFrame->setStyleSheet(
        "QFrame#scanStatusFrame { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; padding: 20px; }");

    QVBoxLayout* statusLayout = new QVBoxLayout(statusFrame);
    statusLayout->setContentsMargins(24, 20, 24, 20);
    statusLayout->setSpacing(12);

    statusLabel_ = new QLabel("Ready to scan");
    QFont statusFont("Segoe UI", 16, QFont::DemiBold);
    statusLabel_->setFont(statusFont);
    statusLabel_->setStyleSheet("color: #8B949E;");

    progressBar_ = new QProgressBar();
    progressBar_->setMinimum(0);
    progressBar_->setMaximum(100);
    progressBar_->setValue(0);
    progressBar_->setMinimumHeight(28);
    progressBar_->setTextVisible(true);

    currentFileLabel_ = new QLabel("");
    currentFileLabel_->setProperty("class", "dimText");
    currentFileLabel_->setWordWrap(true);
    QFont fileFont("Cascadia Code", 10);
    currentFileLabel_->setFont(fileFont);

    threatsCountLabel_ = new QLabel("Threats found: 0");
    QFont threatFont("Segoe UI", 13, QFont::DemiBold);
    threatsCountLabel_->setFont(threatFont);
    threatsCountLabel_->setStyleSheet("color: #4CAF50;");

    statusLayout->addWidget(statusLabel_);
    statusLayout->addWidget(progressBar_);
    statusLayout->addWidget(currentFileLabel_);
    statusLayout->addWidget(threatsCountLabel_);

    layout->addWidget(statusFrame);

    // Buttons
    QHBoxLayout* btnLayout = new QHBoxLayout();
    btnLayout->setSpacing(12);

    startBtn_ = new QPushButton("  Start Quick Scan");
    startBtn_->setProperty("class", "primary");
    startBtn_->setMinimumHeight(44);
    startBtn_->setCursor(Qt::PointingHandCursor);
    QFont btnFont("Segoe UI", 13, QFont::DemiBold);
    startBtn_->setFont(btnFont);

    cancelBtn_ = new QPushButton("  Cancel");
    cancelBtn_->setProperty("class", "danger");
    cancelBtn_->setMinimumHeight(44);
    cancelBtn_->setCursor(Qt::PointingHandCursor);
    cancelBtn_->setFont(btnFont);
    cancelBtn_->setVisible(false);

    connect(startBtn_, &QPushButton::clicked, this, &QuickScanPanel::startScan);
    connect(cancelBtn_, &QPushButton::clicked, bridge_, &EDRBridge::cancelScan);

    btnLayout->addWidget(startBtn_);
    btnLayout->addWidget(cancelBtn_);
    btnLayout->addStretch();

    layout->addLayout(btnLayout);

    // Results log
    QLabel* resultsTitle = new QLabel("Scan Results");
    resultsTitle->setProperty("class", "sectionTitle");
    QFont secFont("Segoe UI", 14, QFont::DemiBold);
    resultsTitle->setFont(secFont);

    resultsLog_ = new QTextEdit();
    resultsLog_->setReadOnly(true);
    resultsLog_->setMinimumHeight(150);
    resultsLog_->setPlaceholderText("Scan results will appear here...");

    layout->addSpacing(8);
    layout->addWidget(resultsTitle);
    layout->addWidget(resultsLog_, 1);

    // Summary frame (hidden until scan completes)
    summaryFrame_ = new QFrame();
    summaryFrame_->setObjectName("summaryFrame");
    summaryFrame_->setStyleSheet(
        "QFrame#summaryFrame { background-color: #161B22; border: 1px solid #4CAF50; border-radius: 12px; padding: 16px; }");
    summaryFrame_->setVisible(false);

    QHBoxLayout* sumLayout = new QHBoxLayout(summaryFrame_);
    sumLayout->setContentsMargins(20, 16, 20, 16);
    summaryLabel_ = new QLabel("");
    QFont sumFont("Segoe UI", 14, QFont::DemiBold);
    summaryLabel_->setFont(sumFont);
    sumLayout->addWidget(summaryLabel_);

    layout->addWidget(summaryFrame_);
}

void QuickScanPanel::startScan()
{
    setScanningState();
    threatsFound_ = 0;
    resultsLog_->clear();
    summaryFrame_->setVisible(false);
    bridge_->startQuickScan();
}

void QuickScanPanel::setIdleState()
{
    statusLabel_->setText("Ready to scan");
    statusLabel_->setStyleSheet("color: #8B949E;");
    progressBar_->setValue(0);
    currentFileLabel_->setText("");
    threatsCountLabel_->setText("Threats found: 0");
    threatsCountLabel_->setStyleSheet("color: #4CAF50;");
    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    cancelBtn_->setVisible(false);
}

void QuickScanPanel::setScanningState()
{
    statusLabel_->setText("Scanning...");
    statusLabel_->setStyleSheet("color: #00BCD4;");
    startBtn_->setVisible(false);
    cancelBtn_->setVisible(true);
}

void QuickScanPanel::onProgressChanged(int percent)
{
    progressBar_->setValue(percent);
}

void QuickScanPanel::onCurrentFileChanged(const QString& filePath)
{
    // Show only the last ~80 chars of the path
    QString display = filePath;
    if (display.length() > 80) {
        display = "..." + display.right(77);
    }
    currentFileLabel_->setText(display);
}

void QuickScanPanel::onThreatDetected(const QString& filePath, const QString& threatName)
{
    threatsFound_++;
    threatsCountLabel_->setText(QString("Threats found: %1").arg(threatsFound_));
    threatsCountLabel_->setStyleSheet("color: #F44336;");

    QString entry = QString("<span style='color:#F44336;'>THREAT</span> "
                            "<span style='color:#E6EDF3;'>%1</span> "
                            "<span style='color:#8B949E;'>in %2</span>")
                        .arg(threatName, filePath);
    resultsLog_->append(entry);
}

void QuickScanPanel::onScanFinished(int totalFiles, int threatsFound)
{
    progressBar_->setValue(100);
    currentFileLabel_->setText("Scan complete");

    if (threatsFound > 0) {
        statusLabel_->setText("Threats detected!");
        statusLabel_->setStyleSheet("color: #F44336;");
        summaryFrame_->setStyleSheet(
            "QFrame#summaryFrame { background-color: #161B22; border: 1px solid #F44336; border-radius: 12px; }");
        summaryLabel_->setText(
            QString("Scan complete: %1 files scanned, %2 threats detected")
                .arg(totalFiles).arg(threatsFound));
        summaryLabel_->setStyleSheet("color: #F44336;");
    } else {
        statusLabel_->setText("No threats found");
        statusLabel_->setStyleSheet("color: #4CAF50;");
        summaryFrame_->setStyleSheet(
            "QFrame#summaryFrame { background-color: #161B22; border: 1px solid #4CAF50; border-radius: 12px; }");
        summaryLabel_->setText(
            QString("Scan complete: %1 files scanned, no threats detected")
                .arg(totalFiles));
        summaryLabel_->setStyleSheet("color: #4CAF50;");
    }

    summaryFrame_->setVisible(true);
    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    cancelBtn_->setVisible(false);
}
