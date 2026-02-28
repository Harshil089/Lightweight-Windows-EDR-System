#include "FullScanPanel.hpp"
#include "EDRBridge.hpp"

FullScanPanel::FullScanPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
    setIdleState();
}

void FullScanPanel::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(32, 28, 32, 28);
    layout->setSpacing(16);

    // Title
    titleLabel_ = new QLabel("Full System Scan");
    titleLabel_->setProperty("class", "title");
    QFont titleFont("Segoe UI", 24, QFont::Bold);
    titleLabel_->setFont(titleFont);

    QLabel* desc = new QLabel("Deep scan of all files on all drives. This may take a while.");
    desc->setProperty("class", "subtitle");
    desc->setWordWrap(true);

    layout->addWidget(titleLabel_);
    layout->addWidget(desc);
    layout->addSpacing(16);

    // Status card
    QFrame* statusFrame = new QFrame();
    statusFrame->setObjectName("fullScanStatusFrame");
    statusFrame->setStyleSheet(
        "QFrame#fullScanStatusFrame { background-color: #161B22; border: 1px solid #30363D; border-radius: 12px; }");

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

    QHBoxLayout* infoRow = new QHBoxLayout();
    currentFileLabel_ = new QLabel("");
    currentFileLabel_->setProperty("class", "dimText");
    currentFileLabel_->setWordWrap(true);
    QFont monoFont("Cascadia Code", 10);
    currentFileLabel_->setFont(monoFont);

    estimatedTimeLabel_ = new QLabel("");
    estimatedTimeLabel_->setStyleSheet("color: #00BCD4; font-size: 13px; font-weight: bold;");
    estimatedTimeLabel_->setAlignment(Qt::AlignRight);

    infoRow->addWidget(currentFileLabel_, 1);
    infoRow->addWidget(estimatedTimeLabel_);

    threatsCountLabel_ = new QLabel("Threats found: 0");
    QFont threatFont("Segoe UI", 13, QFont::DemiBold);
    threatsCountLabel_->setFont(threatFont);
    threatsCountLabel_->setStyleSheet("color: #4CAF50;");

    statusLayout->addWidget(statusLabel_);
    statusLayout->addWidget(progressBar_);
    statusLayout->addLayout(infoRow);
    statusLayout->addWidget(threatsCountLabel_);

    layout->addWidget(statusFrame);

    // Buttons
    QHBoxLayout* btnLayout = new QHBoxLayout();
    btnLayout->setSpacing(12);

    QFont btnFont("Segoe UI", 13, QFont::DemiBold);

    startBtn_ = new QPushButton("  Start Full Scan");
    startBtn_->setProperty("class", "primary");
    startBtn_->setMinimumHeight(44);
    startBtn_->setCursor(Qt::PointingHandCursor);
    startBtn_->setFont(btnFont);

    pauseBtn_ = new QPushButton("  Pause");
    pauseBtn_->setProperty("class", "warning");
    pauseBtn_->setMinimumHeight(44);
    pauseBtn_->setCursor(Qt::PointingHandCursor);
    pauseBtn_->setFont(btnFont);
    pauseBtn_->setVisible(false);

    resumeBtn_ = new QPushButton("  Resume");
    resumeBtn_->setProperty("class", "success");
    resumeBtn_->setMinimumHeight(44);
    resumeBtn_->setCursor(Qt::PointingHandCursor);
    resumeBtn_->setFont(btnFont);
    resumeBtn_->setVisible(false);

    cancelBtn_ = new QPushButton("  Cancel");
    cancelBtn_->setProperty("class", "danger");
    cancelBtn_->setMinimumHeight(44);
    cancelBtn_->setCursor(Qt::PointingHandCursor);
    cancelBtn_->setFont(btnFont);
    cancelBtn_->setVisible(false);

    connect(startBtn_, &QPushButton::clicked, this, &FullScanPanel::startScan);
    connect(pauseBtn_, &QPushButton::clicked, this, [this]() {
        bridge_->pauseScan();
        isPaused_ = true;
        pauseBtn_->setVisible(false);
        resumeBtn_->setVisible(true);
        statusLabel_->setText("Paused");
        statusLabel_->setStyleSheet("color: #FF9800;");
    });
    connect(resumeBtn_, &QPushButton::clicked, this, [this]() {
        bridge_->resumeScan();
        isPaused_ = false;
        resumeBtn_->setVisible(false);
        pauseBtn_->setVisible(true);
        statusLabel_->setText("Scanning...");
        statusLabel_->setStyleSheet("color: #00BCD4;");
    });
    connect(cancelBtn_, &QPushButton::clicked, bridge_, &EDRBridge::cancelScan);

    btnLayout->addWidget(startBtn_);
    btnLayout->addWidget(pauseBtn_);
    btnLayout->addWidget(resumeBtn_);
    btnLayout->addWidget(cancelBtn_);
    btnLayout->addStretch();

    layout->addLayout(btnLayout);

    // Directory traversal log
    QLabel* logTitle = new QLabel("Directory Traversal Log");
    logTitle->setProperty("class", "sectionTitle");
    QFont secFont("Segoe UI", 14, QFont::DemiBold);
    logTitle->setFont(secFont);

    directoryLog_ = new QTextEdit();
    directoryLog_->setReadOnly(true);
    directoryLog_->setMinimumHeight(200);
    directoryLog_->setPlaceholderText("Real-time scan log will appear here...");

    layout->addSpacing(8);
    layout->addWidget(logTitle);
    layout->addWidget(directoryLog_, 1);
}

void FullScanPanel::startScan()
{
    setScanningState();
    threatsFound_ = 0;
    directoryLog_->clear();
    bridge_->startFullScan();
}

void FullScanPanel::setIdleState()
{
    statusLabel_->setText("Ready to scan");
    statusLabel_->setStyleSheet("color: #8B949E;");
    progressBar_->setValue(0);
    currentFileLabel_->setText("");
    estimatedTimeLabel_->setText("");
    threatsCountLabel_->setText("Threats found: 0");
    threatsCountLabel_->setStyleSheet("color: #4CAF50;");
    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    pauseBtn_->setVisible(false);
    resumeBtn_->setVisible(false);
    cancelBtn_->setVisible(false);
    isPaused_ = false;
}

void FullScanPanel::setScanningState()
{
    statusLabel_->setText("Scanning...");
    statusLabel_->setStyleSheet("color: #00BCD4;");
    startBtn_->setVisible(false);
    pauseBtn_->setVisible(true);
    cancelBtn_->setVisible(true);
}

void FullScanPanel::onProgressChanged(int percent)
{
    progressBar_->setValue(percent);
}

void FullScanPanel::onCurrentFileChanged(const QString& filePath)
{
    QString display = filePath;
    if (display.length() > 80) {
        display = "..." + display.right(77);
    }
    currentFileLabel_->setText(display);

    // Add to directory log (limit entries)
    static int logCount = 0;
    logCount++;
    if (logCount % 5 == 0) {  // Log every 5th file to avoid flooding
        directoryLog_->append(
            QString("<span style='color:#8B949E;'>[%1]</span> <span style='color:#E6EDF3;'>%2</span>")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"), filePath));

        // Auto-scroll to bottom
        QTextCursor cursor = directoryLog_->textCursor();
        cursor.movePosition(QTextCursor::End);
        directoryLog_->setTextCursor(cursor);
    }
}

void FullScanPanel::onThreatDetected(const QString& filePath, const QString& threatName)
{
    threatsFound_++;
    threatsCountLabel_->setText(QString("Threats found: %1").arg(threatsFound_));
    threatsCountLabel_->setStyleSheet("color: #F44336;");

    directoryLog_->append(
        QString("<span style='color:#F44336;'>THREAT DETECTED</span> "
                "<span style='color:#FF9800;'>%1</span> "
                "<span style='color:#8B949E;'>in %2</span>")
            .arg(threatName, filePath));
}

void FullScanPanel::onScanFinished(int totalFiles, int threatsFound)
{
    progressBar_->setValue(100);
    estimatedTimeLabel_->setText("Complete");
    currentFileLabel_->setText("Scan complete");

    if (threatsFound > 0) {
        statusLabel_->setText(QString("Scan complete - %1 threats found").arg(threatsFound));
        statusLabel_->setStyleSheet("color: #F44336;");
    } else {
        statusLabel_->setText("Scan complete - No threats found");
        statusLabel_->setStyleSheet("color: #4CAF50;");
    }

    directoryLog_->append(
        QString("\n<span style='color:#00BCD4;'>===== SCAN COMPLETE =====</span>\n"
                "<span style='color:#E6EDF3;'>Files scanned: %1</span>\n"
                "<span style='color:%2;'>Threats found: %3</span>")
            .arg(totalFiles)
            .arg(threatsFound > 0 ? "#F44336" : "#4CAF50")
            .arg(threatsFound));

    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    pauseBtn_->setVisible(false);
    resumeBtn_->setVisible(false);
    cancelBtn_->setVisible(false);
}

void FullScanPanel::onEstimatedTimeChanged(const QString& timeRemaining)
{
    estimatedTimeLabel_->setText("ETA: " + timeRemaining);
}
