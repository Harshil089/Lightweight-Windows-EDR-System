#include "LogsPanel.hpp"
#include "EDRBridge.hpp"

LogsPanel::LogsPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
}

void LogsPanel::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(32, 28, 32, 28);
    layout->setSpacing(16);

    // Title
    QLabel* title = new QLabel("Event Logs");
    title->setProperty("class", "title");
    QFont titleFont("Segoe UI", 24, QFont::Bold);
    title->setFont(titleFont);

    QLabel* desc = new QLabel("View all system events, threats detected, and scan activity");
    desc->setProperty("class", "subtitle");
    desc->setWordWrap(true);

    layout->addWidget(title);
    layout->addWidget(desc);

    // Toolbar row
    QHBoxLayout* toolbar = new QHBoxLayout();
    toolbar->setSpacing(12);

    QLabel* filterLabel = new QLabel("Filter:");
    QFont filterFont("Segoe UI", 12);
    filterLabel->setFont(filterFont);

    filterCombo_ = new QComboBox();
    filterCombo_->addItems({"All", "Threats", "System Events", "Scan Logs"});
    filterCombo_->setMinimumWidth(180);

    countLabel_ = new QLabel("0 entries");
    countLabel_->setProperty("class", "dimText");

    refreshBtn_ = new QPushButton("Refresh");
    refreshBtn_->setCursor(Qt::PointingHandCursor);
    refreshBtn_->setMinimumHeight(36);

    clearBtn_ = new QPushButton("Clear Logs");
    clearBtn_->setProperty("class", "danger");
    clearBtn_->setCursor(Qt::PointingHandCursor);
    clearBtn_->setMinimumHeight(36);

    connect(filterCombo_, &QComboBox::currentTextChanged, this, &LogsPanel::onFilterChanged);
    connect(refreshBtn_, &QPushButton::clicked, this, &LogsPanel::refreshLogs);
    connect(clearBtn_, &QPushButton::clicked, this, [this]() {
        table_->setRowCount(0);
        countLabel_->setText("0 entries");
    });

    toolbar->addWidget(filterLabel);
    toolbar->addWidget(filterCombo_);
    toolbar->addStretch();
    toolbar->addWidget(countLabel_);
    toolbar->addWidget(refreshBtn_);
    toolbar->addWidget(clearBtn_);

    layout->addLayout(toolbar);

    // Log table
    table_ = new QTableWidget();
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"Timestamp", "Type", "Severity", "File Path", "Details"});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSortingEnabled(true);

    layout->addWidget(table_, 1);
}

void LogsPanel::refreshLogs()
{
    onFilterChanged(filterCombo_->currentText());
}

void LogsPanel::onFilterChanged(const QString& filter)
{
    auto entries = bridge_->getLogEntries(filter);

    table_->setSortingEnabled(false);
    table_->setRowCount(entries.size());

    for (int i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];

        auto* timestampItem = new QTableWidgetItem(
            entry.timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz"));
        table_->setItem(i, 0, timestampItem);

        auto* typeItem = new QTableWidgetItem(entry.eventType);
        if (entry.eventType == "Threat") {
            typeItem->setForeground(QColor("#F44336"));
        } else if (entry.eventType == "Scan") {
            typeItem->setForeground(QColor("#2196F3"));
        } else {
            typeItem->setForeground(QColor("#8B949E"));
        }
        table_->setItem(i, 1, typeItem);

        auto* sevItem = new QTableWidgetItem(entry.severity);
        if (entry.severity == "Critical") {
            sevItem->setForeground(QColor("#F44336"));
        } else if (entry.severity == "Warning") {
            sevItem->setForeground(QColor("#FF9800"));
        } else {
            sevItem->setForeground(QColor("#4CAF50"));
        }
        table_->setItem(i, 2, sevItem);

        table_->setItem(i, 3, new QTableWidgetItem(entry.filePath));
        table_->setItem(i, 4, new QTableWidgetItem(entry.details));
    }

    table_->setSortingEnabled(true);
    countLabel_->setText(QString("%1 entries").arg(entries.size()));
}
