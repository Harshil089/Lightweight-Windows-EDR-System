#include "QuarantinePanel.hpp"
#include "EDRBridge.hpp"

QuarantinePanel::QuarantinePanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
}

void QuarantinePanel::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(32, 28, 32, 28);
    layout->setSpacing(16);

    // Title row
    QHBoxLayout* titleRow = new QHBoxLayout();
    titleLabel_ = new QLabel("Quarantine");
    titleLabel_->setProperty("class", "title");
    QFont titleFont("Segoe UI", 24, QFont::Bold);
    titleLabel_->setFont(titleFont);

    countLabel_ = new QLabel("0 items");
    countLabel_->setProperty("class", "subtitle");
    countLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    titleRow->addWidget(titleLabel_);
    titleRow->addStretch();
    titleRow->addWidget(countLabel_);

    QLabel* desc = new QLabel("Manage quarantined threats. Restore or permanently delete detected files.");
    desc->setProperty("class", "subtitle");
    desc->setWordWrap(true);

    layout->addLayout(titleRow);
    layout->addWidget(desc);
    layout->addSpacing(8);

    // Table
    table_ = new QTableWidget();
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"File Name", "Original Path", "Threat Type", "Date", "Quarantine Path"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setColumnHidden(4, true); // Hide quarantine path column

    layout->addWidget(table_, 1);

    // Action buttons
    QHBoxLayout* btnLayout = new QHBoxLayout();
    btnLayout->setSpacing(12);

    QFont btnFont("Segoe UI", 12, QFont::DemiBold);

    restoreBtn_ = new QPushButton("  Restore Selected");
    restoreBtn_->setProperty("class", "success");
    restoreBtn_->setMinimumHeight(40);
    restoreBtn_->setCursor(Qt::PointingHandCursor);
    restoreBtn_->setFont(btnFont);
    restoreBtn_->setEnabled(false);

    deleteBtn_ = new QPushButton("  Delete Permanently");
    deleteBtn_->setProperty("class", "danger");
    deleteBtn_->setMinimumHeight(40);
    deleteBtn_->setCursor(Qt::PointingHandCursor);
    deleteBtn_->setFont(btnFont);
    deleteBtn_->setEnabled(false);

    refreshBtn_ = new QPushButton("  Refresh");
    refreshBtn_->setMinimumHeight(40);
    refreshBtn_->setCursor(Qt::PointingHandCursor);
    refreshBtn_->setFont(btnFont);

    connect(restoreBtn_, &QPushButton::clicked, this, &QuarantinePanel::onRestoreClicked);
    connect(deleteBtn_, &QPushButton::clicked, this, &QuarantinePanel::onDeleteClicked);
    connect(refreshBtn_, &QPushButton::clicked, this, &QuarantinePanel::refreshTable);

    // Enable buttons when row selected
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() {
        bool hasSelection = !table_->selectedItems().isEmpty();
        restoreBtn_->setEnabled(hasSelection);
        deleteBtn_->setEnabled(hasSelection);
    });

    btnLayout->addWidget(restoreBtn_);
    btnLayout->addWidget(deleteBtn_);
    btnLayout->addStretch();
    btnLayout->addWidget(refreshBtn_);

    layout->addLayout(btnLayout);
}

void QuarantinePanel::refreshTable()
{
    auto entries = bridge_->getQuarantineEntries();

    table_->setRowCount(entries.size());
    countLabel_->setText(QString("%1 items").arg(entries.size()));

    for (int i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        table_->setItem(i, 0, new QTableWidgetItem(entry.fileName));
        table_->setItem(i, 1, new QTableWidgetItem(entry.originalPath));
        table_->setItem(i, 2, new QTableWidgetItem(entry.threatType));
        table_->setItem(i, 3, new QTableWidgetItem(entry.dateQuarantined.toString("yyyy-MM-dd hh:mm")));
        table_->setItem(i, 4, new QTableWidgetItem(entry.quarantinePath));

        // Color the threat type
        if (table_->item(i, 2)) {
            table_->item(i, 2)->setForeground(QColor("#F44336"));
        }
    }
}

void QuarantinePanel::onRestoreClicked()
{
    int row = table_->currentRow();
    if (row < 0) return;

    QString fileName = table_->item(row, 0)->text();
    QString originalPath = table_->item(row, 1)->text();
    QString quarantinePath = table_->item(row, 4)->text();

    // Confirmation dialog
    QMessageBox::StandardButton reply = QMessageBox::question(
        this, "Restore File",
        QString("Are you sure you want to restore '%1' to its original location?\n\n"
                "Original path: %2\n\n"
                "Warning: This file was flagged as a potential threat.")
            .arg(fileName, originalPath),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (reply == QMessageBox::Yes) {
        bridge_->restoreFile(quarantinePath, originalPath);
        refreshTable();
    }
}

void QuarantinePanel::onDeleteClicked()
{
    int row = table_->currentRow();
    if (row < 0) return;

    QString fileName = table_->item(row, 0)->text();
    QString quarantinePath = table_->item(row, 4)->text();

    // Confirmation dialog - extra warning for permanent deletion
    QMessageBox::StandardButton reply = QMessageBox::warning(
        this, "Delete Permanently",
        QString("Are you sure you want to PERMANENTLY DELETE '%1'?\n\n"
                "This action cannot be undone. The file will be removed from disk entirely.")
            .arg(fileName),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (reply == QMessageBox::Yes) {
        // Second confirmation for safety
        QMessageBox::StandardButton confirm = QMessageBox::critical(
            this, "Confirm Permanent Deletion",
            QString("FINAL CONFIRMATION: Delete '%1' permanently?").arg(fileName),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No
        );

        if (confirm == QMessageBox::Yes) {
            bridge_->deleteFilePermanently(quarantinePath);
            refreshTable();
        }
    }
}
