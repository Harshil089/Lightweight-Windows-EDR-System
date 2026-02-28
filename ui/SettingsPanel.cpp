#include "SettingsPanel.hpp"
#include "EDRBridge.hpp"

SettingsPanel::SettingsPanel(EDRBridge *bridge, QWidget *parent)
    : QWidget(parent), bridge_(bridge) {
  setupUI();
}

void SettingsPanel::setupUI() {
  QVBoxLayout *layout = new QVBoxLayout(this);
  layout->setContentsMargins(32, 28, 32, 28);
  layout->setSpacing(20);

  // Title
  QLabel *title = new QLabel("Settings");
  title->setProperty("class", "title");
  QFont titleFont("Segoe UI", 24, QFont::Bold);
  title->setFont(titleFont);

  QLabel *desc =
      new QLabel("Configure scan behavior, exclusions, and threat definitions");
  desc->setProperty("class", "subtitle");
  desc->setWordWrap(true);

  layout->addWidget(title);
  layout->addWidget(desc);
  layout->addSpacing(8);

  // Scroll area for settings content
  QWidget *scrollContent = new QWidget();
  QVBoxLayout *contentLayout = new QVBoxLayout(scrollContent);
  contentLayout->setContentsMargins(0, 0, 0, 0);
  contentLayout->setSpacing(16);

  // ─── Scan Sensitivity ─────────────────────
  QFrame *sensitivitySection = createSection("Scan Sensitivity");
  QVBoxLayout *sensLayout =
      qobject_cast<QVBoxLayout *>(sensitivitySection->layout());

  QHBoxLayout *sliderRow = new QHBoxLayout();
  QLabel *lowLabel = new QLabel("Low");
  lowLabel->setProperty("class", "dimText");
  QLabel *highLabel = new QLabel("High");
  highLabel->setProperty("class", "dimText");

  sensitivitySlider_ = new QSlider(Qt::Horizontal);
  sensitivitySlider_->setMinimum(0);
  sensitivitySlider_->setMaximum(100);
  sensitivitySlider_->setValue(bridge_->scanSensitivity());
  sensitivitySlider_->setMinimumHeight(24);

  sliderRow->addWidget(lowLabel);
  sliderRow->addWidget(sensitivitySlider_, 1);
  sliderRow->addWidget(highLabel);

  sensitivityLabel_ =
      new QLabel(QString("Current: %1%").arg(bridge_->scanSensitivity()));
  sensitivityLabel_->setStyleSheet(
      "color: #00BCD4; font-size: 13px; font-weight: bold;");

  QLabel *sensDesc = new QLabel("Higher sensitivity detects more threats but "
                                "may increase false positives");
  sensDesc->setProperty("class", "dimText");
  sensDesc->setWordWrap(true);

  connect(sensitivitySlider_, &QSlider::valueChanged, this,
          &SettingsPanel::onSensitivityChanged);

  sensLayout->addLayout(sliderRow);
  sensLayout->addWidget(sensitivityLabel_);
  sensLayout->addWidget(sensDesc);

  contentLayout->addWidget(sensitivitySection);

  // ─── Scan Options ─────────────────────────
  QFrame *optionsSection = createSection("Scan Options");
  QVBoxLayout *optLayout =
      qobject_cast<QVBoxLayout *>(optionsSection->layout());

  autoScanCheck_ = new QCheckBox("Auto-scan on system startup");
  autoScanCheck_->setChecked(bridge_->autoScanOnStartup());
  autoScanCheck_->setMinimumHeight(32);

  heuristicCheck_ =
      new QCheckBox("Enable heuristic scanning (behavioral analysis)");
  heuristicCheck_->setChecked(bridge_->heuristicScanEnabled());
  heuristicCheck_->setMinimumHeight(32);

  connect(autoScanCheck_, &QCheckBox::checkStateChanged, this,
          &SettingsPanel::onAutoScanChanged);
  connect(heuristicCheck_, &QCheckBox::checkStateChanged, this,
          &SettingsPanel::onHeuristicChanged);

  optLayout->addWidget(autoScanCheck_);
  optLayout->addWidget(heuristicCheck_);

  contentLayout->addWidget(optionsSection);

  // ─── Exclusion Folders ────────────────────
  QFrame *exclusionSection = createSection("Exclusion Folders");
  QVBoxLayout *exclLayout =
      qobject_cast<QVBoxLayout *>(exclusionSection->layout());

  QLabel *exclDesc =
      new QLabel("Files in these folders will be skipped during scans");
  exclDesc->setProperty("class", "dimText");
  exclDesc->setWordWrap(true);
  exclLayout->addWidget(exclDesc);

  exclusionList_ = new QListWidget();
  exclusionList_->setMinimumHeight(120);
  exclusionList_->setMaximumHeight(180);

  // Populate from bridge
  for (const auto &folder : bridge_->exclusionFolders()) {
    exclusionList_->addItem(folder);
  }

  QHBoxLayout *exclBtnRow = new QHBoxLayout();

  QFont btnFont("Segoe UI", 11, QFont::DemiBold);

  addExclusionBtn_ = new QPushButton("  Add Folder");
  addExclusionBtn_->setMinimumHeight(36);
  addExclusionBtn_->setCursor(Qt::PointingHandCursor);
  addExclusionBtn_->setFont(btnFont);

  removeExclusionBtn_ = new QPushButton("  Remove Selected");
  removeExclusionBtn_->setProperty("class", "danger");
  removeExclusionBtn_->setMinimumHeight(36);
  removeExclusionBtn_->setCursor(Qt::PointingHandCursor);
  removeExclusionBtn_->setFont(btnFont);
  removeExclusionBtn_->setEnabled(false);

  connect(addExclusionBtn_, &QPushButton::clicked, this,
          &SettingsPanel::onAddExclusion);
  connect(removeExclusionBtn_, &QPushButton::clicked, this,
          &SettingsPanel::onRemoveExclusion);
  connect(exclusionList_, &QListWidget::itemSelectionChanged, this, [this]() {
    removeExclusionBtn_->setEnabled(!exclusionList_->selectedItems().isEmpty());
  });

  exclBtnRow->addWidget(addExclusionBtn_);
  exclBtnRow->addWidget(removeExclusionBtn_);
  exclBtnRow->addStretch();

  exclLayout->addWidget(exclusionList_);
  exclLayout->addLayout(exclBtnRow);

  contentLayout->addWidget(exclusionSection);

  // ─── Threat Definitions ───────────────────
  QFrame *defsSection = createSection("Threat Definitions");
  QVBoxLayout *defsLayout = qobject_cast<QVBoxLayout *>(defsSection->layout());

  QHBoxLayout *defsRow = new QHBoxLayout();

  updateDefsBtn_ = new QPushButton("  Update Definitions");
  updateDefsBtn_->setProperty("class", "primary");
  updateDefsBtn_->setMinimumHeight(40);
  updateDefsBtn_->setCursor(Qt::PointingHandCursor);
  QFont defsBtnFont("Segoe UI", 12, QFont::DemiBold);
  updateDefsBtn_->setFont(defsBtnFont);

  defsStatusLabel_ = new QLabel("Definitions are up to date");
  defsStatusLabel_->setStyleSheet("color: #4CAF50; font-size: 12px;");

  connect(updateDefsBtn_, &QPushButton::clicked, this,
          &SettingsPanel::onUpdateDefinitions);
  connect(bridge_, &EDRBridge::definitionsUpdated, this, [this](bool success) {
    if (success) {
      defsStatusLabel_->setText("Definitions updated successfully");
      defsStatusLabel_->setStyleSheet("color: #4CAF50; font-size: 12px;");
    } else {
      defsStatusLabel_->setText("Update failed. Please try again.");
      defsStatusLabel_->setStyleSheet("color: #F44336; font-size: 12px;");
    }
    updateDefsBtn_->setEnabled(true);
    updateDefsBtn_->setText("  Update Definitions");
  });

  defsRow->addWidget(updateDefsBtn_);
  defsRow->addWidget(defsStatusLabel_);
  defsRow->addStretch();

  defsLayout->addLayout(defsRow);

  contentLayout->addWidget(defsSection);
  contentLayout->addStretch();

  layout->addWidget(scrollContent, 1);
}

QFrame *SettingsPanel::createSection(const QString &title) {
  QFrame *section = new QFrame();
  section->setStyleSheet("QFrame { background-color: #161B22; border: 1px "
                         "solid #30363D; border-radius: 12px; }");

  QVBoxLayout *sectionLayout = new QVBoxLayout(section);
  sectionLayout->setContentsMargins(24, 20, 24, 20);
  sectionLayout->setSpacing(12);

  QLabel *titleLabel = new QLabel(title);
  titleLabel->setProperty("class", "sectionTitle");
  QFont secFont("Segoe UI", 15, QFont::DemiBold);
  titleLabel->setFont(secFont);

  sectionLayout->addWidget(titleLabel);

  return section;
}

void SettingsPanel::onSensitivityChanged(int value) {
  sensitivityLabel_->setText(QString("Current: %1%").arg(value));
  bridge_->setScanSensitivity(value);
}

void SettingsPanel::onAutoScanChanged(Qt::CheckState state) {
  bridge_->setAutoScanOnStartup(state == Qt::Checked);
}

void SettingsPanel::onHeuristicChanged(Qt::CheckState state) {
  bridge_->setHeuristicScanEnabled(state == Qt::Checked);
}

void SettingsPanel::onAddExclusion() {
  QString dir =
      QFileDialog::getExistingDirectory(this, "Select Exclusion Folder");
  if (!dir.isEmpty()) {
    // Check if already in list
    for (int i = 0; i < exclusionList_->count(); ++i) {
      if (exclusionList_->item(i)->text() == dir) {
        return; // Already exists
      }
    }
    exclusionList_->addItem(dir);
    bridge_->addExclusionFolder(dir);
  }
}

void SettingsPanel::onRemoveExclusion() {
  auto selected = exclusionList_->selectedItems();
  if (selected.isEmpty())
    return;

  QString path = selected.first()->text();
  delete exclusionList_->takeItem(exclusionList_->row(selected.first()));
  bridge_->removeExclusionFolder(path);
}

void SettingsPanel::onUpdateDefinitions() {
  updateDefsBtn_->setEnabled(false);
  updateDefsBtn_->setText("  Updating...");
  defsStatusLabel_->setText("Downloading latest definitions...");
  defsStatusLabel_->setStyleSheet("color: #FF9800; font-size: 12px;");
  bridge_->updateDefinitions();
}
