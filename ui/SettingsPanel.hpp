#pragma once

#include <QCheckBox>
#include <QFileDialog>
#include <QFrame>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QSlider>
#include <QVBoxLayout>
#include <QWidget>


class EDRBridge;

class SettingsPanel : public QWidget {
  Q_OBJECT

public:
  explicit SettingsPanel(EDRBridge *bridge, QWidget *parent = nullptr);

private slots:
  void onSensitivityChanged(int value);
  void onAutoScanChanged(Qt::CheckState state);
  void onHeuristicChanged(Qt::CheckState state);
  void onAddExclusion();
  void onRemoveExclusion();
  void onUpdateDefinitions();

private:
  void setupUI();
  QFrame *createSection(const QString &title);

  EDRBridge *bridge_;

  QSlider *sensitivitySlider_;
  QLabel *sensitivityLabel_;
  QCheckBox *autoScanCheck_;
  QCheckBox *heuristicCheck_;
  QListWidget *exclusionList_;
  QPushButton *addExclusionBtn_;
  QPushButton *removeExclusionBtn_;
  QPushButton *updateDefsBtn_;
  QLabel *defsStatusLabel_;
};
