#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QComboBox>
#include <QHeaderView>

class EDRBridge;

class LogsPanel : public QWidget {
    Q_OBJECT

public:
    explicit LogsPanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void refreshLogs();

private slots:
    void onFilterChanged(const QString& filter);

private:
    void setupUI();

    EDRBridge* bridge_;

    QLabel* titleLabel_;
    QComboBox* filterCombo_;
    QTableWidget* table_;
    QPushButton* refreshBtn_;
    QPushButton* clearBtn_;
    QLabel* countLabel_;
};
