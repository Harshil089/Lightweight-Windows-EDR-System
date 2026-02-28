#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>

class EDRBridge;

class QuarantinePanel : public QWidget {
    Q_OBJECT

public:
    explicit QuarantinePanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void refreshTable();

private slots:
    void onRestoreClicked();
    void onDeleteClicked();

private:
    void setupUI();

    EDRBridge* bridge_;

    QLabel* titleLabel_;
    QLabel* countLabel_;
    QTableWidget* table_;
    QPushButton* restoreBtn_;
    QPushButton* deleteBtn_;
    QPushButton* refreshBtn_;
};
