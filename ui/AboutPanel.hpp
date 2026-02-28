#pragma once

#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>

class AboutPanel : public QWidget {
    Q_OBJECT

public:
    explicit AboutPanel(QWidget* parent = nullptr);

private:
    void setupUI();
};
