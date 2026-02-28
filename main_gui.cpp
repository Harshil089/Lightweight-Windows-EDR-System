// CortexEDR GUI Entry Point
// This is the main entry point for the graphical user interface.
// The console-based EDR engine (main.cpp) runs independently.
// This GUI connects to the backend via the EDRBridge adapter.

#include "ui/EDRBridge.hpp"
#include "ui/MainWindow.hpp"
#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QIcon>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QStyleFactory>


int main(int argc, char *argv[]) {
  QApplication app(argc, argv);
  app.setApplicationName("CortexEDR");
  app.setApplicationVersion("1.0.0");
  app.setOrganizationName("CortexSecurity");

  // Use Fusion style as base for consistent cross-version look
  app.setStyle(QStyleFactory::create("Fusion"));

  // Set application-wide font
  QFont defaultFont("Segoe UI", 10);
  app.setFont(defaultFont);

  // Create a programmatic application icon (shield shape)
  QPixmap iconPixmap(256, 256);
  iconPixmap.fill(Qt::transparent);
  {
    QPainter p(&iconPixmap);
    p.setRenderHint(QPainter::Antialiasing);

    // Dark background circle
    p.setBrush(QColor("#0D1117"));
    p.setPen(QPen(QColor("#00BCD4"), 6));
    p.drawEllipse(8, 8, 240, 240);

    // Inner teal gradient shield
    QLinearGradient gradient(128, 40, 128, 220);
    gradient.setColorAt(0, QColor("#00BCD4"));
    gradient.setColorAt(1, QColor("#0097A7"));
    p.setBrush(gradient);
    p.setPen(Qt::NoPen);

    // Shield path
    QPainterPath shield;
    shield.moveTo(128, 40);
    shield.lineTo(200, 70);
    shield.lineTo(200, 140);
    shield.quadTo(200, 200, 128, 230);
    shield.quadTo(56, 200, 56, 140);
    shield.lineTo(56, 70);
    shield.closeSubpath();
    p.drawPath(shield);

    // Checkmark
    p.setPen(QPen(Qt::white, 10, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.drawLine(96, 140, 118, 168);
    p.drawLine(118, 168, 164, 108);
  }

  QIcon appIcon(iconPixmap);
  app.setWindowIcon(appIcon);

  // Create the backend bridge
  EDRBridge bridge;

  // Create and show main window
  MainWindow window(&bridge);
  window.setWindowIcon(appIcon);
  window.show();

  return app.exec();
}
