#include "ui/MainWindow.h"
#include <QtWidgets/QApplication>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    MainWindow w;
    w.resize(1100, 720);
    w.show();
    return app.exec();
}
