QT += core gui widgets

CONFIG += c++11 console

TARGET = Qtnpcap
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000

INCLUDEPATH += $$PWD/npcap-sdk-0.1/Include
LIBS += -L$$PWD/npcap-sdk-0.1/Lib/x64 -lwpcap -lpacket -lws2_32

INCLUDEPATH += $$PWD/pcapplusplus-17.11-windows-vs2015/header
LIBS += -L$$PWD/pcapplusplus-17.11-windows-vs2015/x64/Release -lCommon++ -lPacket++ -lPcap++

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    npcap.cpp \
    npcap_handler.cpp \
    npcap_process.cpp \
    npcap_run.cpp

HEADERS += \
        mainwindow.h \
    npcap.h

FORMS += \
        mainwindow.ui
