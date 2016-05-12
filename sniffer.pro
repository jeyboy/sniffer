#-------------------------------------------------
#
# Project created by QtCreator 2016-05-08T00:31:59
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

#CONFIG += g99
#QMAKE_CFLAGS += -D_GNU_SOURCE
#DEFINES *= TINS_STATIC

TARGET = sniffer
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    modules/accordion.cpp

HEADERS  += mainwindow.h \
    modules/sniffer.h \
    modules/raw_socket.h \
    modules/proto_headers.h \
    modules/proto_defines.h \
    modules/sniffer_wrapper.h \
    modules/accordion.h

FORMS    += mainwindow.ui

win32:LIBS += -lIphlpapi -lWs2_32 -lpsapi

#LIBS += -L$$PWD/libs/libtins/ -ltins -lwpcap
#INCLUDEPATH += $$PWD/libs/libtins/include
#DEPENDPATH += $$PWD/libs/libtins
